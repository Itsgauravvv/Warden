/**
 * Toll: Token-Bucket Rate Limiter + Token/Cost Budget Enforcer.
 * Runs inside a Cloudflare Durable Object (RateLimiterDO) for strict global consistency,
 * and can also be instantiated directly in Node/Docker or Vitest tests.
 */

export interface BudgetLimits {
  rpmLimit: number;            // Requests per minute (Token Bucket capacity & refill rate)
  dailyTokenLimit: number;     // Max tokens per 24h window
  monthlyCostLimitUsd: number; // Max USD spend per 30d window
}

export const DEFAULT_BUDGET_LIMITS: BudgetLimits = {
  rpmLimit: 60,
  dailyTokenLimit: 500_000,
  monthlyCostLimitUsd: 10.0,
};

interface ScopeState {
  tokens: number;
  lastRefillMs: number;
  dailyTokensUsed: number;
  dayWindowStartMs: number;
  monthlyCostUsdUsed: number;
  monthWindowStartMs: number;
}

export interface RateLimitCheckResult {
  allowed: boolean;
  reason?: "rpm_exceeded" | "daily_token_budget_exceeded" | "monthly_cost_budget_exceeded";
  retryAfterSeconds: number;
  remainingRpm: number;
  remainingDailyTokens: number;
  remainingMonthlyCostUsd: number;
}

export class RateLimitEngine {
  private readonly states = new Map<string, ScopeState>();
  private readonly customLimits = new Map<string, BudgetLimits>();

  private scopeKey(tenantId: string, scope: "tenant" | "project" | "key", scopeId: string): string {
    return `${tenantId}:${scope}:${scopeId}`;
  }

  public setLimits(
    tenantId: string,
    scope: "tenant" | "project" | "key",
    scopeId: string,
    limits: Partial<BudgetLimits>
  ): void {
    const key = this.scopeKey(tenantId, scope, scopeId);
    const current = this.customLimits.get(key) ?? DEFAULT_BUDGET_LIMITS;
    this.customLimits.set(key, { ...current, ...limits });
  }

  public checkAndConsumeRequest(options: {
    tenantId: string;
    scope?: "tenant" | "project" | "key";
    scopeId?: string;
    estimatedTokens?: number;
    nowMs?: number;
  }): RateLimitCheckResult {
    const scope = options.scope ?? "tenant";
    const scopeId = options.scopeId ?? options.tenantId;
    const now = options.nowMs ?? Date.now();
    const key = this.scopeKey(options.tenantId, scope, scopeId);
    const limits = this.customLimits.get(key) ?? DEFAULT_BUDGET_LIMITS;

    let state = this.states.get(key);
    if (!state) {
      state = {
        tokens: limits.rpmLimit,
        lastRefillMs: now,
        dailyTokensUsed: 0,
        dayWindowStartMs: now,
        monthlyCostUsdUsed: 0,
        monthWindowStartMs: now,
      };
      this.states.set(key, state);
    }

    // 1. Refill token bucket based on elapsed time (limits.rpmLimit tokens per 60,000 ms)
    const elapsedMs = Math.max(0, now - state.lastRefillMs);
    const refillRatePerMs = limits.rpmLimit / 60_000;
    state.tokens = Math.min(limits.rpmLimit, state.tokens + elapsedMs * refillRatePerMs);
    state.lastRefillMs = now;

    // 2. Roll daily and monthly budget windows if expired
    if (now - state.dayWindowStartMs >= 86_400_000) {
      state.dailyTokensUsed = 0;
      state.dayWindowStartMs = now;
    }
    if (now - state.monthWindowStartMs >= 30 * 86_400_000) {
      state.monthlyCostUsdUsed = 0;
      state.monthWindowStartMs = now;
    }

    // 3. Check monthly cost budget
    if (state.monthlyCostUsdUsed >= limits.monthlyCostLimitUsd) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((state.monthWindowStartMs + 30 * 86_400_000 - now) / 1000)
      );
      return {
        allowed: false,
        reason: "monthly_cost_budget_exceeded",
        retryAfterSeconds,
        remainingRpm: Math.floor(state.tokens),
        remainingDailyTokens: Math.max(0, limits.dailyTokenLimit - state.dailyTokensUsed),
        remainingMonthlyCostUsd: 0,
      };
    }

    // 4. Check daily token budget
    const estTokens = options.estimatedTokens ?? 0;
    if (state.dailyTokensUsed + estTokens > limits.dailyTokenLimit) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((state.dayWindowStartMs + 86_400_000 - now) / 1000)
      );
      return {
        allowed: false,
        reason: "daily_token_budget_exceeded",
        retryAfterSeconds,
        remainingRpm: Math.floor(state.tokens),
        remainingDailyTokens: Math.max(0, limits.dailyTokenLimit - state.dailyTokensUsed),
        remainingMonthlyCostUsd: Math.max(0, limits.monthlyCostLimitUsd - state.monthlyCostUsdUsed),
      };
    }

    // 5. Check RPM token bucket (requires at least 1 token)
    if (state.tokens < 1) {
      const neededTokens = 1 - state.tokens;
      const msUntilNextToken = neededTokens / refillRatePerMs;
      return {
        allowed: false,
        reason: "rpm_exceeded",
        retryAfterSeconds: Math.max(1, Math.ceil(msUntilNextToken / 1000)),
        remainingRpm: 0,
        remainingDailyTokens: Math.max(0, limits.dailyTokenLimit - state.dailyTokensUsed),
        remainingMonthlyCostUsd: Math.max(0, limits.monthlyCostLimitUsd - state.monthlyCostUsdUsed),
      };
    }

    // Consume 1 request token
    state.tokens -= 1;

    return {
      allowed: true,
      retryAfterSeconds: 0,
      remainingRpm: Math.floor(state.tokens),
      remainingDailyTokens: Math.max(0, limits.dailyTokenLimit - state.dailyTokensUsed),
      remainingMonthlyCostUsd: Number(
        Math.max(0, limits.monthlyCostLimitUsd - state.monthlyCostUsdUsed).toFixed(6)
      ),
    };
  }

  /**
   * Records actual token usage and USD cost after the LLM responds (or from cache savings).
   */
  public recordUsage(options: {
    tenantId: string;
    scope?: "tenant" | "project" | "key";
    scopeId?: string;
    totalTokens: number;
    costUsd: number;
  }): void {
    const scope = options.scope ?? "tenant";
    const scopeId = options.scopeId ?? options.tenantId;
    const key = this.scopeKey(options.tenantId, scope, scopeId);
    const state = this.states.get(key);
    if (!state) return;

    state.dailyTokensUsed += options.totalTokens;
    state.monthlyCostUsdUsed += options.costUsd;
  }
}

/**
 * Cloudflare Durable Object wrapper around RateLimitEngine for edge deployment.
 */
export class RateLimiterDO {
  private readonly engine = new RateLimitEngine();

  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/check") {
      const body = (await request.json()) as Parameters<RateLimitEngine["checkAndConsumeRequest"]>[0];
      const result = this.engine.checkAndConsumeRequest(body);
      return new Response(JSON.stringify(result), {
        status: result.allowed ? 200 : 429,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/usage") {
      const body = (await request.json()) as Parameters<RateLimitEngine["recordUsage"]>[0];
      this.engine.recordUsage(body);
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("Not Found", { status: 404 });
  }
}