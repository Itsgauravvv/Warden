import { Hono } from "hono";
import { BRAND } from "@warden/brand";
import {
  checkCanaryLeak,
  evaluateInputPipeline,
  generateCanaryToken,
  injectCanaryIntoSystemPrompt,
  restoreRedactedValues,
} from "@warden/detectors";
import type { AppVariables } from "../index.js";
import type { TenantRepository } from "../db/repository.js";
import type { RateLimitEngine } from "../durable-objects/rate-limiter.js";
import type { SemanticCache } from "../cache/semantic-cache.js";
import { sha256Hex } from "../auth/api-key.js";
import { createScannedSseStream } from "../streaming/sse-scanner.js";
import {
  analyzeUntrustedToolResults,
  evaluateToolCallsFirewall,
  type IncomingToolCall,
} from "../firewall/tool-firewall.js";
import {
  callUpstreamProvider,
  ChatCompletionRequestSchema,
  DEFAULT_MODELS,
  ProviderNameSchema,
  type ProviderName,
} from "../adapters/provider.js";

export interface V1RouteDependencies {
  repo?: TenantRepository;
  customFetch?: typeof fetch;
  rateLimiter: RateLimitEngine;
  semanticCache: SemanticCache;
}

function estimateCostUsd(promptTokens: number, completionTokens: number): number {
  return Number(((promptTokens * 0.00015 + completionTokens * 0.0006) / 1000).toFixed(6));
}

export function createV1Routes(deps: V1RouteDependencies) {
  const v1 = new Hono<{ Variables: AppVariables }>();

  v1.use("*", async (c, next) => {
    if (deps.repo && !c.get("repo")) {
      c.set("repo", deps.repo);
    }
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json(
        { error: { message: `Missing ${BRAND.name} Bearer API key`, type: "auth_error" } },
        401
      );
    }

    const rawKey = authHeader.slice("Bearer ".length).trim();
    const verified = await c.get("repo").verifyApiKey(rawKey);
    if (!verified || !verified.scopes.includes("proxy:write")) {
      return c.json(
        { error: { message: "Invalid API key or missing proxy:write scope", type: "auth_error" } },
        401
      );
    }

    c.set("auth", {
      tenantId: verified.tenantId,
      keyId: verified.keyId,
      projectId: verified.projectId,
      scopes: verified.scopes,
    });
    await next();
  });

  v1.get("/models", (c) => {
    const models = Object.values(DEFAULT_MODELS)
      .flat()
      .map((m) => ({
        id: m.id,
        object: "model",
        created: 1735689600,
        owned_by: m.provider,
      }));

    return c.json({ object: "list", data: models });
  });

  v1.post("/chat/completions", async (c) => {
    const startedAt = Date.now();
    const auth = c.get("auth");
    const repo = c.get("repo");

    const rawText = await c.req.text();
    if (rawText.length > 512_000) {
      return c.json({ error: { message: "Request body exceeds 512KB limit", type: "invalid_request_error" } }, 413);
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(rawText);
    } catch {
      return c.json({ error: { message: "Malformed JSON body", type: "invalid_request_error" } }, 400);
    }

    const parsedReq = ChatCompletionRequestSchema.safeParse(parsedJson);
    if (!parsedReq.success) {
      return c.json(
        { error: { message: "Invalid OpenAI chat request payload", details: parsedReq.error.flatten() } },
        400
      );
    }

    // 1. Check Toll (Rate Limit & Budgets)
    const rateCheck = deps.rateLimiter.checkAndConsumeRequest({
      tenantId: auth.tenantId,
      scope: "tenant",
      scopeId: auth.tenantId,
    });

    c.header(`${BRAND.headerPrefix}-RateLimit-Remaining-RPM`, String(rateCheck.remainingRpm));

    if (!rateCheck.allowed) {
      c.header("Retry-After", String(rateCheck.retryAfterSeconds));
      return c.json(
        {
          error: {
            message: `Rate limit or budget exceeded (${rateCheck.reason}). Retry after ${rateCheck.retryAfterSeconds}s.`,
            type: "rate_limit_error",
            code: rateCheck.reason,
            retry_after_seconds: rateCheck.retryAfterSeconds,
          },
        },
        429
      );
    }

    const providerHeader = c.req.header(`${BRAND.headerPrefix}-Provider`) ?? "gemini";
    const providerParse = ProviderNameSchema.safeParse(providerHeader);
    if (!providerParse.success) {
      return c.json({ error: { message: `Unsupported provider: ${providerHeader}` } }, 400);
    }
    const provider: ProviderName = providerParse.data;

    const reqId = `req_${crypto.randomUUID()}`;
    const sessionId = c.req.header(`${BRAND.headerPrefix}-Session-Id`) ?? null;
    const projectHeader = c.req.header(`${BRAND.headerPrefix}-Project-Id`) ?? auth.projectId;
    const policy = await repo.resolveEffectivePolicy(auth.tenantId, projectHeader);

    // 2. Analyze untrusted tool_result messages for taint, and evaluate non-tool messages
    const taintContext = analyzeUntrustedToolResults(parsedReq.data.messages, policy);
    const nonToolMessagesText = parsedReq.data.messages
      .filter((m) => m.role !== "tool")
      .map((m) => m.content ?? "")
      .join("\n");

    const evaluation = evaluateInputPipeline(nonToolMessagesText, policy);

    if (evaluation.finalAction === "block") {
      await repo.insertRequest(auth.tenantId, {
        id: reqId,
        sessionId,
        provider,
        model: parsedReq.data.model,
        finalAction: "block",
        promptRedacted: evaluation.sanitizedText,
        responseRedacted: `[Blocked by ${BRAND.name} Gatekeeper]`,
        latencyMs: Date.now() - startedAt,
        createdAt: Date.now(),
      });
      await repo.insertFindings(auth.tenantId, reqId, evaluation.findings);
      await repo.appendAuditRecord({
        tenantId: auth.tenantId,
        requestId: reqId,
        eventType: "proxy.request.blocked",
        payload: {
          requestId: reqId,
          model: parsedReq.data.model,
          action: "block",
          findingRuleIds: evaluation.findings.map((f) => f.ruleId),
        },
      });

      c.header(`${BRAND.headerPrefix}-Request-Id`, reqId);
      c.header(`${BRAND.headerPrefix}-Action`, "block");
      return c.json(
        {
          error: {
            message: `Request blocked by ${BRAND.name} security policy`,
            type: "policy_violation",
            request_id: reqId,
            findings: evaluation.findings.map((f) => ({
              id: f.id,
              detector: f.detector,
              rule_id: f.ruleId,
              owasp_category: f.owaspCategory,
              message: f.message,
            })),
          },
        },
        403
      );
    }

    // 3. Check Echo (Semantic Cache)
    const policyHash = (await sha256Hex(JSON.stringify(policy))).slice(0, 16);
    if (policy.semanticCache.enabled && !parsedReq.data.stream && !taintContext.isTainted) {
      const cacheHit = deps.semanticCache.lookup({
        tenantId: auth.tenantId,
        policyHash,
        model: parsedReq.data.model,
        promptText: evaluation.sanitizedText,
        similarityThreshold: policy.semanticCache.similarityThreshold,
      });

      if (cacheHit) {
        await repo.insertRequest(auth.tenantId, {
          id: reqId,
          sessionId,
          provider,
          model: parsedReq.data.model,
          finalAction: evaluation.finalAction,
          cacheHit: true,
          promptRedacted: evaluation.sanitizedText,
          responseRedacted: "[Served by Echo Semantic Cache]",
          latencyMs: Date.now() - startedAt,
          createdAt: Date.now(),
        });

        c.header(`${BRAND.headerPrefix}-Request-Id`, reqId);
        c.header(`${BRAND.headerPrefix}-Cache`, "HIT");
        c.header(`${BRAND.headerPrefix}-Cache-Similarity`, cacheHit.similarity.toFixed(4));
        c.header(`${BRAND.headerPrefix}-Action`, evaluation.finalAction);
        return c.json(cacheHit.entry.responseJson, 200);
      }
    }

    c.header(`${BRAND.headerPrefix}-Cache`, "MISS");

    // 4. Resolve upstream provider key
    const headerProviderKey = c.req.header(`${BRAND.headerPrefix}-Provider-Key`);
    const headerBaseUrl = c.req.header(`${BRAND.headerPrefix}-Provider-Base-Url`);

    let upstreamApiKey = headerProviderKey ?? null;
    let upstreamBaseUrl = headerBaseUrl ?? null;

    if (!upstreamApiKey) {
      const storedCred = await repo.getDecryptedProviderCredential(auth.tenantId, provider);
      if (!storedCred) {
        return c.json(
          {
            error: {
              message: `No upstream API key configured for provider '${provider}'. Supply ${BRAND.headerPrefix}-Provider-Key or save a tenant credential.`,
              type: "configuration_error",
            },
          },
          400
        );
      }
      upstreamApiKey = storedCred.apiKey;
      upstreamBaseUrl = upstreamBaseUrl ?? storedCred.baseUrl;
    }

    const canaryToken = generateCanaryToken();
    const outgoingMessages = parsedReq.data.messages.map((m, idx) => {
      let content = m.content ?? "";
      for (const [placeholder, original] of Object.entries(evaluation.redactionMap)) {
        content = content.split(original).join(placeholder);
      }
      if (m.role === "system" && idx === 0 && policy.detectors.canary.enabled) {
        content = injectCanaryIntoSystemPrompt(content, canaryToken);
      }
      return { ...m, content };
    });

    let upstreamRes: Response;
    try {
      upstreamRes = await callUpstreamProvider({
        provider,
        apiKey: upstreamApiKey,
        baseUrl: upstreamBaseUrl,
        body: { ...parsedReq.data, messages: outgoingMessages },
        fetchImpl: deps.customFetch,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Upstream request failed";
      return c.json({ error: { message, type: "upstream_error" } }, 400);
    }

    // 5. Handle Streaming SSE with Sliding-Window Output Scanner
    if (parsedReq.data.stream && upstreamRes.body) {
      await repo.insertRequest(auth.tenantId, {
        id: reqId,
        sessionId,
        provider,
        model: parsedReq.data.model,
        finalAction: evaluation.finalAction,
        promptRedacted: evaluation.sanitizedText,
        responseRedacted: "[streamed]",
        latencyMs: Date.now() - startedAt,
        createdAt: Date.now(),
      });
      await repo.insertFindings(auth.tenantId, reqId, evaluation.findings);

      const scannedStream = createScannedSseStream(upstreamRes.body, {
        policy,
        canaryToken,
        redactionMap: evaluation.redactionMap,
        onViolation: async (finding) => {
          await repo.insertFindings(auth.tenantId, reqId, [finding]);
        },
      });

      return new Response(scannedStream, {
        status: upstreamRes.status,
        headers: {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
          [`${BRAND.headerPrefix}-Request-Id`]: reqId,
          [`${BRAND.headerPrefix}-Provider`]: provider,
          [`${BRAND.headerPrefix}-Action`]: evaluation.finalAction,
        },
      });
    }

    // 6. Handle Non-Streaming JSON Response + Agent Tool-Call Firewall
    const upstreamJson = (await upstreamRes.json()) as {
      choices?: {
        message?: {
          role?: string;
          content?: string | null;
          tool_calls?: IncomingToolCall[];
        };
      }[];
      usage?: { prompt_tokens?: number; completion_tokens?: number };
    };

    let assistantText = upstreamJson.choices?.[0]?.message?.content ?? "";
    const incomingToolCalls = upstreamJson.choices?.[0]?.message?.tool_calls ?? [];

    // Inspect Agent Tool Calls through Firewall if present
    if (policy.toolFirewall.enabled && incomingToolCalls.length > 0) {
      // Save request row first so toolCalls foreign key is satisfied
      await repo.insertRequest(auth.tenantId, {
        id: reqId,
        sessionId,
        provider,
        model: parsedReq.data.model,
        finalAction: evaluation.finalAction,
        promptRedacted: evaluation.sanitizedText,
        responseRedacted: assistantText || "[tool_calls]",
        latencyMs: Date.now() - startedAt,
        createdAt: Date.now(),
      });

      const decisions = evaluateToolCallsFirewall({
        toolCalls: incomingToolCalls,
        policy,
        taintContext,
      });

      const approvalIds: string[] = [];
      for (const dec of decisions) {
        evaluation.findings.push(...dec.findings);
        const recorded = await repo.recordToolCallAndApproval({
          id: dec.toolCallId || `tc_${crypto.randomUUID()}`,
          tenantId: auth.tenantId,
          requestId: reqId,
          sessionId,
          toolName: dec.toolName,
          argumentsRedactedJson: dec.argumentsRedactedJson,
          taintDetected: dec.taintDetected,
          status: dec.status,
        });
        if (recorded.approvalId) {
          approvalIds.push(recorded.approvalId);
        }
      }

      await repo.insertFindings(auth.tenantId, reqId, evaluation.findings);

      const blockedDecision = decisions.find((d) => d.status === "blocked");
      if (blockedDecision && policy.mode === "enforce") {
        c.header(`${BRAND.headerPrefix}-Request-Id`, reqId);
        c.header(`${BRAND.headerPrefix}-Action`, "block");
        return c.json(
          {
            error: {
              message: `Agent tool call '${blockedDecision.toolName}' blocked by ${BRAND.name} Tool Firewall`,
              type: "tool_firewall_violation",
              request_id: reqId,
              taint_detected: blockedDecision.taintDetected,
              findings: blockedDecision.findings,
            },
          },
          403
        );
      }

      const pendingDecision = decisions.find((d) => d.status === "pending_approval");
      if (pendingDecision && policy.mode === "enforce") {
        c.header(`${BRAND.headerPrefix}-Request-Id`, reqId);
        c.header(`${BRAND.headerPrefix}-Action`, "flag");
        return c.json(
          {
            error: {
              message: `Agent tool call '${pendingDecision.toolName}' requires human approval before execution`,
              type: "approval_required",
              request_id: reqId,
              approval_ids: approvalIds,
            },
          },
          202
        );
      }

      c.header(`${BRAND.headerPrefix}-Request-Id`, reqId);
      c.header(`${BRAND.headerPrefix}-Action`, evaluation.finalAction);
      return c.json(upstreamJson, 200);
    }

    // Check Canary Token Leak on standard assistant response
    if (policy.detectors.canary.enabled) {
      const canaryFinding = checkCanaryLeak({
        responseText: assistantText,
        canaryToken,
        action: policy.detectors.canary.action,
      });
      if (canaryFinding) {
        evaluation.findings.push(canaryFinding);
        await repo.insertRequest(auth.tenantId, {
          id: reqId,
          sessionId,
          provider,
          model: parsedReq.data.model,
          finalAction: "block",
          promptRedacted: evaluation.sanitizedText,
          responseRedacted: "[Blocked: Canary Token Leaked]",
          latencyMs: Date.now() - startedAt,
          createdAt: Date.now(),
        });
        await repo.insertFindings(auth.tenantId, reqId, evaluation.findings);

        return c.json(
          {
            error: {
              message: `Response blocked by ${BRAND.name}: system prompt canary token leak detected`,
              type: "canary_leak",
              request_id: reqId,
            },
          },
          403
        );
      }
    }

    if (policy.detectors.pii.restoreOnResponse && Object.keys(evaluation.redactionMap).length > 0) {
      assistantText = restoreRedactedValues(assistantText, evaluation.redactionMap);
      if (upstreamJson.choices?.[0]?.message) {
        upstreamJson.choices[0].message.content = assistantText;
      }
    }

    const promptTokens = upstreamJson.usage?.prompt_tokens ?? 20;
    const completionTokens = upstreamJson.usage?.completion_tokens ?? 10;
    const costUsd = estimateCostUsd(promptTokens, completionTokens);

    deps.rateLimiter.recordUsage({
      tenantId: auth.tenantId,
      totalTokens: promptTokens + completionTokens,
      costUsd,
    });

    if (policy.semanticCache.enabled && upstreamRes.status === 200) {
      deps.semanticCache.store({
        tenantId: auth.tenantId,
        policyHash,
        model: parsedReq.data.model,
        promptText: evaluation.sanitizedText,
        responseJson: upstreamJson as Record<string, unknown>,
        promptTokens,
        completionTokens,
        costUsd,
        ttlSeconds: policy.semanticCache.ttlSeconds,
      });
    }

    await repo.insertRequest(auth.tenantId, {
      id: reqId,
      sessionId,
      provider,
      model: parsedReq.data.model,
      finalAction: evaluation.finalAction,
      promptTokens,
      completionTokens,
      costUsd,
      promptRedacted: evaluation.sanitizedText,
      responseRedacted: assistantText,
      latencyMs: Date.now() - startedAt,
      createdAt: Date.now(),
    });
    await repo.insertFindings(auth.tenantId, reqId, evaluation.findings);
    await repo.appendAuditRecord({
      tenantId: auth.tenantId,
      requestId: reqId,
      eventType: "proxy.request.completed",
      payload: {
        requestId: reqId,
        model: parsedReq.data.model,
        action: evaluation.finalAction,
        promptTokens,
        completionTokens,
      },
    });

    c.header(`${BRAND.headerPrefix}-Request-Id`, reqId);
    c.header(`${BRAND.headerPrefix}-Provider`, provider);
    c.header(`${BRAND.headerPrefix}-Action`, evaluation.finalAction);
    return c.json(upstreamJson, upstreamRes.status as 200);
  });

  return v1;
}