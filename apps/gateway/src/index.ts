import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { drizzle } from "drizzle-orm/d1";
import { z } from "zod";
import { BRAND } from "@warden/brand";
import { runEvaluationSuite } from "@warden/eval";
import * as schema from "./db/schema.js";
import { TenantRepository, type WardenDb } from "./db/repository.js";
import type { ApiKeyScope } from "./auth/api-key.js";
import { createV1Routes } from "./routes/v1.js";
import { createAdminPolicyRoutes } from "./routes/admin-policies.js";
import { createAdminAuditRoutes } from "./routes/admin-audit.js";
import { createAdminRedTeamRoutes } from "./routes/admin-redteam.js";
import { createAdminVaultRoutes } from "./routes/admin-vault.js";
import { RateLimitEngine, RateLimiterDO } from "./durable-objects/rate-limiter.js";
import { SemanticCache } from "./cache/semantic-cache.js";
import { JudgeBudgetTracker, buildGroundedIncidentExplanation } from "./genai/judge.js";

export { RateLimiterDO };

export interface AuthContext {
  tenantId: string;
  keyId: string;
  projectId: string | null;
  scopes: ApiKeyScope[];
}

export type AppBindings = {
  DB?: Parameters<typeof drizzle>[0];
  WARDEN_ENCRYPTION_SECRET?: string;
  WARDEN_BOOTSTRAP_SECRET?: string;
};

export type AppVariables = {
  auth: AuthContext;
  repo: TenantRepository;
  rateLimiter: RateLimitEngine;
  semanticCache: SemanticCache;
};

export interface GatewayAppOptions {
  repo?: TenantRepository;
  customFetch?: typeof fetch;
  rateLimiter?: RateLimitEngine;
  semanticCache?: SemanticCache;
  judgeBudget?: JudgeBudgetTracker;
  bootstrapSecret?: string;
}

const BootstrapTenantSchema = z.object({
  name: z.string().min(2).max(80),
  isSandbox: z.boolean().optional(),
});

export function createGatewayApp(
  repoOrOptions?: TenantRepository | GatewayAppOptions,
  customFetch?: typeof fetch
) {
  const isOptions =
    repoOrOptions !== undefined &&
    !("createTenant" in repoOrOptions);

  const injectedRepo = isOptions ? repoOrOptions.repo : repoOrOptions;
  const fetchImpl = isOptions ? repoOrOptions.customFetch : customFetch;
  const rateLimiter = (isOptions && repoOrOptions.rateLimiter) || new RateLimitEngine();
  const semanticCache = (isOptions && repoOrOptions.semanticCache) || new SemanticCache();
  const judgeBudget = (isOptions && repoOrOptions.judgeBudget) || new JudgeBudgetTracker();
  const configuredBootstrapSecret = isOptions ? repoOrOptions.bootstrapSecret : undefined;

  const app = new Hono<{ Bindings: AppBindings; Variables: AppVariables }>();

  app.use(
    "*",
    cors({
      origin: "*",
      allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowHeaders: [
        "Content-Type",
        "Authorization",
        `${BRAND.headerPrefix}-Provider`,
        `${BRAND.headerPrefix}-Provider-Key`,
        `${BRAND.headerPrefix}-Provider-Base-Url`,
        `${BRAND.headerPrefix}-Project-Id`,
        `${BRAND.headerPrefix}-Session-Id`,
        `${BRAND.headerPrefix}-Bootstrap-Secret`,
      ],
      exposeHeaders: [
        `${BRAND.headerPrefix}-Request-Id`,
        `${BRAND.headerPrefix}-Action`,
        `${BRAND.headerPrefix}-Cache`,
        `${BRAND.headerPrefix}-Provider`,
        `${BRAND.headerPrefix}-RateLimit-Remaining-RPM`,
      ],
    })
  );

  app.use("*", secureHeaders());

  app.use("*", async (c, next) => {
    c.header(`${BRAND.headerPrefix}-Gate`, BRAND.name);
    if (injectedRepo) {
      c.set("repo", injectedRepo);
    } else if (c.env?.DB) {
      const db = drizzle(c.env.DB, { schema }) as unknown as WardenDb;
      c.set("repo", new TenantRepository(db, c.env.WARDEN_ENCRYPTION_SECRET));
    }
    c.set("rateLimiter", rateLimiter);
    c.set("semanticCache", semanticCache);
    await next();
  });

  app.get("/healthz", (c) =>
    c.json({
      status: "ok",
      service: BRAND.name,
      tagline: BRAND.tagline,
    })
  );

  app.get("/readyz", (c) => {
    const isReady = Boolean(c.get("repo"));
    return c.json({ ready: isReady }, isReady ? 200 : 503);
  });

  // Self-serve tenant onboarding (creates tenant + initial wrd_ API key in D1)
  app.post("/bootstrap/tenant", async (c) => {
    const requiredSecret = configuredBootstrapSecret ?? c.env?.WARDEN_BOOTSTRAP_SECRET;
    if (requiredSecret) {
      const supplied = c.req.header(`${BRAND.headerPrefix}-Bootstrap-Secret`);
      if (supplied !== requiredSecret) {
        return c.json(
          { error: { message: "Invalid or missing bootstrap secret", code: "unauthorized" } },
          401
        );
      }
    }

    const activeRepo = c.get("repo");
    if (!activeRepo) {
      return c.json(
        { error: { message: "D1 database binding is not ready", code: "service_unavailable" } },
        503
      );
    }

    const parsed = BootstrapTenantSchema.safeParse(await c.req.json());
    if (!parsed.success) {
      return c.json(
        { error: { message: "Invalid tenant details", details: parsed.error.flatten() } },
        400
      );
    }

    const tenantId = `t_${crypto.randomUUID().slice(0, 12)}`;
    const slugBase = parsed.data.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 24);
    const slug = `${slugBase || "tenant"}-${crypto.randomUUID().slice(0, 6)}`;
    const isSandbox = parsed.data.isSandbox ?? true;

    await activeRepo.createTenant({
      id: tenantId,
      name: parsed.data.name,
      slug,
      isSandbox,
    });

    const issued = await activeRepo.createApiKey({
      id: `key_${crypto.randomUUID()}`,
      tenantId,
      name: "Initial Admin & Proxy Key",
      scopes: ["proxy:write", "admin:read", "admin:write"],
      isSandbox,
    });

    return c.json(
      {
        data: {
          tenantId,
          name: parsed.data.name,
          slug,
          isSandbox,
          apiKey: issued.rawKey,
          keyId: issued.id,
          prefix: issued.prefix,
          scopes: issued.scopes,
        },
      },
      201
    );
  });

  // Public evaluation benchmark endpoint for the /eval transparency page
  app.get("/eval/summary", (c) => {
    const suite = runEvaluationSuite();
    return c.json({
      data: {
        tpr: suite.tpr,
        fpr: suite.fpr,
        totalCases: suite.totalCases,
        truePositives: suite.truePositives,
        falsePositives: suite.falsePositives,
        p95LatencyMs: suite.p95LatencyMs,
        byCategory: suite.byCategory,
        licenses: suite.licenses,
        regressionGatePassed: suite.regressionGatePassed,
        disclaimer:
          "Detection is probabilistic and defense-in-depth; no gateway catches 100% of novel attacks.",
      },
    });
  });

  // Mount OpenAI-compatible /v1 proxy routes (defaults to Gemini)
  app.route(
    "/v1",
    createV1Routes({
      repo: injectedRepo,
      customFetch: fetchImpl,
      rateLimiter,
      semanticCache,
      judgeBudget,
    })
  );

  // Tenant API Key Auth Middleware for /admin/v1/*
  app.use("/admin/v1/*", async (c, next) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json({ error: { message: "Missing Bearer API key", code: "unauthorized" } }, 401);
    }
    const rawKey = authHeader.slice("Bearer ".length).trim();
    const activeRepo = c.get("repo");
    const verified = await activeRepo.verifyApiKey(rawKey);

    if (!verified) {
      return c.json({ error: { message: "Invalid, expired, or revoked API key", code: "unauthorized" } }, 401);
    }

    c.set("auth", {
      tenantId: verified.tenantId,
      keyId: verified.keyId,
      projectId: verified.projectId,
      scopes: verified.scopes,
    });
    await next();
  });

  app.get("/admin/v1/requests/:id", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:read")) {
      return c.json({ error: { message: "Insufficient scope: requires admin:read", code: "forbidden" } }, 403);
    }
    const record = await c.get("repo").getRequestById(auth.tenantId, c.req.param("id"));
    if (!record) {
      return c.json({ error: { message: "Request not found", code: "not_found" } }, 404);
    }
    return c.json({ data: record });
  });

  // Grounded Incident Explainer citing ONLY stored findings for a tenant-scoped request
  app.get("/admin/v1/requests/:id/explain", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:read")) {
      return c.json({ error: { message: "Insufficient scope: requires admin:read", code: "forbidden" } }, 403);
    }
    const requestId = c.req.param("id");
    const activeRepo = c.get("repo");
    const record = await activeRepo.getRequestById(auth.tenantId, requestId);
    if (!record) {
      return c.json({ error: { message: "Request not found", code: "not_found" } }, 404);
    }
    const storedFindings = await activeRepo.getFindingsByRequestId(auth.tenantId, requestId);
    const explanation = buildGroundedIncidentExplanation(
      record.id,
      record.finalAction,
      storedFindings
    );
    return c.json({ data: explanation });
  });

  // Configure tenant rate limits & budgets (Toll)
  app.put("/admin/v1/budgets", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }
    const schemaBody = z.object({
      rpmLimit: z.number().int().positive().optional(),
      dailyTokenLimit: z.number().int().positive().optional(),
      monthlyCostLimitUsd: z.number().positive().optional(),
    });
    const parsed = schemaBody.safeParse(await c.req.json());
    if (!parsed.success) {
      return c.json({ error: { message: "Invalid budget limits" } }, 400);
    }
    c.get("rateLimiter").setLimits(auth.tenantId, "tenant", auth.tenantId, parsed.data);
    return c.json({ data: { tenantId: auth.tenantId, ...parsed.data } });
  });

  // Inspect semantic cache savings (Echo)
  app.get("/admin/v1/cache/stats", (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:read")) {
      return c.json({ error: { message: "Requires admin:read scope", code: "forbidden" } }, 403);
    }
    return c.json({ data: c.get("semanticCache").getTenantStats(auth.tenantId) });
  });

  app.route("/admin/v1/policies", createAdminPolicyRoutes(injectedRepo));
  app.route("/admin/v1/redteam", createAdminRedTeamRoutes(injectedRepo, fetchImpl));
  app.route("/admin/v1/vault", createAdminVaultRoutes(injectedRepo));
  app.route("/admin/v1", createAdminAuditRoutes(injectedRepo));

  return app;
}

export default createGatewayApp();