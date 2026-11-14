import { Hono } from "hono";
import { createAdminAuditRoutes } from "./routes/admin-audit.js";
import { secureHeaders } from "hono/secure-headers";
import { z } from "zod";
import { BRAND } from "@warden/brand";
import type { TenantRepository } from "./db/repository.js";
import type { ApiKeyScope } from "./auth/api-key.js";
import { createV1Routes } from "./routes/v1.js";
import { createAdminPolicyRoutes } from "./routes/admin-policies.js";
import { RateLimitEngine, RateLimiterDO } from "./durable-objects/rate-limiter.js";
import { SemanticCache } from "./cache/semantic-cache.js";

export { RateLimiterDO };

export interface AuthContext {
  tenantId: string;
  keyId: string;
  projectId: string | null;
  scopes: ApiKeyScope[];
}

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
}

export function createGatewayApp(
  repoOrOptions?: TenantRepository | GatewayAppOptions,
  customFetch?: typeof fetch
) {
  const isOptions =
    repoOrOptions !== undefined &&
    !("createTenant" in repoOrOptions);

  const repo = isOptions ? repoOrOptions.repo : repoOrOptions;
  const fetchImpl = isOptions ? repoOrOptions.customFetch : customFetch;
  const rateLimiter = (isOptions && repoOrOptions.rateLimiter) || new RateLimitEngine();
  const semanticCache = (isOptions && repoOrOptions.semanticCache) || new SemanticCache();

  const app = new Hono<{ Variables: AppVariables }>();

  app.use("*", secureHeaders());
  app.use("*", async (c, next) => {
    c.header(`${BRAND.headerPrefix}-Gate`, BRAND.name);
    if (repo) {
      c.set("repo", repo);
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

  // Mount OpenAI-compatible /v1 proxy routes (defaults to Gemini)
  app.route("/v1", createV1Routes({ repo, customFetch: fetchImpl, rateLimiter, semanticCache }));

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

  // Configure tenant rate limits & budgets (Toll)
  app.put("/admin/v1/budgets", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }
    const schema = z.object({
      rpmLimit: z.number().int().positive().optional(),
      dailyTokenLimit: z.number().int().positive().optional(),
      monthlyCostLimitUsd: z.number().positive().optional(),
    });
    const parsed = schema.safeParse(await c.req.json());
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

  app.route("/admin/v1/policies", createAdminPolicyRoutes(repo));
  app.route("/admin/v1", createAdminAuditRoutes(repo));

  return app;
}

export default createGatewayApp();