import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { BRAND } from "@warden/brand";
import type { TenantRepository } from "./db/repository.js";
import type { ApiKeyScope } from "./auth/api-key.js";
import { createV1Routes } from "./routes/v1.js";

export interface AuthContext {
  tenantId: string;
  keyId: string;
  projectId: string | null;
  scopes: ApiKeyScope[];
}

export type AppVariables = {
  auth: AuthContext;
  repo: TenantRepository;
};

export function createGatewayApp(repo?: TenantRepository, customFetch?: typeof fetch) {
  const app = new Hono<{ Variables: AppVariables }>();

  app.use("*", secureHeaders());
  app.use("*", async (c, next) => {
    c.header(`${BRAND.headerPrefix}-Gate`, BRAND.name);
    if (repo) {
      c.set("repo", repo);
    }
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
  app.route("/v1", createV1Routes(customFetch));

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

  return app;
}

export default createGatewayApp();