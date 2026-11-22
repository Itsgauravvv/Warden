import { Hono } from "hono";
import { z } from "zod";
import type { AppVariables } from "../index.js";
import type { TenantRepository } from "../db/repository.js";
import type { ApiKeyScope } from "../auth/api-key.js";
import { ProviderNameSchema } from "../adapters/provider.js";

const CreateKeyBodySchema = z.object({
  name: z.string().min(2).max(80),
  scopes: z
    .array(z.enum(["proxy:write", "admin:read", "admin:write"]))
    .min(1)
    .default(["proxy:write", "admin:read"]),
  isSandbox: z.boolean().optional(),
});

const SaveCredentialBodySchema = z.object({
  provider: ProviderNameSchema,
  apiKey: z.string().min(8).max(512),
  baseUrl: z.string().url().optional(),
});

export function createAdminVaultRoutes(injectedRepo?: TenantRepository) {
  const router = new Hono<{ Variables: AppVariables }>();

  router.use("*", async (c, next) => {
    if (injectedRepo && !c.get("repo")) {
      c.set("repo", injectedRepo);
    }
    await next();
  });

  // List tenant API keys (metadata only — never returns hashes or raw keys)
  router.get("/keys", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:read")) {
      return c.json({ error: { message: "Requires admin:read scope", code: "forbidden" } }, 403);
    }
    const keys = await c.get("repo").listApiKeys(auth.tenantId);
    return c.json({ data: keys });
  });

  // Issue a new wrd_ API key for the authenticated tenant (rawKey shown once)
  router.post("/keys", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }
    const parsed = CreateKeyBodySchema.safeParse(await c.req.json());
    if (!parsed.success) {
      return c.json(
        { error: { message: "Invalid key payload", details: parsed.error.flatten() } },
        400
      );
    }

    const issued = await c.get("repo").createApiKey({
      id: `key_${crypto.randomUUID()}`,
      tenantId: auth.tenantId,
      name: parsed.data.name,
      scopes: parsed.data.scopes as ApiKeyScope[],
      isSandbox: parsed.data.isSandbox,
    });

    return c.json({ data: issued }, 201);
  });

  // Revoke an existing tenant API key
  router.delete("/keys/:id", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }
    await c.get("repo").revokeApiKey(auth.tenantId, c.req.param("id"));
    return c.json({ data: { revoked: true, id: c.req.param("id") } });
  });

  // List saved upstream provider credentials (metadata only)
  router.get("/credentials", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:read")) {
      return c.json({ error: { message: "Requires admin:read scope", code: "forbidden" } }, 403);
    }
    const creds = await c.get("repo").listProviderCredentials(auth.tenantId);
    return c.json({ data: creds });
  });

  // Encrypt & store an upstream provider key (Gemini, Groq, OpenRouter, etc.) with AES-256-GCM
  router.post("/credentials", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }
    const parsed = SaveCredentialBodySchema.safeParse(await c.req.json());
    if (!parsed.success) {
      return c.json(
        { error: { message: "Invalid provider credential", details: parsed.error.flatten() } },
        400
      );
    }

    const id = `cred_${crypto.randomUUID()}`;
    try {
      await c.get("repo").saveProviderCredential({
        id,
        tenantId: auth.tenantId,
        provider: parsed.data.provider,
        rawApiKey: parsed.data.apiKey.trim(),
        baseUrl: parsed.data.baseUrl,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to save credential";
      return c.json({ error: { message, code: "invalid_credential" } }, 400);
    }

    return c.json(
      {
        data: {
          id,
          provider: parsed.data.provider,
          baseUrl: parsed.data.baseUrl ?? null,
          encrypted: true,
        },
      },
      201
    );
  });

  return router;
}