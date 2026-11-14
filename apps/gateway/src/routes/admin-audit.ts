import { Hono } from "hono";
import { z } from "zod";
import type { AppVariables } from "../index.js";
import type { TenantRepository } from "../db/repository.js";

const CreateWebhookSchema = z.object({
  url: z.string().url(),
  signingSecret: z.string().min(16),
  events: z.array(z.string()).min(1),
});

export function createAdminAuditRoutes(injectedRepo?: TenantRepository) {
  const router = new Hono<{ Variables: AppVariables }>();

  router.use("*", async (c, next) => {
    if (injectedRepo && !c.get("repo")) {
      c.set("repo", injectedRepo);
    }
    if (!c.get("auth")) {
      const authHeader = c.req.header("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return c.json({ error: { message: "Missing Bearer API key", code: "unauthorized" } }, 401);
      }
      const rawKey = authHeader.slice("Bearer ".length).trim();
      const verified = await c.get("repo").verifyApiKey(rawKey);
      if (!verified) {
        return c.json({ error: { message: "Invalid, expired, or revoked API key", code: "unauthorized" } }, 401);
      }
      c.set("auth", {
        tenantId: verified.tenantId,
        keyId: verified.keyId,
        projectId: verified.projectId,
        scopes: verified.scopes,
      });
    }
    await next();
  });

  // Verify the tenant's tamper-evident SHA-256 audit log chain
  router.get("/audit/verify", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:read")) {
      return c.json({ error: { message: "Requires admin:read scope", code: "forbidden" } }, 403);
    }
    const verification = await c.get("repo").verifyTenantAuditChain(auth.tenantId);
    return c.json({ data: verification });
  });

  // Seal current audit chain into a signed batch
  router.post("/audit/seal", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }
    try {
      const batch = await c.get("repo").sealAuditBatch(auth.tenantId);
      return c.json({ data: batch }, 201);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to seal batch";
      return c.json({ error: { message: msg } }, 400);
    }
  });

  // Register an HMAC-signed webhook
  router.post("/webhooks", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }
    const parsed = CreateWebhookSchema.safeParse(await c.req.json());
    if (!parsed.success) {
      return c.json({ error: { message: "Invalid webhook configuration", details: parsed.error.flatten() } }, 400);
    }

    const id = `wh_${crypto.randomUUID()}`;
    try {
      await c.get("repo").createWebhook({
        id,
        tenantId: auth.tenantId,
        url: parsed.data.url,
        signingSecret: parsed.data.signingSecret,
        events: parsed.data.events,
      });
      return c.json({ data: { id, url: parsed.data.url, events: parsed.data.events } }, 201);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Webhook creation failed";
      return c.json({ error: { message: msg } }, 400);
    }
  });

  return router;
}