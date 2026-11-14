import { Hono } from "hono";
import { z } from "zod";
import {
  diffPolicyDocuments,
  parsePolicyYamlOrJson,
  PolicyDocumentSchema,
} from "@warden/policy-schema";
import type { AppVariables } from "../index.js";
import type { TenantRepository } from "../db/repository.js";
import { runPolicyDryRunOnHistory } from "../pipeline/dry-run.js";

const CreateVersionBodySchema = z.object({
  name: z.string().min(1),
  content: z.string().min(1),
});

const RollbackBodySchema = z.object({
  versionNumber: z.number().int().positive(),
});

const DryRunBodySchema = z.object({
  content: z.string().min(1),
  limit: z.number().int().min(1).max(200).optional(),
});

export function createAdminPolicyRoutes(injectedRepo?: TenantRepository) {
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

  router.post("/:policyId/versions", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }

    const body = CreateVersionBodySchema.safeParse(await c.req.json());
    if (!body.success) {
      return c.json({ error: { message: "Invalid request body", details: body.error.flatten() } }, 400);
    }

    try {
      const saved = await c.get("repo").savePolicyVersion({
        tenantId: auth.tenantId,
        policyId: c.req.param("policyId"),
        name: body.data.name,
        rawYamlOrJson: body.data.content,
        createdBy: auth.keyId,
      });
      return c.json({ data: saved }, 201);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Policy validation failed";
      return c.json({ error: { message: msg, code: "invalid_policy" } }, 400);
    }
  });

  router.post("/:policyId/rollback", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }

    const body = RollbackBodySchema.safeParse(await c.req.json());
    if (!body.success) {
      return c.json({ error: { message: "Invalid versionNumber" } }, 400);
    }

    try {
      const rolledBack = await c
        .get("repo")
        .rollbackPolicyVersion(auth.tenantId, c.req.param("policyId"), body.data.versionNumber);
      return c.json({ data: rolledBack });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Rollback failed";
      return c.json({ error: { message: msg, code: "not_found" } }, 404);
    }
  });

  router.get("/:policyId/diff", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:read")) {
      return c.json({ error: { message: "Requires admin:read scope", code: "forbidden" } }, 403);
    }

    const fromVer = Number(c.req.query("from") ?? "1");
    const toVer = Number(c.req.query("to") ?? "2");
    const policyId = c.req.param("policyId");
    const repo = c.get("repo");

    const vA = await repo.getPolicyVersionByNumber(auth.tenantId, policyId, fromVer);
    const vB = await repo.getPolicyVersionByNumber(auth.tenantId, policyId, toVer);

    if (!vA || !vB) {
      return c.json({ error: { message: "One or both policy versions not found" } }, 404);
    }

    const docA = PolicyDocumentSchema.parse(JSON.parse(vA.parsedJson));
    const docB = PolicyDocumentSchema.parse(JSON.parse(vB.parsedJson));
    const changes = diffPolicyDocuments(docA, docB);

    return c.json({
      data: {
        policyId,
        fromVersion: fromVer,
        toVersion: toVer,
        changes,
      },
    });
  });

  router.post("/dry-run", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:read")) {
      return c.json({ error: { message: "Requires admin:read scope", code: "forbidden" } }, 403);
    }

    const body = DryRunBodySchema.safeParse(await c.req.json());
    if (!body.success) {
      return c.json({ error: { message: "Invalid dry-run payload" } }, 400);
    }

    try {
      const { policy } = parsePolicyYamlOrJson(body.data.content);
      const report = await runPolicyDryRunOnHistory({
        repo: c.get("repo"),
        tenantId: auth.tenantId,
        candidatePolicy: policy,
        limit: body.data.limit,
      });
      return c.json({ data: report });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Dry-run failed";
      return c.json({ error: { message: msg, code: "invalid_policy" } }, 400);
    }
  });

  return router;
}