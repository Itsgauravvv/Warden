import { Hono } from "hono";
import { z } from "zod";
import { BRAND } from "@warden/brand";
import type { AppVariables } from "../index.js";
import type { TenantRepository } from "../db/repository.js";
import { runRedTeamSiege } from "../genai/redteam.js";
import { draftPolicyWithQuill } from "../genai/copilot.js";

const SiegeBodySchema = z.object({
  maxRounds: z.number().int().min(1).max(3).optional(),
});

const QuillBodySchema = z.object({
  instruction: z.string().min(5).max(500),
});

export function createAdminRedTeamRoutes(
  injectedRepo?: TenantRepository,
  customFetch?: typeof fetch
) {
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
        return c.json({ error: { message: "Invalid API key", code: "unauthorized" } }, 401);
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

  // Trigger Imp Siege Mode — strictly restricted to sandbox tenants!
  router.post("/siege", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }

    const repo = c.get("repo");
    const tenant = await repo.getTenantById(auth.tenantId);
    if (!tenant?.isSandbox) {
      return c.json(
        {
          error: {
            message:
              "Imp Red-Team Siege Mode is strictly restricted to sandbox tenants (isSandbox: true).",
            code: "sandbox_required",
          },
        },
        403
      );
    }

    let maxRounds = 2;
    try {
      const raw = await c.req.text();
      if (raw.trim()) {
        const parsed = SiegeBodySchema.safeParse(JSON.parse(raw));
        if (parsed.success && parsed.data.maxRounds) {
          maxRounds = parsed.data.maxRounds;
        }
      }
    } catch {
      // Default to 2 rounds
    }

    const activePolicy = await repo.resolveEffectivePolicy(auth.tenantId);
    const judgeKey = c.req.header(`${BRAND.headerPrefix}-Provider-Key`) ?? null;

    const report = await runRedTeamSiege({
      tenantId: auth.tenantId,
      policy: activePolicy,
      maxRounds,
      judgeApiKey: judgeKey,
      fetchImpl: customFetch,
    });

    await repo.appendAuditRecord({
      tenantId: auth.tenantId,
      eventType: "redteam.siege.completed",
      payload: {
        runId: report.runId,
        totalAttempts: report.totalAttempts,
        blockedAttempts: report.blockedAttempts,
        detectionRate: report.detectionRate,
      },
    });

    return c.json({ data: report });
  });

  // Trigger Quill Policy Copilot (validates YAML, diffs vs active policy, dry-runs history)
  router.post("/copilot/draft", async (c) => {
    const auth = c.get("auth");
    if (!auth.scopes.includes("admin:write")) {
      return c.json({ error: { message: "Requires admin:write scope", code: "forbidden" } }, 403);
    }

    const parsed = QuillBodySchema.safeParse(await c.req.json());
    if (!parsed.success) {
      return c.json(
        { error: { message: "Invalid instruction", details: parsed.error.flatten() } },
        400
      );
    }

    const repo = c.get("repo");
    const currentPolicy = await repo.resolveEffectivePolicy(auth.tenantId);
    const recentRequests = await repo.listRequests(auth.tenantId, 25);
    const apiKey = c.req.header(`${BRAND.headerPrefix}-Provider-Key`) ?? null;

    const draft = await draftPolicyWithQuill({
      instruction: parsed.data.instruction,
      currentPolicy,
      historicalPrompts: recentRequests.map((r) => ({
        promptRedacted: r.promptRedacted,
        finalAction: r.finalAction,
      })),
      apiKey,
      fetchImpl: customFetch,
    });

    return c.json({ data: draft });
  });

  return router;
}