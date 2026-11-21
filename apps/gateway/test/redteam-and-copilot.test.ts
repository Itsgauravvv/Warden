import { describe, expect, it, beforeEach } from "vitest";
import { TenantRepository } from "../src/db/repository.js";
import { createGatewayApp } from "../src/index.js";
import { createFullTestDb } from "./test-db.js";

describe("Step 14: Imp Red-Team Siege Mode & Quill Policy Copilot", () => {
  let repo: TenantRepository;
  let prodKey: string;
  let sandboxKey: string;

  beforeEach(async () => {
    const setup = await createFullTestDb();
    repo = new TenantRepository(setup.db);

    await repo.createTenant({ id: "t_prod", name: "Production Org", slug: "prod", isSandbox: false });
    await repo.createTenant({ id: "t_sandbox", name: "Siege Sandbox", slug: "sandbox", isSandbox: true });

    prodKey = (
      await repo.createApiKey({
        id: "k_prod",
        tenantId: "t_prod",
        name: "Prod Admin",
        scopes: ["proxy:write", "admin:read", "admin:write"],
      })
    ).rawKey;

    sandboxKey = (
      await repo.createApiKey({
        id: "k_sand",
        tenantId: "t_sandbox",
        name: "Sandbox Admin",
        scopes: ["proxy:write", "admin:read", "admin:write"],
        isSandbox: true,
      })
    ).rawKey;
  });

  it("blocks Imp Siege Mode on non-sandbox production tenants (403 sandbox_required)", async () => {
    const app = createGatewayApp({ repo });
    const res = await app.request("/admin/v1/redteam/siege", {
      method: "POST",
      headers: { Authorization: `Bearer ${prodKey}` },
    });
    expect(res.status).toBe(403);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe("sandbox_required");
  });

  it("runs multi-round mutated Siege Mode in sandbox, detects leaks on weak policy, and validates the suggested patch", async () => {
    // Save an intentionally weak policy (injection + secrets disabled)
    const weakYaml = `
version: "1.0"
name: "weak-sandbox-policy"
mode: "enforce"
detectors:
  injection:
    enabled: false
    action: "block"
  secrets:
    enabled: false
    action: "block"
toolFirewall:
  enabled: false
  defaultAction: "allow"
`;
    await repo.savePolicyVersion({
      tenantId: "t_sandbox",
      policyId: "pol_sand",
      name: "Sandbox Policy",
      rawYamlOrJson: weakYaml,
    });

    const app = createGatewayApp({ repo });

    // Round 1 Siege against weak policy -> attacks leak, Imp suggests a hardened patch
    const weakRes = await app.request("/admin/v1/redteam/siege", {
      method: "POST",
      headers: { Authorization: `Bearer ${sandboxKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ maxRounds: 2 }),
    });
    expect(weakRes.status).toBe(200);
    const weakReport = (await weakRes.json()) as {
      data: { leakedAttempts: number; detectionRate: number; suggestedPatchYaml: string | null };
    };
    expect(weakReport.data.leakedAttempts).toBeGreaterThan(0);
    expect(weakReport.data.suggestedPatchYaml).toBeTruthy();

    // Apply the suggested hardened patch and re-run Siege Mode -> 100% detection across mutated rounds!
    await repo.savePolicyVersion({
      tenantId: "t_sandbox",
      policyId: "pol_sand",
      name: "Hardened Sandbox Policy",
      rawYamlOrJson: weakReport.data.suggestedPatchYaml!,
    });

    const hardenedRes = await app.request("/admin/v1/redteam/siege", {
      method: "POST",
      headers: { Authorization: `Bearer ${sandboxKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ maxRounds: 2 }),
    });
    expect(hardenedRes.status).toBe(200);
    const hardenedReport = (await hardenedRes.json()) as {
      data: { totalAttempts: number; blockedAttempts: number; leakedAttempts: number; detectionRate: number };
    };
    expect(hardenedReport.data.totalAttempts).toBe(12); // 6 attacks x 2 rounds (Round 1 + Mutated Round 2)
    expect(hardenedReport.data.leakedAttempts).toBe(0);
    expect(hardenedReport.data.detectionRate).toBe(1);
  });

  it("drafts schema-valid YAML with Quill Copilot, returns structural diff, and dry-runs historical traffic", async () => {
    // Seed 1 historical PII request that was previously redacted
    await repo.insertRequest("t_sandbox", {
      id: "req_hist_pii",
      provider: "gemini",
      model: "gemini-2.5-flash",
      finalAction: "redact",
      promptRedacted: "Please email billing@acme-corp.org with my invoice.",
      responseRedacted: "Done.",
      createdAt: Date.now(),
    });

    const app = createGatewayApp({ repo });
    const res = await app.request("/admin/v1/redteam/copilot/draft", {
      method: "POST",
      headers: { Authorization: `Bearer ${sandboxKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        instruction: "Block all PII, enable semantic cache, and require approval for send_email",
      }),
    });

    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      data: {
        yaml: string;
        changes: { path: string; after: unknown }[];
        dryRun: { totalEvaluated: number; newlyBlockedCount: number };
      };
    };

    expect(json.data.yaml).toContain("action: block");
    expect(json.data.yaml).toContain("send_email");
    expect(json.data.changes.some((c) => c.path === "detectors.pii.action" && c.after === "block")).toBe(true);
    expect(json.data.dryRun.totalEvaluated).toBe(1);
    expect(json.data.dryRun.newlyBlockedCount).toBe(1);
  });
});