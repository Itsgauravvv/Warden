import { describe, expect, it, beforeEach } from "vitest";
import type { Client } from "@libsql/client";
import { TenantRepository } from "../src/db/repository.js";
import { createGatewayApp } from "../src/index.js";
import { hmacSha256Hex } from "../src/crypto/hash-chain.js";
import { dispatchTenantWebhooks } from "../src/queues/webhook-dispatcher.js";
import { createFullTestDb } from "./test-db.js";

describe("Step 6: Tamper-Evident SHA-256 Audit Chain (Ledger), Batch Sealing & Signed Webhooks", () => {
  let client: Client;
  let repo: TenantRepository;
  let adminKey: string;

  beforeEach(async () => {
    const setup = await createFullTestDb();
    client = setup.client;
    repo = new TenantRepository(setup.db, "warden-master-secret-for-audit-and-hmac!");

    await repo.createTenant({ id: "t_audit", name: "Audit Fortress", slug: "audit-fortress" });
    const issued = await repo.createApiKey({
      id: "k_audit",
      tenantId: "t_audit",
      name: "Audit Admin Key",
      scopes: ["proxy:write", "admin:read", "admin:write"],
    });
    adminKey = issued.rawKey;
  });

  it("verifies an intact SHA-256 audit chain and pinpoints the exact first corrupted record on tampering", async () => {
    await repo.appendAuditRecord({
      tenantId: "t_audit",
      requestId: "req_1",
      eventType: "proxy.request.completed",
      payload: { requestId: "req_1", action: "allow", promptRedacted: "Hello 1" },
    });
    const rec2 = await repo.appendAuditRecord({
      tenantId: "t_audit",
      requestId: "req_2",
      eventType: "proxy.request.blocked",
      payload: { requestId: "req_2", action: "block", promptRedacted: "Ignore instructions" },
    });
    await repo.appendAuditRecord({
      tenantId: "t_audit",
      requestId: "req_3",
      eventType: "proxy.request.completed",
      payload: { requestId: "req_3", action: " redact", promptRedacted: "[REDACTED_EMAIL_1]" },
    });

    const app = createGatewayApp(repo);

    // 1. Verify intact chain (valid === true)
    const verifyOkRes = await app.request("/admin/v1/audit/verify", {
      headers: { Authorization: `Bearer ${adminKey}` },
    });
    expect(verifyOkRes.status).toBe(200);
    const okJson = (await verifyOkRes.json()) as {
      data: { valid: boolean; totalChecked: number; firstCorruptedSeq: number | null };
    };
    expect(okJson.data.valid).toBe(true);
    expect(okJson.data.totalChecked).toBe(3);
    expect(okJson.data.firstCorruptedSeq).toBeNull();

    // 2. Seal batch and verify signature & R2 key
    const sealRes = await app.request("/admin/v1/audit/seal", {
      method: "POST",
      headers: { Authorization: `Bearer ${adminKey}` },
    });
    expect(sealRes.status).toBe(201);
    const sealJson = (await sealRes.json()) as {
      data: { firstSeq: number; lastSeq: number; signature: string; r2ArchiveKey: string };
    };
    expect(sealJson.data.firstSeq).toBe(1);
    expect(sealJson.data.lastSeq).toBe(3);
    expect(sealJson.data.r2ArchiveKey).toContain("audit-archives/t_audit/");

    // 3. Simulate an attacker tampering with Record #2 directly in SQLite!
    await client.execute({
      sql: "UPDATE audit_records SET canonical_json = ? WHERE id = ?",
      args: ['{"action":"allow","requestId":"req_2","tampered":true}', rec2.id],
    });

    // 4. Verify chain again -> Ledger catches tampering and pinpoints seq 2!
    const verifyCorruptRes = await app.request("/admin/v1/audit/verify", {
      headers: { Authorization: `Bearer ${adminKey}` },
    });
    const corruptJson = (await verifyCorruptRes.json()) as {
      data: { valid: boolean; firstCorruptedSeq: number; reason: string };
    };
    expect(corruptJson.data.valid).toBe(false);
    expect(corruptJson.data.firstCorruptedSeq).toBe(2);
    expect(corruptJson.data.reason).toContain("seq 2");
  });

  it("delivers HMAC-signed webhooks and moves failing endpoints to DLQ after retries", async () => {
    const signingSecret = "whsec_test_secret_1234567890";
    await repo.createWebhook({
      id: "wh_ok",
      tenantId: "t_audit",
      url: "https://hooks.example.com/warden-ok",
      signingSecret,
      events: ["request.blocked"],
    });
    await repo.createWebhook({
      id: "wh_fail",
      tenantId: "t_audit",
      url: "https://hooks.example.com/warden-500",
      signingSecret,
      events: ["request.blocked"],
    });

    let capturedSig = "";
    let capturedBody = "";
    let failAttempts = 0;

    const mockWebhookFetch: typeof fetch = async (input, init) => {
      const url = String(input);
      if (url.endsWith("/warden-ok")) {
        capturedSig = String((init?.headers as Record<string, string>)?.["X-Warden-Signature-256"]);
        capturedBody = String(init?.body);
        return new Response("OK", { status: 200 });
      }
      failAttempts += 1;
      return new Response("Internal Server Error", { status: 500 });
    };

    const results = await dispatchTenantWebhooks({
      repo,
      job: {
        idempotencyKey: "evt_block_001",
        tenantId: "t_audit",
        eventType: "request.blocked",
        timestamp: 1735689600000,
        data: { requestId: "req_99", ruleId: "injection.ignore_previous" },
      },
      maxAttempts: 3,
      baseDelayMs: 1,
      fetchImpl: mockWebhookFetch,
    });

    const okResult = results.find((r) => r.webhookId === "wh_ok");
    const dlqResult = results.find((r) => r.webhookId === "wh_fail");

    expect(okResult?.status).toBe("delivered");
    expect(okResult?.attempts).toBe(1);

    // Verify HMAC-SHA256 signature matches payload
    const expectedHmac = await hmacSha256Hex(signingSecret, capturedBody);
    expect(capturedSig).toBe(`sha256=${expectedHmac}`);

    // Verify failing endpoint retried 3 times and moved to DLQ
    expect(dlqResult?.status).toBe("dlq");
    expect(dlqResult?.attempts).toBe(3);
    expect(failAttempts).toBe(3);
  });
});