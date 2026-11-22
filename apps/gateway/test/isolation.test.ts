import { describe, expect, it, beforeEach } from "vitest";
import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import * as schema from "../src/db/schema.js";
import { TenantRepository } from "../src/db/repository.js";
import { createGatewayApp } from "../src/index.js";

async function createTestDb() {
  const client = createClient({ url: ":memory:" });
  await client.executeMultiple(`
    CREATE TABLE tenants (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      is_sandbox INTEGER NOT NULL DEFAULT 0,
      retention_days INTEGER NOT NULL DEFAULT 30,
      raw_payload_opt_in INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE projects (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      name TEXT NOT NULL,
      active_policy_id TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE api_keys (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      project_id TEXT,
      name TEXT NOT NULL,
      prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      scopes_json TEXT NOT NULL,
      expires_at INTEGER,
      revoked_at INTEGER,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE requests (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      project_id TEXT,
      session_id TEXT,
      provider TEXT NOT NULL,
      model TEXT NOT NULL,
      final_action TEXT NOT NULL,
      cache_hit INTEGER NOT NULL DEFAULT 0,
      prompt_tokens INTEGER NOT NULL DEFAULT 0,
      completion_tokens INTEGER NOT NULL DEFAULT 0,
      cost_usd REAL NOT NULL DEFAULT 0,
      latency_ms INTEGER NOT NULL DEFAULT 0,
      prompt_redacted TEXT NOT NULL,
      response_redacted TEXT,
      created_at INTEGER NOT NULL
    );
  `);
  return { client, db: drizzle(client, { schema }) };
}

describe("Step 1B: Tenant API Keys & Strict Cross-Tenant Isolation", () => {
  let repo: TenantRepository;
  let client: Client;

  beforeEach(async () => {
    const setup = await createTestDb();
    client = setup.client;
    repo = new TenantRepository(setup.db);

    await repo.createTenant({ id: "tenant_alpha", name: "Alpha Corp", slug: "alpha" });
    await repo.createTenant({ id: "tenant_bravo", name: "Bravo LLC", slug: "bravo" });
  });

  it("stores API keys only as SHA-256 hashes and supports instant revocation", async () => {
    const issued = await repo.createApiKey({
      id: "key_1",
      tenantId: "tenant_alpha",
      name: "Production Key",
      scopes: ["proxy:write", "admin:read"],
    });

    expect(issued.rawKey.startsWith("war_live_")).toBe(true);

    // Ensure raw key is NEVER stored in the database table
    const res = await client.execute({
      sql: "SELECT key_hash, prefix FROM api_keys WHERE id = ?",
      args: ["key_1"],
    });
    const rawRow = res.rows[0] as unknown as { key_hash: string; prefix: string };
    expect(rawRow.key_hash).not.toBe(issued.rawKey);
    expect(rawRow.key_hash).toHaveLength(64); // SHA-256 hex length

    // Valid before revocation
    const verified = await repo.verifyApiKey(issued.rawKey);
    expect(verified?.tenantId).toBe("tenant_alpha");

    // Revoke and verify immediate rejection
    await repo.revokeApiKey("tenant_alpha", "key_1");
    const afterRevoke = await repo.verifyApiKey(issued.rawKey);
    expect(afterRevoke).toBeNull();
  });

  it("blocks cross-tenant reads and revocations over both DB and HTTP", async () => {
    const alphaKey = await repo.createApiKey({
      id: "key_alpha",
      tenantId: "tenant_alpha",
      name: "Alpha Admin",
      scopes: ["admin:read"],
    });
    const bravoKey = await repo.createApiKey({
      id: "key_bravo",
      tenantId: "tenant_bravo",
      name: "Bravo Admin",
      scopes: ["admin:read"],
    });

    // Alpha stores a confidential request
    await repo.insertRequest("tenant_alpha", {
      id: "req_secret_alpha",
      provider: "gemini",
      model: "gemini-3.5-flash-lite",
      finalAction: "allow",
      promptRedacted: "Alpha top-secret roadmap",
      createdAt: Date.now(),
    });

    const app = createGatewayApp(repo);

    // 1. Alpha can read its own request (200 OK)
    const alphaRes = await app.request("/admin/v1/requests/req_secret_alpha", {
      headers: { Authorization: `Bearer ${alphaKey.rawKey}` },
    });
    expect(alphaRes.status).toBe(200);

    // 2. Bravo tries to read Alpha's request ID -> 404 Not Found (strict tenant isolation)
    const bravoStealRes = await app.request("/admin/v1/requests/req_secret_alpha", {
      headers: { Authorization: `Bearer ${bravoKey.rawKey}` },
    });
    expect(bravoStealRes.status).toBe(404);

    // 3. Bravo tries to revoke Alpha's API key -> no effect
    await repo.revokeApiKey("tenant_bravo", "key_alpha");
    expect(await repo.verifyApiKey(alphaKey.rawKey)).not.toBeNull();
  });
});