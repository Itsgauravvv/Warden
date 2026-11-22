import { describe, expect, it, beforeEach } from "vitest";
import { BRAND } from "@warden/brand";
import { TenantRepository } from "../src/db/repository.js";
import { createGatewayApp } from "../src/index.js";
import { createFullTestDb } from "./test-db.js";

describe("Tenant Bootstrap, wrd_ Key Management & AES-256-GCM Provider Vault", () => {
  let repo: TenantRepository;

  beforeEach(async () => {
    const setup = await createFullTestDb();
    repo = new TenantRepository(setup.db);
  });

  it("bootstraps a tenant, issues/lists/revokes wrd_ keys, and never leaks hashes", async () => {
    const app = createGatewayApp({ repo, bootstrapSecret: "local-test-secret" });

    // Rejected without bootstrap secret when configured
    const unauthRes = await app.request("/bootstrap/tenant", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Gaurav AI Lab" }),
    });
    expect(unauthRes.status).toBe(401);

    // Succeeds with secret
    const bootRes = await app.request("/bootstrap/tenant", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Warden-Bootstrap-Secret": "local-test-secret",
      },
      body: JSON.stringify({ name: "Gaurav AI Lab", isSandbox: true }),
    });
    expect(bootRes.status).toBe(201);
    const bootJson = (await bootRes.json()) as {
      data: { tenantId: string; apiKey: string; keyId: string };
    };
    const expectedSandboxPrefix = BRAND.apiKeyPrefix.replace("_live_", "_test_");
    expect(bootJson.data.apiKey.startsWith(expectedSandboxPrefix)).toBe(true);

    // Create a second scoped proxy key
    const createRes = await app.request("/admin/v1/vault/keys", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${bootJson.data.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: "Backend Worker", scopes: ["proxy:write"] }),
    });
    expect(createRes.status).toBe(201);
    const createdKey = (await createRes.json()) as { data: { id: string; rawKey: string } };

    // List keys — must not contain rawKey or keyHash
    const listRes = await app.request("/admin/v1/vault/keys", {
      headers: { Authorization: `Bearer ${bootJson.data.apiKey}` },
    });
    expect(listRes.status).toBe(200);
    const listText = await listRes.text();
    expect(listText).toContain("Backend Worker");
    expect(listText).not.toContain(createdKey.data.rawKey);
    expect(listText).not.toContain("keyHash");

    // Revoke the second key
    const revRes = await app.request(`/admin/v1/vault/keys/${createdKey.data.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${bootJson.data.apiKey}` },
    });
    expect(revRes.status).toBe(200);
  });

  it("encrypts a Gemini key in D1 vault and uses it automatically on /v1/chat/completions", async () => {
    let forwardedAuthHeader = "";
    const mockGeminiFetch: typeof fetch = async (_input, init) => {
      const headers = new Headers(init?.headers);
      forwardedAuthHeader = headers.get("Authorization") ?? "";
      return new Response(
        JSON.stringify({
          id: "chatcmpl_vault",
          object: "chat.completion",
          choices: [{ index: 0, message: { role: "assistant", content: "Hello from Gemini!" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    const app = createGatewayApp({ repo, customFetch: mockGeminiFetch });

    const bootRes = await app.request("/bootstrap/tenant", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Vault Org" }),
    });
    const { apiKey } = ((await bootRes.json()) as { data: { apiKey: string } }).data;

    // Save Gemini API key into AES-256-GCM vault
    const saveCredRes = await app.request("/admin/v1/vault/credentials", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ provider: "gemini", apiKey: "AIzaSyVaultTestKey12345" }),
    });
    expect(saveCredRes.status).toBe(201);

    // Listing credentials must NEVER return the plaintext key
    const listCredRes = await app.request("/admin/v1/vault/credentials", {
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    const listCredText = await listCredRes.text();
    expect(listCredText).toContain("gemini");
    expect(listCredText).not.toContain("AIzaSyVaultTestKey12345");

    // Proxy chat completion WITHOUT X-Warden-Provider-Key header — resolves from D1 vault!
    const chatRes = await app.request("/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "X-Warden-Provider": "gemini",
      },
      body: JSON.stringify({
        model: "gemini-3.5-flash-lite",
        messages: [{ role: "user", content: "Say hello!" }],
      }),
    });
    expect(chatRes.status).toBe(200);
    expect(forwardedAuthHeader).toBe("Bearer AIzaSyVaultTestKey12345");
  });
});