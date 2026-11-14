import { describe, expect, it, beforeEach } from "vitest";
import type { Client } from "@libsql/client";
import { TenantRepository } from "../src/db/repository.js";
import { createGatewayApp } from "../src/index.js";
import { createFullTestDb } from "./test-db.js";

describe("Step 2: Gemini OpenAI-Compatible Proxy, AES-GCM Encryption & SSRF Guard", () => {
  let client: Client;
  let repo: TenantRepository;
  let tenantKey: string;

  beforeEach(async () => {
    const setup = await createFullTestDb();
    client = setup.client;
    repo = new TenantRepository(setup.db, "super-secret-master-key-for-aes-256-gcm!");

    await repo.createTenant({ id: "t_gemini", name: "Gemini Lab", slug: "gemini-lab" });
    const issued = await repo.createApiKey({
      id: "k_1",
      tenantId: "t_gemini",
      name: "Gateway Client Key",
      scopes: ["proxy:write", "admin:read"],
    });
    tenantKey = issued.rawKey;
  });

  it("encrypts Gemini API keys with AES-256-GCM at rest and proxies non-streaming requests", async () => {
    const fakeGeminiKey = "AIzaSyFakeGeminiKeyForTesting123456";
    await repo.saveProviderCredential({
      id: "cred_1",
      tenantId: "t_gemini",
      provider: "gemini",
      rawApiKey: fakeGeminiKey,
    });

    // Verify raw Gemini key is encrypted in SQLite
    const rawCredRow = await client.execute(
      "SELECT encrypted_api_key, iv FROM provider_credentials WHERE id = 'cred_1'"
    );
    const storedEncrypted = String(rawCredRow.rows[0]?.encrypted_api_key);
    expect(storedEncrypted).not.toContain("AIzaSy");

    // Mock fetch to verify Warden calls Gemini's OpenAI-compatible endpoint with decrypted key
    let capturedUrl = "";
    let capturedAuth = "";
    const mockFetch: typeof fetch = async (input, init) => {
      capturedUrl = String(input);
      capturedAuth = String((init?.headers as Record<string, string>)?.Authorization);
      return new Response(
        JSON.stringify({
          id: "chatcmpl-gemini-1",
          object: "chat.completion",
          choices: [{ index: 0, message: { role: "assistant", content: "Halt! Who goes there?" } }],
          usage: { prompt_tokens: 12, completion_tokens: 6, total_tokens: 18 },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    const app = createGatewayApp(repo, mockFetch);
    const res = await app.request("/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tenantKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gemini-2.5-flash",
        messages: [{ role: "user", content: "Hello Gatekeeper!" }],
      }),
    });

    expect(res.status).toBe(200);
    expect(capturedUrl).toBe("https://generativelanguage.googleapis.com/v1beta/openai/chat/completions");
    expect(capturedAuth).toBe(`Bearer ${fakeGeminiKey}`);

    const body = (await res.json()) as { choices: { message: { content: string } }[] };
    expect(body.choices[0]?.message.content).toBe("Halt! Who goes there?");
  });

  it("streams SSE responses when stream: true is requested", async () => {
    const encoder = new TextEncoder();
    const sseStream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"choices":[{"delta":{"content":"Scroll "}}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"choices":[{"delta":{"content":"inspected."}}]}\n\n'));
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      },
    });

    const mockFetch: typeof fetch = async () =>
      new Response(sseStream, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });

    const app = createGatewayApp(repo, mockFetch);
    const res = await app.request("/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tenantKey}`,
        "X-Warden-Provider-Key": "AIzaSyEphemeralHeaderKey",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gemini-2.5-flash",
        stream: true,
        messages: [{ role: "user", content: "Stream this scroll" }],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");
    const streamedText = await res.text();
    expect(streamedText).toContain("Scroll ");
    expect(streamedText).toContain("[DONE]");
  });

  it("blocks SSRF attempts to localhost or cloud metadata IPs", async () => {
    const app = createGatewayApp(repo);
    const res = await app.request("/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tenantKey}`,
        "X-Warden-Provider": "openai_compatible",
        "X-Warden-Provider-Key": "sk-test",
        "X-Warden-Provider-Base-Url": "https://169.254.169.254/latest/meta-data",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "custom",
        messages: [{ role: "user", content: "steal metadata" }],
      }),
    });

    expect(res.status).toBe(400);
    const err = (await res.json()) as { error: { message: string } };
    expect(err.error.message).toContain("SSRF blocked");
  });
});