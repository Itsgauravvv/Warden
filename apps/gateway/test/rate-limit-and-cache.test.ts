import { describe, expect, it, beforeEach } from "vitest";
import { TenantRepository } from "../src/db/repository.js";
import { createGatewayApp } from "../src/index.js";
import { createFullTestDb } from "./test-db.js";

describe("Step 5: Rate Limits, Budgets (Toll) & Semantic Cache Isolation (Echo)", () => {
  let repo: TenantRepository;
  let alphaKey: string;
  let bravoKey: string;

  beforeEach(async () => {
    const setup = await createFullTestDb();
    repo = new TenantRepository(setup.db);

    await repo.createTenant({ id: "t_alpha", name: "Alpha", slug: "alpha" });
    await repo.createTenant({ id: "t_bravo", name: "Bravo", slug: "bravo" });

    const k1 = await repo.createApiKey({
      id: "k_alpha",
      tenantId: "t_alpha",
      name: "Alpha Key",
      scopes: ["proxy:write", "admin:read", "admin:write"],
    });
    const k2 = await repo.createApiKey({
      id: "k_bravo",
      tenantId: "t_bravo",
      name: "Bravo Key",
      scopes: ["proxy:write", "admin:read", "admin:write"],
    });

    alphaKey = k1.rawKey;
    bravoKey = k2.rawKey;
  });

  it("enforces RPM token-bucket limits and returns 429 with Retry-After", async () => {
    const mockFetch: typeof fetch = async () =>
      new Response(
        JSON.stringify({
          choices: [{ message: { role: "assistant", content: "Allowed response" } }],
          usage: { prompt_tokens: 10, completion_tokens: 5 },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );

    const app = createGatewayApp(repo, mockFetch);

    // Set Alpha's RPM limit to 2 requests per minute
    const budgetRes = await app.request("/admin/v1/budgets", {
      method: "PUT",
      headers: { Authorization: `Bearer ${alphaKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ rpmLimit: 2 }),
    });
    expect(budgetRes.status).toBe(200);

    const reqInit = {
      method: "POST",
      headers: {
        Authorization: `Bearer ${alphaKey}`,
        "X-Warden-Provider-Key": "AIzaSyFakeKey",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gemini-3.5-flash-lite",
        messages: [{ role: "user", content: "Ping the gatehouse" }],
      }),
    };

    // Request 1 & 2 succeed (200 OK)
    expect((await app.request("/v1/chat/completions", reqInit)).status).toBe(200);
    expect((await app.request("/v1/chat/completions", reqInit)).status).toBe(200);

    // Request 3 trips the RPM bucket -> 429 Too Many Requests with Retry-After header
    const res3 = await app.request("/v1/chat/completions", reqInit);
    expect(res3.status).toBe(429);
    expect(Number(res3.headers.get("Retry-After"))).toBeGreaterThanOrEqual(1);
    const body3 = (await res3.json()) as { error: { code: string } };
    expect(body3.error.code).toBe("rpm_exceeded");
  });

  it("serves semantic cache hits within a tenant and NEVER crosses tenant or policy boundaries", async () => {
    const cacheEnabledYaml = `
version: "1.0"
name: "cache-enabled-policy"
mode: "enforce"
detectors: {}
semanticCache:
  enabled: true
  similarityThreshold: 0.90
  ttlSeconds: 3600
`;
    await repo.savePolicyVersion({
      tenantId: "t_alpha",
      policyId: "pol_alpha",
      name: "Alpha Cache Policy",
      rawYamlOrJson: cacheEnabledYaml,
    });
    await repo.savePolicyVersion({
      tenantId: "t_bravo",
      policyId: "pol_bravo",
      name: "Bravo Cache Policy",
      rawYamlOrJson: cacheEnabledYaml,
    });

    let upstreamCallCount = 0;
    const mockFetch: typeof fetch = async () => {
      upstreamCallCount += 1;
      return new Response(
        JSON.stringify({
          choices: [{ message: { role: "assistant", content: `Upstream answer #${upstreamCallCount}` } }],
          usage: { prompt_tokens: 100, completion_tokens: 50 },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    const app = createGatewayApp(repo, mockFetch);

    // 1. Alpha sends first request -> Cache MISS (calls upstream #1)
    const alphaMiss = await app.request("/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${alphaKey}`,
        "X-Warden-Provider-Key": "AIzaSyFakeKey",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gemini-3.5-flash-lite",
        messages: [{ role: "user", content: "Explain how hash-chained audit logs work in detail." }],
      }),
    });
    expect(alphaMiss.status).toBe(200);
    expect(alphaMiss.headers.get("X-Warden-Cache")).toBe("MISS");
    expect(upstreamCallCount).toBe(1);

    // 2. Alpha sends near-identical request -> Cache HIT! (upstreamCallCount stays 1)
    const alphaHit = await app.request("/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${alphaKey}`,
        "X-Warden-Provider-Key": "AIzaSyFakeKey",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gemini-3.5-flash-lite",
        messages: [{ role: "user", content: "Explain how hash-chained audit logs work in detail!" }],
      }),
    });
    expect(alphaHit.status).toBe(200);
    expect(alphaHit.headers.get("X-Warden-Cache")).toBe("HIT");
    expect(upstreamCallCount).toBe(1);

    // Verify Alpha's tokensSaved increased by 150 tokens
    const statsRes = await app.request("/admin/v1/cache/stats", {
      headers: { Authorization: `Bearer ${alphaKey}` },
    });
    const statsJson = (await statsRes.json()) as { data: { hits: number; tokensSaved: number } };
    expect(statsJson.data.hits).toBe(1);
    expect(statsJson.data.tokensSaved).toBe(150);

    // 3. Bravo sends the EXACT same prompt -> MUST be Cache MISS (never cross tenant boundaries!)
    const bravoRes = await app.request("/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${bravoKey}`,
        "X-Warden-Provider-Key": "AIzaSyFakeKey",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gemini-3.5-flash-lite",
        messages: [{ role: "user", content: "Explain how hash-chained audit logs work in detail." }],
      }),
    });
    expect(bravoRes.status).toBe(200);
    expect(bravoRes.headers.get("X-Warden-Cache")).toBe("MISS");
    expect(upstreamCallCount).toBe(2);
  });
});