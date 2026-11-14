import { Hono } from "hono";
import { BRAND } from "@warden/brand";
import type { AppVariables } from "../index.js";
import {
  callUpstreamProvider,
  ChatCompletionRequestSchema,
  DEFAULT_MODELS,
  ProviderNameSchema,
  type ProviderName,
} from "../adapters/provider.js";

export function createV1Routes(customFetch?: typeof fetch) {
  const v1 = new Hono<{ Variables: AppVariables }>();

  // Authenticate all /v1/* calls with a Warden tenant API key
  v1.use("*", async (c, next) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json(
        { error: { message: `Missing ${BRAND.name} Bearer API key`, type: "auth_error" } },
        401
      );
    }

    const rawKey = authHeader.slice("Bearer ".length).trim();
    const verified = await c.get("repo").verifyApiKey(rawKey);
    if (!verified || !verified.scopes.includes("proxy:write")) {
      return c.json(
        { error: { message: "Invalid API key or missing proxy:write scope", type: "auth_error" } },
        401
      );
    }

    c.set("auth", {
      tenantId: verified.tenantId,
      keyId: verified.keyId,
      projectId: verified.projectId,
      scopes: verified.scopes,
    });
    await next();
  });

  // GET /v1/models (OpenAI-compatible model list, Gemini listed first)
  v1.get("/models", (c) => {
    const models = Object.values(DEFAULT_MODELS)
      .flat()
      .map((m) => ({
        id: m.id,
        object: "model",
        created: 1735689600,
        owned_by: m.provider,
      }));

    return c.json({ object: "list", data: models });
  });

  // POST /v1/chat/completions (Streaming & Non-Streaming, defaults to Gemini)
  v1.post("/chat/completions", async (c) => {
    const startedAt = Date.now();
    const auth = c.get("auth");
    const repo = c.get("repo");

    // Size limit guard (prevent oversized-body DoS)
    const rawText = await c.req.text();
    if (rawText.length > 512_000) {
      return c.json({ error: { message: "Request body exceeds 512KB limit", type: "invalid_request_error" } }, 413);
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(rawText);
    } catch {
      return c.json({ error: { message: "Malformed JSON body", type: "invalid_request_error" } }, 400);
    }

    const parsedReq = ChatCompletionRequestSchema.safeParse(parsedJson);
    if (!parsedReq.success) {
      return c.json(
        { error: { message: "Invalid OpenAI chat request payload", details: parsedReq.error.flatten() } },
        400
      );
    }

    // Determine provider (header override or default to "gemini")
    const providerHeader = c.req.header(`${BRAND.headerPrefix}-Provider`) ?? "gemini";
    const providerParse = ProviderNameSchema.safeParse(providerHeader);
    if (!providerParse.success) {
      return c.json({ error: { message: `Unsupported provider: ${providerHeader}` } }, 400);
    }
    const provider: ProviderName = providerParse.data;

    // Resolve upstream key: either ephemeral per-request header (never stored) or encrypted tenant credential
    const headerProviderKey = c.req.header(`${BRAND.headerPrefix}-Provider-Key`);
    const headerBaseUrl = c.req.header(`${BRAND.headerPrefix}-Provider-Base-Url`);

    let upstreamApiKey = headerProviderKey ?? null;
    let upstreamBaseUrl = headerBaseUrl ?? null;

    if (!upstreamApiKey) {
      const storedCred = await repo.getDecryptedProviderCredential(auth.tenantId, provider);
      if (!storedCred) {
        return c.json(
          {
            error: {
              message: `No upstream API key configured for provider '${provider}'. Supply ${BRAND.headerPrefix}-Provider-Key or save a tenant credential.`,
              type: "configuration_error",
            },
          },
          400
        );
      }
      upstreamApiKey = storedCred.apiKey;
      upstreamBaseUrl = upstreamBaseUrl ?? storedCred.baseUrl;
    }

    let upstreamRes: Response;
    try {
      upstreamRes = await callUpstreamProvider({
        provider,
        apiKey: upstreamApiKey,
        baseUrl: upstreamBaseUrl,
        body: parsedReq.data,
        fetchImpl: customFetch,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Upstream request failed";
      return c.json({ error: { message, type: "upstream_error" } }, 400);
    }

    const reqId = `req_${crypto.randomUUID()}`;
    const promptPreview = parsedReq.data.messages.map((m) => m.content ?? "").join("\n");

    // Handle SSE Streaming passthrough
    if (parsedReq.data.stream && upstreamRes.body) {
      await repo.insertRequest(auth.tenantId, {
        id: reqId,
        provider,
        model: parsedReq.data.model,
        finalAction: "allow",
        promptRedacted: promptPreview,
        responseRedacted: "[streamed]",
        latencyMs: Date.now() - startedAt,
        createdAt: Date.now(),
      });

      return new Response(upstreamRes.body, {
        status: upstreamRes.status,
        headers: {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
          [`${BRAND.headerPrefix}-Request-Id`]: reqId,
          [`${BRAND.headerPrefix}-Provider`]: provider,
        },
      });
    }

    // Handle Non-Streaming JSON response
    const upstreamJson = (await upstreamRes.json()) as {
      choices?: { message?: { content?: string } }[];
      usage?: { prompt_tokens?: number; completion_tokens?: number };
    };

    const assistantText = upstreamJson.choices?.[0]?.message?.content ?? "";
    const promptTokens = upstreamJson.usage?.prompt_tokens ?? 0;
    const completionTokens = upstreamJson.usage?.completion_tokens ?? 0;

    await repo.insertRequest(auth.tenantId, {
      id: reqId,
      provider,
      model: parsedReq.data.model,
      finalAction: "allow",
      promptTokens,
      completionTokens,
      promptRedacted: promptPreview,
      responseRedacted: assistantText,
      latencyMs: Date.now() - startedAt,
      createdAt: Date.now(),
    });

    c.header(`${BRAND.headerPrefix}-Request-Id`, reqId);
    c.header(`${BRAND.headerPrefix}-Provider`, provider);
    return c.json(upstreamJson, upstreamRes.status as 200);
  });

  return v1;
}