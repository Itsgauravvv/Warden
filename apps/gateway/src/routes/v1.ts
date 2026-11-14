import { Hono } from "hono";
import { BRAND } from "@warden/brand";
import { DEFAULT_POLICY } from "@warden/policy-schema";
import {
  checkCanaryLeak,
  evaluateInputPipeline,
  generateCanaryToken,
  injectCanaryIntoSystemPrompt,
  restoreRedactedValues,
} from "@warden/detectors";
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

  v1.post("/chat/completions", async (c) => {
    const startedAt = Date.now();
    const auth = c.get("auth");
    const repo = c.get("repo");

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

    const providerHeader = c.req.header(`${BRAND.headerPrefix}-Provider`) ?? "gemini";
    const providerParse = ProviderNameSchema.safeParse(providerHeader);
    if (!providerParse.success) {
      return c.json({ error: { message: `Unsupported provider: ${providerHeader}` } }, 400);
    }
    const provider: ProviderName = providerParse.data;

    const reqId = `req_${crypto.randomUUID()}`;
    const policy = DEFAULT_POLICY;

    // Run Step 3 Detection Pipeline across all input messages
    const combinedInput = parsedReq.data.messages.map((m) => m.content ?? "").join("\n");
    const evaluation = evaluateInputPipeline(combinedInput, policy);

    // Short-circuit immediately if blocked!
    if (evaluation.finalAction === "block") {
      await repo.insertRequest(auth.tenantId, {
        id: reqId,
        provider,
        model: parsedReq.data.model,
        finalAction: "block",
        promptRedacted: evaluation.sanitizedText,
        responseRedacted: `[Blocked by ${BRAND.name} Gatekeeper]`,
        latencyMs: Date.now() - startedAt,
        createdAt: Date.now(),
      });
      await repo.insertFindings(auth.tenantId, reqId, evaluation.findings);

      c.header(`${BRAND.headerPrefix}-Request-Id`, reqId);
      c.header(`${BRAND.headerPrefix}-Action`, "block");
      return c.json(
        {
          error: {
            message: `Request blocked by ${BRAND.name} security policy`,
            type: "policy_violation",
            request_id: reqId,
            findings: evaluation.findings.map((f) => ({
              id: f.id,
              detector: f.detector,
              rule_id: f.ruleId,
              owasp_category: f.owaspCategory,
              message: f.message,
            })),
          },
        },
        403
      );
    }

    // Resolve upstream key
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

    // Prepare sanitized messages (with PII redacted + canary token planted in system prompt)
    const canaryToken = generateCanaryToken();
    const outgoingMessages = parsedReq.data.messages.map((m, idx) => {
      let content = m.content ?? "";
      for (const [placeholder, original] of Object.entries(evaluation.redactionMap)) {
        content = content.split(original).join(placeholder);
      }
      if (m.role === "system" && idx === 0 && policy.detectors.canary.enabled) {
        content = injectCanaryIntoSystemPrompt(content, canaryToken);
      }
      return { ...m, content };
    });

    let upstreamRes: Response;
    try {
      upstreamRes = await callUpstreamProvider({
        provider,
        apiKey: upstreamApiKey,
        baseUrl: upstreamBaseUrl,
        body: { ...parsedReq.data, messages: outgoingMessages },
        fetchImpl: customFetch,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Upstream request failed";
      return c.json({ error: { message, type: "upstream_error" } }, 400);
    }

    if (parsedReq.data.stream && upstreamRes.body) {
      await repo.insertRequest(auth.tenantId, {
        id: reqId,
        provider,
        model: parsedReq.data.model,
        finalAction: evaluation.finalAction,
        promptRedacted: evaluation.sanitizedText,
        responseRedacted: "[streamed]",
        latencyMs: Date.now() - startedAt,
        createdAt: Date.now(),
      });
      await repo.insertFindings(auth.tenantId, reqId, evaluation.findings);

      return new Response(upstreamRes.body, {
        status: upstreamRes.status,
        headers: {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
          [`${BRAND.headerPrefix}-Request-Id`]: reqId,
          [`${BRAND.headerPrefix}-Provider`]: provider,
          [`${BRAND.headerPrefix}-Action`]: evaluation.finalAction,
        },
      });
    }

    const upstreamJson = (await upstreamRes.json()) as {
      choices?: { message?: { role?: string; content?: string } }[];
      usage?: { prompt_tokens?: number; completion_tokens?: number };
    };

    let assistantText = upstreamJson.choices?.[0]?.message?.content ?? "";

    // Check if the model leaked the planted Canary token
    if (policy.detectors.canary.enabled) {
      const canaryFinding = checkCanaryLeak({
        responseText: assistantText,
        canaryToken,
        action: policy.detectors.canary.action,
      });
      if (canaryFinding) {
        evaluation.findings.push(canaryFinding);
        await repo.insertRequest(auth.tenantId, {
          id: reqId,
          provider,
          model: parsedReq.data.model,
          finalAction: "block",
          promptRedacted: evaluation.sanitizedText,
          responseRedacted: "[Blocked: Canary Token Leaked]",
          latencyMs: Date.now() - startedAt,
          createdAt: Date.now(),
        });
        await repo.insertFindings(auth.tenantId, reqId, evaluation.findings);

        return c.json(
          {
            error: {
              message: `Response blocked by ${BRAND.name}: system prompt canary token leak detected`,
              type: "canary_leak",
              request_id: reqId,
            },
          },
          403
        );
      }
    }

    // Restore reversible PII redactions in the response if permitted
    if (policy.detectors.pii.restoreOnResponse && Object.keys(evaluation.redactionMap).length > 0) {
      assistantText = restoreRedactedValues(assistantText, evaluation.redactionMap);
      if (upstreamJson.choices?.[0]?.message) {
        upstreamJson.choices[0].message.content = assistantText;
      }
    }

    const promptTokens = upstreamJson.usage?.prompt_tokens ?? 0;
    const completionTokens = upstreamJson.usage?.completion_tokens ?? 0;

    await repo.insertRequest(auth.tenantId, {
      id: reqId,
      provider,
      model: parsedReq.data.model,
      finalAction: evaluation.finalAction,
      promptTokens,
      completionTokens,
      promptRedacted: evaluation.sanitizedText,
      responseRedacted: assistantText,
      latencyMs: Date.now() - startedAt,
      createdAt: Date.now(),
    });
    await repo.insertFindings(auth.tenantId, reqId, evaluation.findings);

    c.header(`${BRAND.headerPrefix}-Request-Id`, reqId);
    c.header(`${BRAND.headerPrefix}-Provider`, provider);
    c.header(`${BRAND.headerPrefix}-Action`, evaluation.finalAction);
    return c.json(upstreamJson, upstreamRes.status as 200);
  });

  return v1;
}