import { z } from "zod";
import { validateSafeUpstreamUrl } from "./ssrf-guard.js";

export const ProviderNameSchema = z.enum([
  "gemini",
  "groq",
  "openrouter",
  "workers_ai",
  "openai_compatible",
]);

export type ProviderName = z.infer<typeof ProviderNameSchema>;

export const ChatMessageSchema = z.object({
  role: z.enum(["system", "user", "assistant", "tool"]),
  content: z.union([z.string(), z.null()]).optional(),
  name: z.string().optional(),
  tool_call_id: z.string().optional(),
  tool_calls: z
    .array(
      z.object({
        id: z.string(),
        type: z.literal("function"),
        function: z.object({
          name: z.string(),
          arguments: z.string(),
        }),
      })
    )
    .optional(),
});

export const ChatCompletionRequestSchema = z
  .object({
    model: z.string().default("gemini-3.5-flash-lite"),
    messages: z.array(ChatMessageSchema).min(1),
    stream: z.boolean().optional().default(false),
    temperature: z.number().min(0).max(2).optional(),
    max_tokens: z.number().int().positive().optional(),
    tools: z.array(z.record(z.unknown())).optional(),
    tool_choice: z.unknown().optional(),
  })
  .passthrough();

export type ChatCompletionRequest = z.infer<typeof ChatCompletionRequestSchema>;

export const PROVIDER_BASE_URLS: Record<Exclude<ProviderName, "openai_compatible" | "workers_ai">, string> = {
  gemini: "https://generativelanguage.googleapis.com/v1beta/openai",
  groq: "https://api.groq.com/openai/v1",
  openrouter: "https://openrouter.ai/api/v1",
};

export const DEFAULT_MODELS: Record<ProviderName, { id: string; provider: ProviderName }[]> = {
  gemini: [
    { id: "gemini-3.5-flash-lite", provider: "gemini" },
    { id: "gemini-2.5-pro", provider: "gemini" },
    { id: "gemini-2.0-flash", provider: "gemini" },
  ],
  groq: [
    { id: "llama-3.3-70b-versatile", provider: "groq" },
    { id: "llama-3.1-8b-instant", provider: "groq" },
  ],
  openrouter: [{ id: "google/gemini-3.5-flash-lite", provider: "openrouter" }],
  workers_ai: [{ id: "@cf/meta/llama-3.1-8b-instruct", provider: "workers_ai" }],
  openai_compatible: [{ id: "custom-model", provider: "openai_compatible" }],
};

export interface UpstreamCallOptions {
  provider: ProviderName;
  apiKey: string;
  baseUrl?: string | null;
  body: ChatCompletionRequest;
  fetchImpl?: typeof fetch;
}

/**
 * Resolves the safe HTTPS endpoint for the selected provider (defaults to Gemini).
 */
export function resolveProviderEndpoint(provider: ProviderName, customBaseUrl?: string | null): string {
  if (provider === "openai_compatible") {
    if (!customBaseUrl) {
      throw new Error("Custom baseUrl is required for openai_compatible provider");
    }
    const safeUrl = validateSafeUpstreamUrl(customBaseUrl);
    return `${safeUrl.origin}${safeUrl.pathname.replace(/\/+$/, "")}/chat/completions`;
  }

  if (provider === "workers_ai") {
    if (!customBaseUrl) {
      throw new Error("Cloudflare account base URL required for workers_ai REST adapter");
    }
    const safeUrl = validateSafeUpstreamUrl(customBaseUrl);
    return `${safeUrl.origin}${safeUrl.pathname.replace(/\/+$/, "")}/chat/completions`;
  }

  const base = PROVIDER_BASE_URLS[provider];
  return `${base}/chat/completions`;
}

/**
 * Calls the upstream LLM (Gemini by default) and returns either a parsed JSON response
 * or a raw SSE ReadableStream when stream === true.
 */
export async function callUpstreamProvider(options: UpstreamCallOptions): Promise<Response> {
  const fetchFn = options.fetchImpl ?? fetch;
  const endpoint = resolveProviderEndpoint(options.provider, options.baseUrl);

  const upstreamRes = await fetchFn(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${options.apiKey}`,
    },
    body: JSON.stringify(options.body),
  });

  return upstreamRes;
}