import { BRAND } from "@warden/brand";
import { checkCanaryLeak, restoreRedactedValues, scanSecrets } from "@warden/detectors";
import type { Finding, PolicyDocument } from "@warden/policy-schema";

export interface StreamScanOptions {
  policy: PolicyDocument;
  canaryToken: string;
  redactionMap: Record<string, string>;
  onViolation?: (finding: Finding) => void | Promise<void>;
}

/**
 * Wraps an upstream OpenAI/Gemini SSE ReadableStream in a sliding-window scanner.
 * - Maintains a 512-char rolling buffer across SSE delta chunks so secrets/canaries split
 *   across chunk boundaries are still caught.
 * - Restores reversible PII placeholders when allowed by policy.
 * - Cuts the stream cleanly and emits a safe refusal SSE chunk + [DONE] on violation.
 */
export function createScannedSseStream(
  upstreamBody: ReadableStream<Uint8Array>,
  options: StreamScanOptions
): ReadableStream<Uint8Array> {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  let sseLineBuffer = "";
  let slidingTextWindow = "";
  let streamCut = false;

  return new ReadableStream<Uint8Array>({
    async start(controller) {
      const reader = upstreamBody.getReader();

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done || streamCut) break;

          sseLineBuffer += decoder.decode(value, { stream: true });
          const events = sseLineBuffer.split("\n\n");
          // Keep the last potentially incomplete SSE frame in the buffer
          sseLineBuffer = events.pop() ?? "";

          for (const rawEvent of events) {
            const trimmed = rawEvent.trim();
            if (!trimmed) continue;

            if (trimmed === "data: [DONE]") {
              controller.enqueue(encoder.encode("data: [DONE]\n\n"));
              continue;
            }

            if (!trimmed.startsWith("data:")) {
              controller.enqueue(encoder.encode(`${rawEvent}\n\n`));
              continue;
            }

            const jsonStr = trimmed.slice("data:".length).trim();
            let parsedChunk: {
              choices?: {
                index?: number;
                delta?: { content?: string };
                finish_reason?: string | null;
              }[];
            };

            try {
              parsedChunk = JSON.parse(jsonStr);
            } catch {
              controller.enqueue(encoder.encode(`${rawEvent}\n\n`));
              continue;
            }

            let deltaContent = parsedChunk.choices?.[0]?.delta?.content ?? "";
            if (deltaContent) {
              // Restore reversible PII redactions if enabled
              if (
                options.policy.detectors.pii.restoreOnResponse &&
                Object.keys(options.redactionMap).length > 0
              ) {
                deltaContent = restoreRedactedValues(deltaContent, options.redactionMap);
                if (parsedChunk.choices?.[0]?.delta) {
                  parsedChunk.choices[0].delta.content = deltaContent;
                }
              }

              // Update rolling 512-char sliding window across chunks
              slidingTextWindow = (slidingTextWindow + deltaContent).slice(-512);

              // 1. Check Canary token leak across sliding window
              if (options.policy.detectors.canary.enabled) {
                const canaryFinding = checkCanaryLeak({
                  responseText: slidingTextWindow,
                  canaryToken: options.canaryToken,
                  action: options.policy.detectors.canary.action,
                });
                if (canaryFinding && canaryFinding.action === "block") {
                  streamCut = true;
                  await options.onViolation?.(canaryFinding);
                  const abortChunk = {
                    choices: [
                      {
                        index: 0,
                        delta: {
                          content: `\n[Stream terminated by ${BRAND.name}: system prompt canary leak detected]`,
                        },
                        finish_reason: "content_filter",
                      },
                    ],
                  };
                  controller.enqueue(encoder.encode(`data: ${JSON.stringify(abortChunk)}\n\n`));
                  controller.enqueue(encoder.encode("data: [DONE]\n\n"));
                  await reader.cancel();
                  break;
                }
              }

              // 2. Check Secret leakage across sliding window
              if (options.policy.detectors.secrets.enabled) {
                const secretFindings = scanSecrets({
                  text: slidingTextWindow,
                  action: options.policy.detectors.secrets.action,
                  entropyThreshold: options.policy.detectors.secrets.entropyThreshold,
                  direction: "output",
                });
                const blockingSecret = secretFindings.find((f) => f.action === "block");
                if (blockingSecret) {
                  streamCut = true;
                  await options.onViolation?.(blockingSecret);
                  const abortChunk = {
                    choices: [
                      {
                        index: 0,
                        delta: {
                          content: `\n[Stream terminated by ${BRAND.name}: secret leak detected (${blockingSecret.ruleId})]`,
                        },
                        finish_reason: "content_filter",
                      },
                    ],
                  };
                  controller.enqueue(encoder.encode(`data: ${JSON.stringify(abortChunk)}\n\n`));
                  controller.enqueue(encoder.encode("data: [DONE]\n\n"));
                  await reader.cancel();
                  break;
                }
              }
            }

            controller.enqueue(encoder.encode(`data: ${JSON.stringify(parsedChunk)}\n\n`));
          }
        }
      } finally {
        controller.close();
      }
    },
  });
}