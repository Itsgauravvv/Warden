import { BRAND } from "@warden/brand";
import { hmacSha256Hex } from "../crypto/hash-chain.js";
import type { TenantRepository } from "../db/repository.js";

export interface WebhookEventJob {
  idempotencyKey: string;
  tenantId: string;
  eventType: "request.blocked" | "request.flagged" | "approval.required";
  timestamp: number;
  data: Record<string, unknown>;
}

export interface WebhookDispatchResult {
  webhookId: string;
  status: "delivered" | "dlq";
  attempts: number;
  lastStatusCode: number | null;
}

/**
 * Dispatches an event to all subscribed tenant webhooks with:
 * - HMAC-SHA256 signature header (X-Warden-Signature-256)
 * - Idempotency-Key header
 * - Exponential backoff retries up to maxAttempts, then Dead-Letter Queue (status = "dlq")
 */
export async function dispatchTenantWebhooks(options: {
  repo: TenantRepository;
  job: WebhookEventJob;
  maxAttempts?: number;
  baseDelayMs?: number;
  fetchImpl?: typeof fetch;
}): Promise<WebhookDispatchResult[]> {
  const fetchFn = options.fetchImpl ?? fetch;
  const maxAttempts = options.maxAttempts ?? 3;
  const baseDelayMs = options.baseDelayMs ?? 10; // Fast default for tests/workers
  const webhooks = await options.repo.listActiveWebhooks(options.job.tenantId);
  const results: WebhookDispatchResult[] = [];

  for (const wh of webhooks) {
    if (!wh.events.includes(options.job.eventType) && !wh.events.includes("*")) {
      continue;
    }

    const deliveryIdempKey = `${options.job.idempotencyKey}:${wh.id}`;
    const bodyString = JSON.stringify({
      id: options.job.idempotencyKey,
      event: options.job.eventType,
      timestamp: options.job.timestamp,
      data: options.job.data,
    });

    const signature = await hmacSha256Hex(wh.signingSecret, bodyString);
    let attempts = 0;
    let delivered = false;
    let lastStatusCode: number | null = null;

    while (attempts < maxAttempts && !delivered) {
      attempts += 1;
      try {
        const res = await fetchFn(wh.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            [`${BRAND.headerPrefix}-Signature-256`]: `sha256=${signature}`,
            [`${BRAND.headerPrefix}-Event`]: options.job.eventType,
            "Idempotency-Key": deliveryIdempKey,
          },
          body: bodyString,
        });

        lastStatusCode = res.status;
        if (res.status >= 200 && res.status < 300) {
          delivered = true;
          break;
        }
      } catch {
        lastStatusCode = null;
      }

      if (attempts < maxAttempts) {
        const backoffMs = baseDelayMs * Math.pow(2, attempts - 1);
        await new Promise((resolve) => setTimeout(resolve, backoffMs));
      }
    }

    const finalStatus = delivered ? "delivered" : "dlq";
    await options.repo.recordWebhookDelivery({
      id: `whd_${crypto.randomUUID()}`,
      tenantId: options.job.tenantId,
      webhookId: wh.id,
      idempotencyKey: deliveryIdempKey,
      status: finalStatus,
      attempts,
      lastStatusCode,
    });

    results.push({
      webhookId: wh.id,
      status: finalStatus,
      attempts,
      lastStatusCode,
    });
  }

  return results;
}