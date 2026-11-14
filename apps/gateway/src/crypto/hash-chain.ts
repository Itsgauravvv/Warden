import { sha256Hex } from "../auth/api-key.js";

export const GENESIS_PREV_HASH = "0".repeat(64);

/**
 * Produces deterministic canonical JSON with recursively sorted object keys
 * so SHA-256 hashes are identical across all runtimes.
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`);
  return `{${pairs.join(",")}}`;
}

/**
 * Computes SHA-256(prevHash || canonicalJson)
 */
export async function computeAuditRecordHash(
  prevHash: string,
  canonicalJson: string
): Promise<string> {
  return sha256Hex(`${prevHash}||${canonicalJson}`);
}

/**
 * Computes HMAC-SHA256 hex signature using Web Crypto API (portable across Workers & Node)
 */
export async function hmacSha256Hex(secret: string, payload: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface AuditChainLink {
  seq: number;
  prevHash: string;
  canonicalJson: string;
  recordHash: string;
}

export interface AuditChainVerificationResult {
  valid: boolean;
  totalChecked: number;
  firstCorruptedSeq: number | null;
  reason?: string;
}

/**
 * Verifies an ordered array of audit records and pinpoints the exact first corrupted sequence number.
 */
export async function verifyAuditChainLinks(
  links: AuditChainLink[]
): Promise<AuditChainVerificationResult> {
  let expectedPrevHash = GENESIS_PREV_HASH;

  for (let i = 0; i < links.length; i++) {
    const link = links[i]!;
    const expectedSeq = i + 1;

    if (link.seq !== expectedSeq) {
      return {
        valid: false,
        totalChecked: i + 1,
        firstCorruptedSeq: link.seq,
        reason: `Sequence gap at index ${i}: expected seq ${expectedSeq}, found ${link.seq}`,
      };
    }

    if (link.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        totalChecked: i + 1,
        firstCorruptedSeq: link.seq,
        reason: `Broken prevHash link at seq ${link.seq}`,
      };
    }

    const recomputedHash = await computeAuditRecordHash(link.prevHash, link.canonicalJson);
    if (recomputedHash !== link.recordHash) {
      return {
        valid: false,
        totalChecked: i + 1,
        firstCorruptedSeq: link.seq,
        reason: `Payload hash mismatch at seq ${link.seq}: record content was tampered with`,
      };
    }

    expectedPrevHash = link.recordHash;
  }

  return {
    valid: true,
    totalChecked: links.length,
    firstCorruptedSeq: null,
  };
}