import { BRAND } from "@warden/brand";

export type ApiKeyScope = "proxy:write" | "admin:read" | "admin:write" | "redteam:run";

export interface GeneratedApiKey {
  rawKey: string;      // Shown ONCE to the user, never stored
  prefix: string;      // Stored for UI identification, e.g. "war_live_a1b2c3d4"
  keyHash: string;     // SHA-256 hex digest stored in D1
}

/**
 * Computes SHA-256 hex digest using standard Web Crypto API (Workers + Node portable)
 */
export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Generates a high-entropy tenant API key using BRAND prefix
 */
export async function generateTenantApiKey(isSandbox = false): Promise<GeneratedApiKey> {
  const randomBytes = new Uint8Array(24);
  crypto.getRandomValues(randomBytes);
  const tokenPart = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const basePrefix = isSandbox ? BRAND.sandboxKeyPrefix : BRAND.apiKeyPrefix;
  const rawKey = `${basePrefix}${tokenPart}`;
  const prefix = `${basePrefix}${tokenPart.slice(0, 8)}`;
  const keyHash = await sha256Hex(rawKey);

  return { rawKey, prefix, keyHash };
}