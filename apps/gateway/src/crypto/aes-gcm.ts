/**
 * AES-256-GCM authenticated encryption for tenant provider API keys at rest.
 * Master secret is derived via SHA-256 into a 256-bit CryptoKey.
 */

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  const buffer = new ArrayBuffer(hex.length / 2);
  const out = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

async function deriveAesKey(masterSecret: string): Promise<CryptoKey> {
  if (!masterSecret || masterSecret.length < 16) {
    throw new Error("Master encryption secret must be at least 16 characters");
  }
  const rawHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(masterSecret));
  return crypto.subtle.importKey("raw", rawHash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptSecret(
  plaintext: string,
  masterSecret: string
): Promise<{ encryptedHex: string; ivHex: string }> {
  const key = await deriveAesKey(masterSecret);
  const iv = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(12))); // 96-bit IV for AES-GCM
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);

  return {
    encryptedHex: toHex(new Uint8Array(ciphertext)),
    ivHex: toHex(iv),
  };
}

export async function decryptSecret(
  encryptedHex: string,
  ivHex: string,
  masterSecret: string
): Promise<string> {
  const key = await deriveAesKey(masterSecret);
  const iv = fromHex(ivHex);
  const ciphertext = fromHex(encryptedHex);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}