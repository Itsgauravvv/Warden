const ZERO_WIDTH_REGEX = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g;

const CONFUSABLES_MAP: Record<string, string> = {
  "\u0430": "a", // Cyrillic a
  "\u0435": "e", // Cyrillic e
  "\u0456": "i", // Cyrillic i
  "\u043E": "o", // Cyrillic o
  "\u0440": "p", // Cyrillic r
  "\u0441": "c", // Cyrillic c
  "\u0443": "y", // Cyrillic y
  "\u0445": "x", // Cyrillic x
  "\u03B1": "a", // Greek alpha
  "\u03BF": "o", // Greek omicron
};

export interface NormalizedResult {
  original: string;
  normalized: string;
  decodedPayloads: { encoding: "base64" | "hex" | "rot13"; decoded: string }[];
  obfuscationDetected: boolean;
}

export function rot13(input: string): string {
  return input.replace(/[a-zA-Z]/g, (char) => {
    const base = char <= "Z" ? 65 : 97;
    return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
  });
}

function tryDecodeBase64(candidate: string): string | null {
  if (candidate.length < 16 || candidate.length % 4 !== 0) return null;
  try {
    const binString = atob(candidate);
    const bytes = Uint8Array.from(binString, (m) => m.codePointAt(0) ?? 0);
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

function tryDecodeHex(candidate: string): string | null {
  const clean = candidate.replace(/^0x/i, "");
  if (clean.length < 16 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    return null;
  }
  try {
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
    }
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

export function normalizeText(input: string): NormalizedResult {
  const withoutZeroWidth = input.replace(ZERO_WIDTH_REGEX, "");
  const hadZeroWidth = withoutZeroWidth.length !== input.length;

  let confusableReplaced = false;
  const nfkc = withoutZeroWidth.normalize("NFKC").replace(/[^\x00-\x7F]/g, (ch) => {
    const mapped = CONFUSABLES_MAP[ch];
    if (mapped) {
      confusableReplaced = true;
      return mapped;
    }
    return ch;
  });

  const strippedHtml = nfkc
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<\/?[a-zA-Z][^>]*>/g, " ");

  const decodedPayloads: { encoding: "base64" | "hex" | "rot13"; decoded: string }[] = [];

  // Fixed: allow '=' padding at the end of Base64 tokens without requiring \b after '='
  const b64Matches = strippedHtml.match(/(?:^|[\s:])([A-Za-z0-9+/]{16,}={0,2})(?=$|[\s.,;!?])/g) ?? [];
  for (const rawMatch of b64Matches.slice(0, 5)) {
    const token = rawMatch.replace(/^[\s:]+/, "");
    const decoded = tryDecodeBase64(token);
    if (decoded) {
      decodedPayloads.push({ encoding: "base64", decoded });
    }
  }

  const hexMatches = strippedHtml.match(/\b(?:0x)?[0-9a-fA-F]{16,}\b/g) ?? [];
  for (const token of hexMatches.slice(0, 5)) {
    const decoded = tryDecodeHex(token);
    if (decoded) {
      decodedPayloads.push({ encoding: "hex", decoded });
    }
  }

  const rot13Candidate = rot13(strippedHtml);
  if (/\b(ignore previous|system prompt|developer mode|jailbreak)\b/i.test(rot13Candidate)) {
    decodedPayloads.push({ encoding: "rot13", decoded: rot13Candidate });
  }

  const combinedNormalized = [
    strippedHtml,
    ...decodedPayloads.map((d) => `[DECODED_${d.encoding.toUpperCase()}: ${d.decoded}]`),
  ].join("\n");

  return {
    original: input,
    normalized: combinedNormalized,
    decodedPayloads,
    obfuscationDetected: hadZeroWidth || confusableReplaced || decodedPayloads.length > 0,
  };
}