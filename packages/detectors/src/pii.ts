import type { Finding, PolicyAction } from "@warden/policy-schema";

export type PiiType = "email" | "phone" | "credit_card" | "iban" | "ssn_us" | "national_id";

/**
 * Luhn checksum validation to eliminate false positives on 13-19 digit numbers.
 */
export function passesLuhn(rawDigits: string): boolean {
  const digits = rawDigits.replace(/[\s-]/g, "");
  if (!/^\d{13,19}$/.test(digits)) return false;
  // Reject all-same-digit strings like 0000000000000000
  if (/^(\d)\1+$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = Number(digits[i]);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

const PII_PATTERNS: Record<PiiType, RegExp> = {
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  phone: /(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g,
  credit_card: /\b(?:\d[ -]*?){13,19}\b/g,
  iban: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
  ssn_us: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  national_id: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
};

export interface PiiScanResult {
  findings: Finding[];
  redactedText: string;
  redactionMap: Record<string, string>; // placeholder -> original value
}

export function scanAndRedactPii(options: {
  text: string;
  enabledTypes: PiiType[];
  action: PolicyAction;
  direction: "input" | "output";
}): PiiScanResult {
  const findings: Finding[] = [];
  const redactionMap: Record<string, string> = {};
  let redactedText = options.text;
  let counter = 1;

  for (const piiType of options.enabledTypes) {
    const regex = new RegExp(PII_PATTERNS[piiType].source, "g");
    let match: RegExpExecArray | null;

    while ((match = regex.exec(options.text)) !== null) {
      const rawValue = match[0];
      if (piiType === "credit_card" && !passesLuhn(rawValue)) {
        continue;
      }

      const placeholder = `[REDACTED_${piiType.toUpperCase()}_${counter++}]`;
      const maskedPreview =
        rawValue.length > 6 ? `${rawValue.slice(0, 2)}***${rawValue.slice(-2)}` : "***";

      findings.push({
        id: `fnd_pii_${crypto.randomUUID().slice(0, 8)}`,
        detector: "pii",
        ruleId: `pii.${piiType}`,
        owaspCategory: "LLM02:2025-SensitiveInformationDisclosure",
        confidence: 0.98,
        action: options.action,
        direction: options.direction,
        evidenceSpan: {
          start: match.index,
          end: match.index + rawValue.length,
          snippetRedacted: maskedPreview,
        },
        message: `Sniffer detected ${piiType.replace("_", " ")} (${maskedPreview})`,
      });

      if (options.action === "redact") {
        redactionMap[placeholder] = rawValue;
        redactedText = redactedText.split(rawValue).join(placeholder);
      }
    }
  }

  return { findings, redactedText, redactionMap };
}

/**
 * Restores reversible placeholders in the LLM response when allowed by policy.
 */
export function restoreRedactedValues(text: string, redactionMap: Record<string, string>): string {
  let restored = text;
  for (const [placeholder, original] of Object.entries(redactionMap)) {
    restored = restored.split(placeholder).join(original);
  }
  return restored;
}