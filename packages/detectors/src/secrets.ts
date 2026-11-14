import type { Finding, PolicyAction } from "@warden/policy-schema";

/**
 * Calculates Shannon Entropy in bits per character (0 to 8).
 */
export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] ?? 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const SECRET_RULES: { id: string; label: string; regex: RegExp }[] = [
  { id: "secret.aws_access_key", label: "AWS Access Key ID", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: "secret.github_pat", label: "GitHub Personal Access Token", regex: /\bgh[pousr]_[A-Za-z0-9_]{30,255}\b/g },
  { id: "secret.google_api_key", label: "Google / Gemini API Key", regex: /\bAIzaSy[A-Za-z0-9_-]{33}\b/g },
  { id: "secret.openai_key", label: "OpenAI API Key", regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: "secret.slack_token", label: "Slack Token", regex: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g },
  { id: "secret.private_key_pem", label: "PEM Private Key", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
];

export function scanSecrets(options: {
  text: string;
  action: PolicyAction;
  entropyThreshold: number;
  direction: "input" | "output";
}): Finding[] {
  const findings: Finding[] = [];

  // 1. Deterministic signature rules
  for (const rule of SECRET_RULES) {
    const regex = new RegExp(rule.regex.source, "g");
    let match: RegExpExecArray | null;
    while ((match = regex.exec(options.text)) !== null) {
      const val = match[0];
      const redactedPreview = `${val.slice(0, 4)}...[REDACTED_SECRET]`;
      findings.push({
        id: `fnd_sec_${crypto.randomUUID().slice(0, 8)}`,
        detector: "secret",
        ruleId: rule.id,
        owaspCategory: "LLM02:2025-SensitiveInformationDisclosure",
        confidence: 0.99,
        action: options.action,
        direction: options.direction,
        evidenceSpan: {
          start: match.index,
          end: match.index + val.length,
          snippetRedacted: redactedPreview,
        },
        message: `Sniffer detected ${rule.label}`,
      });
    }
  }

  // 2. High-entropy secret assignment check (e.g. api_key = "8f9a2b...")
  const assignmentRegex = /\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*["']([A-Za-z0-9/+_-]{20,})["']/gi;
  let assignMatch: RegExpExecArray | null;
  while ((assignMatch = assignmentRegex.exec(options.text)) !== null) {
    const candidate = assignMatch[1] ?? "";
    const entropy = calculateShannonEntropy(candidate);
    if (entropy >= options.entropyThreshold) {
      findings.push({
        id: `fnd_sec_${crypto.randomUUID().slice(0, 8)}`,
        detector: "secret",
        ruleId: "secret.high_entropy_assignment",
        owaspCategory: "LLM02:2025-SensitiveInformationDisclosure",
        confidence: 0.9,
        action: options.action,
        direction: options.direction,
        evidenceSpan: {
          start: assignMatch.index,
          end: assignMatch.index + assignMatch[0].length,
          snippetRedacted: `${candidate.slice(0, 3)}...[ENTROPY:${entropy.toFixed(2)}]`,
        },
        message: `Sniffer detected high-entropy secret (${entropy.toFixed(2)} bits/char)`,
      });
    }
  }

  return findings;
}