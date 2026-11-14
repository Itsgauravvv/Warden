import type { Finding, OwaspLlmCategory, PolicyAction } from "@warden/policy-schema";

const INJECTION_RULES: {
  id: string;
  owasp: OwaspLlmCategory;
  confidence: number;
  description: string;
  regex: RegExp;
}[] = [
  {
    id: "injection.ignore_previous",
    owasp: "LLM01:2025-PromptInjection",
    confidence: 0.95,
    description: "Instruction override attempt (ignore/disregard previous instructions)",
    regex: /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules|directions)\b/i,
  },
  {
    id: "injection.jailbreak_dan",
    owasp: "LLM01:2025-PromptInjection",
    confidence: 0.96,
    description: "Jailbreak persona activation (DAN / Developer Mode / unfiltered)",
    regex: /\b(?:you\s+are\s+now\s+in\s+developer\s+mode|act\s+as\s+DAN|do\s+anything\s+now|bypass\s+all\s+safety\s+filters)\b/i,
  },
  {
    id: "injection.delimiter_spoofing",
    owasp: "LLM01:2025-PromptInjection",
    confidence: 0.94,
    description: "Chat template or system role delimiter spoofing",
    regex: /(?:<\|im_start\|>system|\[INST\]\s*<<SYS>>|###\s*System\s+Instruction:)/i,
  },
  {
    id: "injection.system_prompt_leak",
    owasp: "LLM07:2025-SystemPromptLeakage",
    confidence: 0.92,
    description: "Attempt to extract or verbatim repeat the hidden system prompt",
    regex: /\b(?:repeat|print|output|reveal|show)\s+(?:your\s+)?(?:exact|verbatim|full|entire|hidden)?\s*(?:system\s+prompt|initial\s+instructions|developer\s+instructions)\b/i,
  },
];

export function scanInjectionRules(options: {
  normalizedText: string;
  action: PolicyAction;
  direction: "input" | "output" | "tool_result";
}): Finding[] {
  const findings: Finding[] = [];

  for (const rule of INJECTION_RULES) {
    const match = rule.regex.exec(options.normalizedText);
    if (match) {
      findings.push({
        id: `fnd_inj_${crypto.randomUUID().slice(0, 8)}`,
        detector: "injection_rule",
        ruleId: rule.id,
        owaspCategory: rule.owasp,
        confidence: rule.confidence,
        action: options.action,
        direction: options.direction,
        evidenceSpan: {
          start: match.index,
          end: match.index + match[0].length,
          snippetRedacted: match[0].slice(0, 80),
        },
        message: `Hex spotted ${rule.description}`,
      });
    }
  }

  return findings;
}