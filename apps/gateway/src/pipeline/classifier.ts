/**
 * Stage 3: Lightweight Injection & Jailbreak Classifier (< 1ms CPU budget).
 * Produces a continuous probability score [0.0, 1.0] so:
 * - score < grayZone[0] (default 0.45): fast-path allow (no LLM Judge cost)
 * - grayZone[0] <= score < grayZone[1] (0.45..0.80): escalate to Gemini LLM Judge
 * - score >= classifierThreshold (default 0.80): immediate high-confidence block
 */

export interface ClassifierSignal {
  feature: string;
  weight: number;
}

export interface ClassifierResult {
  score: number;
  signals: ClassifierSignal[];
}

const FEATURE_WEIGHTS: { feature: string; weight: number; regex: RegExp }[] = [
  {
    feature: "roleplay_bypass_framing",
    weight: 0.34,
    regex: /\b(?:pretend|hypothetically|for a fictional|roleplay as|imagine you have no)\b/i,
  },
  {
    feature: "policy_boundary_probe",
    weight: 0.32,
    regex: /\b(?:no restrictions|no boundaries|without filters|unfiltered mode|ignore safety|ethical guidelines)\b/i,
  },
  {
    feature: "hidden_instruction_reference",
    weight: 0.3,
    regex: /\b(?:hidden instructions|above text|initial prompt|original directives|secret rules|developer prompt)\b/i,
  },
  {
    feature: "authority_spoofing",
    weight: 0.28,
    regex: /\b(?:as the administrator|maintenance override|root mode|authorized security audit|emergency override)\b/i,
  },
  {
    feature: "exfiltration_intent",
    weight: 0.25,
    regex: /\b(?:dump all|exfiltrate|forward the database|leak credentials|send to external)\b/i,
  },
];

export function classifyPromptInjection(normalizedText: string): ClassifierResult {
  const signals: ClassifierSignal[] = [];
  let rawScore = 0;

  for (const feat of FEATURE_WEIGHTS) {
    if (feat.regex.test(normalizedText)) {
      signals.push({ feature: feat.feature, weight: feat.weight });
      rawScore += feat.weight;
    }
  }

  // Clamp to [0, 0.99]
  const score = Number(Math.min(0.99, rawScore).toFixed(3));
  return { score, signals };
}