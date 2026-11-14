import { DEFAULT_POLICY, type Finding, type PolicyAction, type PolicyDocument } from "@warden/policy-schema";
import { normalizeText } from "./normalizer.js";
import { scanAndRedactPii, restoreRedactedValues, passesLuhn } from "./pii.js";
import { scanSecrets, calculateShannonEntropy } from "./secrets.js";
import { scanInjectionRules } from "./injection.js";
import { generateCanaryToken, injectCanaryIntoSystemPrompt, checkCanaryLeak } from "./canary.js";

export {
  normalizeText,
  passesLuhn,
  scanAndRedactPii,
  restoreRedactedValues,
  scanSecrets,
  calculateShannonEntropy,
  scanInjectionRules,
  generateCanaryToken,
  injectCanaryIntoSystemPrompt,
  checkCanaryLeak,
};

const ACTION_PRECEDENCE: Record<PolicyAction, number> = {
  allow: 0,
  shadow: 1,
  flag: 2,
  redact: 3,
  block: 4,
};

export interface PipelineEvaluationResult {
  finalAction: PolicyAction;
  sanitizedText: string;
  redactionMap: Record<string, string>;
  findings: Finding[];
}

/**
 * Executes the fast-path detection cascade (Normalizer -> Secrets -> Injection -> PII)
 * with short-circuiting when a "block" verdict is reached in enforce mode.
 */
export function evaluateInputPipeline(
  rawText: string,
  policy: PolicyDocument = DEFAULT_POLICY
): PipelineEvaluationResult {
  const findings: Finding[] = [];
  let sanitizedText = rawText;
  let redactionMap: Record<string, string> = {};

  // Stage 1: Normalize
  const norm = normalizeText(rawText);

  // Stage 2A: Secrets (check both original and normalized text)
  if (policy.detectors.secrets.enabled) {
    const secretFindings = scanSecrets({
      text: norm.normalized,
      action: policy.detectors.secrets.action,
      entropyThreshold: policy.detectors.secrets.entropyThreshold,
      direction: "input",
    });
    findings.push(...secretFindings);
  }

  // Stage 2B: Prompt Injection signatures (runs on normalized/decoded text!)
  if (policy.detectors.injection.enabled) {
    const injectionFindings = scanInjectionRules({
      normalizedText: norm.normalized,
      action: policy.detectors.injection.action,
      direction: "input",
    });
    findings.push(...injectionFindings);
  }

  // Stage 2C: PII detection & reversible redaction
  if (policy.detectors.pii.enabled) {
    const piiResult = scanAndRedactPii({
      text: sanitizedText,
      enabledTypes: policy.detectors.pii.types,
      action: policy.detectors.pii.action,
      direction: "input",
    });
    findings.push(...piiResult.findings);
    sanitizedText = piiResult.redactedText;
    redactionMap = piiResult.redactionMap;
  }

  // Determine highest-severity action
  let finalAction: PolicyAction = "allow";
  for (const f of findings) {
    if (ACTION_PRECEDENCE[f.action] > ACTION_PRECEDENCE[finalAction]) {
      finalAction = f.action;
    }
  }

  // If the entire policy is in shadow mode, downgrade final enforcement to "shadow"
  if (policy.mode === "shadow" && finalAction !== "allow") {
    finalAction = "shadow";
    sanitizedText = rawText; // Do not alter traffic in shadow mode
  }

  return {
    finalAction,
    sanitizedText,
    redactionMap,
    findings,
  };
}