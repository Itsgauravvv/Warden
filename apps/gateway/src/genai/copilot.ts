import { evaluateInputPipeline } from "@warden/detectors";
import {
  diffPolicyDocuments,
  parsePolicyYamlOrJson,
  type PolicyDocument,
} from "@warden/policy-schema";
import { callUpstreamProvider } from "../adapters/provider.js";

export interface QuillDraftResult {
  yaml: string;
  policy: PolicyDocument;
  changes: ReturnType<typeof diffPolicyDocuments>;
  dryRun: {
    totalEvaluated: number;
    newlyBlockedCount: number;
    newlyRedactedCount: number;
  };
  source: "gemini" | "deterministic_compiler";
}

/**
 * Deterministic natural-language-to-YAML compiler used as an instant baseline
 * and guaranteed valid fallback when Gemini is unavailable or offline.
 */
function compileDeterministicPolicyYaml(instruction: string, basePolicy: PolicyDocument): string {
  const lower = instruction.toLowerCase();

  const mode = lower.includes("shadow") ? "shadow" : "enforce";
  const failMode = lower.includes("fail open") || lower.includes("fail-open") ? "open" : "closed";
  const piiAction = lower.includes("block") && lower.includes("pii") ? "block" : "redact";
  const secretsEnabled = !lower.includes("disable secret");
  const injectionEnabled = !lower.includes("disable injection");
  const cacheEnabled =
    lower.includes("cache") && !lower.includes("disable cache")
      ? true
      : basePolicy.semanticCache.enabled;

  const requireEmailApproval =
    lower.includes("approval") && (lower.includes("send_email") || lower.includes("email"));

  const toolsBlock = requireEmailApproval
    ? `  tools:
    - name: "send_email"
      allowed: true
      requireApproval: true
      blockUntrustedTaint: true`
    : `  tools: []`;

  return `version: "1.0"
name: "quill-draft-${Date.now().toString().slice(-4)}"
mode: "${mode}"
failMode: "${failMode}"
detectors:
  pii:
    enabled: true
    action: "${piiAction}"
    restoreOnResponse: true
  secrets:
    enabled: ${secretsEnabled}
    action: "block"
    entropyThreshold: 4.2
  injection:
    enabled: ${injectionEnabled}
    action: "block"
    classifierThreshold: 0.75
    judgeGrayZone: [0.45, 0.80]
  canary:
    enabled: true
    action: "block"
semanticCache:
  enabled: ${cacheEnabled}
  similarityThreshold: 0.92
  ttlSeconds: 3600
toolFirewall:
  enabled: true
  defaultAction: "block"
${toolsBlock}`;
}

/**
 * Quill Policy Copilot:
 * 1. Converts natural-language instruction into Warden v1.0 YAML (via Gemini or deterministic compiler).
 * 2. Validates strictly against PolicyDocumentSchema (Zod).
 * 3. Computes structural diff against the tenant's current policy.
 * 4. Runs a non-destructive dry-run against historical tenant requests.
 */
export async function draftPolicyWithQuill(options: {
  instruction: string;
  currentPolicy: PolicyDocument;
  historicalPrompts: { promptRedacted: string; finalAction: string }[];
  apiKey?: string | null;
  fetchImpl?: typeof fetch;
}): Promise<QuillDraftResult> {
  let rawYaml: string | null = null;
  let source: "gemini" | "deterministic_compiler" = "deterministic_compiler";

  if (options.apiKey) {
    try {
      const res = await callUpstreamProvider({
        provider: "gemini",
        apiKey: options.apiKey,
        body: {
          model: "gemini-2.5-flash",
          temperature: 0.1,
          stream: false,
          messages: [
            {
              role: "system",
              content:
                'You are Quill, the policy clerk for Warden. Convert the user request into valid Warden YAML version "1.0". Output ONLY raw YAML without markdown fences.',
            },
            { role: "user", content: options.instruction },
          ],
        },
        fetchImpl: options.fetchImpl,
      });

      if (res.ok) {
        const json = (await res.json()) as { choices?: { message?: { content?: string } }[] };
        const candidate = (json.choices?.[0]?.message?.content ?? "")
          .replace(/```yaml/gi, "")
          .replace(/```/g, "")
          .trim();
        if (candidate) {
          // Validate Gemini's YAML strictly against Zod before accepting it
          parsePolicyYamlOrJson(candidate);
          rawYaml = candidate;
          source = "gemini";
        }
      }
    } catch {
      // Fall back cleanly to deterministic compiler if Gemini output is invalid or unreachable
    }
  }

  if (!rawYaml) {
    rawYaml = compileDeterministicPolicyYaml(options.instruction, options.currentPolicy);
    source = "deterministic_compiler";
  }

  const parsed = parsePolicyYamlOrJson(rawYaml);
  const changes = diffPolicyDocuments(options.currentPolicy, parsed.policy);

  let newlyBlockedCount = 0;
  let newlyRedactedCount = 0;

  for (const req of options.historicalPrompts) {
    const evalRes = evaluateInputPipeline(req.promptRedacted, parsed.policy);
    if (evalRes.finalAction === "block" && req.finalAction !== "block") {
      newlyBlockedCount += 1;
    }
    if (evalRes.finalAction === "redact" && req.finalAction !== "redact") {
      newlyRedactedCount += 1;
    }
  }

  return {
    yaml: parsed.canonicalYaml,
    policy: parsed.policy,
    changes,
    dryRun: {
      totalEvaluated: options.historicalPrompts.length,
      newlyBlockedCount,
      newlyRedactedCount,
    },
    source,
  };
}