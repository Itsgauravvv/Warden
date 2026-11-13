import { z } from "zod";

/**
 * Official OWASP Top 10 for LLM Applications (2025 Revision)
 */
export const OwaspLlmCategorySchema = z.enum([
  "LLM01:2025-PromptInjection",
  "LLM02:2025-SensitiveInformationDisclosure",
  "LLM03:2025-SupplyChain",
  "LLM04:2025-DataAndModelPoisoning",
  "LLM05:2025-ImproperOutputHandling",
  "LLM06:2025-ExcessiveAgency",
  "LLM07:2025-SystemPromptLeakage",
  "LLM08:2025-VectorAndEmbeddingWeaknesses",
  "LLM09:2025-Misinformation",
  "LLM10:2025-UnboundedConsumption",
]);

export type OwaspLlmCategory = z.infer<typeof OwaspLlmCategorySchema>;

/**
 * Policy Actions:
 * - allow: let request/response pass untouched
 * - redact: reversible masking on input, restored in output if permitted
 * - block: halt immediately with safe refusal body
 * - flag: allow traffic but emit high-priority finding & webhook alert
 * - shadow: log-only mode for testing policies without affecting production traffic
 */
export const PolicyActionSchema = z.enum(["allow", "redact", "block", "flag", "shadow"]);
export type PolicyAction = z.infer<typeof PolicyActionSchema>;

export const FailModeSchema = z.enum(["open", "closed"]);

/**
 * Individual Finding produced by any stage of the detection pipeline
 */
export const FindingSchema = z.object({
  id: z.string(),
  detector: z.enum(["normalizer", "pii", "secret", "injection_rule", "classifier", "llm_judge", "tool_firewall", "canary"]),
  ruleId: z.string(),
  owaspCategory: OwaspLlmCategorySchema,
  confidence: z.number().min(0).max(1),
  action: PolicyActionSchema,
  direction: z.enum(["input", "output", "tool_call", "tool_result"]),
  evidenceSpan: z.object({
    start: z.number().int().nonnegative(),
    end: z.number().int().nonnegative(),
    snippetRedacted: z.string(),
  }),
  message: z.string(),
});

export type Finding = z.infer<typeof FindingSchema>;

/**
 * Agent Tool-Call Firewall Rule
 */
export const ToolRuleSchema = z.object({
  name: z.string().min(1),
  allowed: z.boolean().default(true),
  requireApproval: z.boolean().default(false),
  blockUntrustedTaint: z.boolean().default(true),
  argumentJsonSchema: z.record(z.unknown()).optional(),
  denyPatterns: z
    .array(z.enum(["path_traversal", "ssrf_private_ip", "shell_metacharacters", "destructive_sql"]))
    .default(["path_traversal", "ssrf_private_ip", "shell_metacharacters", "destructive_sql"]),
});

/**
 * Complete Versioned Policy-as-Code Schema
 */
export const PolicyDocumentSchema = z.object({
  version: z.literal("1.0"),
  name: z.string().min(1).max(120),
  description: z.string().max(500).optional(),
  mode: z.enum(["enforce", "shadow"]).default("enforce"),
  failMode: FailModeSchema.default("closed"),
  stageBudgetsMs: z
    .object({
      normalizer: z.number().int().min(1).max(50).default(5),
      rules: z.number().int().min(1).max(100).default(15),
      classifier: z.number().int().min(10).max(1000).default(150),
      llmJudge: z.number().int().min(100).max(5000).default(1200),
    })
    .default({}),
  detectors: z.object({
    pii: z
      .object({
        enabled: z.boolean().default(true),
        action: PolicyActionSchema.default("redact"),
        restoreOnResponse: z.boolean().default(true),
        types: z
          .array(z.enum(["email", "phone", "credit_card", "iban", "ssn_us", "national_id"]))
          .default(["email", "phone", "credit_card", "iban", "ssn_us"]),
      })
      .default({}),
    secrets: z
      .object({
        enabled: z.boolean().default(true),
        action: PolicyActionSchema.default("block"),
        entropyThreshold: z.number().min(3.0).max(6.0).default(4.3),
      })
      .default({}),
    injection: z
      .object({
        enabled: z.boolean().default(true),
        action: PolicyActionSchema.default("block"),
        classifierThreshold: z.number().min(0).max(1).default(0.8),
        judgeGrayZone: z
          .tuple([z.number().min(0).max(1), z.number().min(0).max(1)])
          .default([0.45, 0.8]),
      })
      .default({}),
    canary: z
      .object({
        enabled: z.boolean().default(true),
        action: PolicyActionSchema.default("block"),
      })
      .default({}),
  }),
  toolFirewall: z
    .object({
      enabled: z.boolean().default(true),
      defaultAction: z.enum(["allow", "block", "require_approval"]).default("block"),
      tools: z.array(ToolRuleSchema).default([]),
    })
    .default({}),
  semanticCache: z
    .object({
      enabled: z.boolean().default(false),
      similarityThreshold: z.number().min(0.8).max(0.999).default(0.94),
      ttlSeconds: z.number().int().min(60).max(86400).default(3600),
    })
    .default({}),
});

export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;

export const DEFAULT_POLICY: PolicyDocument = PolicyDocumentSchema.parse({
  version: "1.0",
  name: "default-gatehouse-policy",
  description: "Balanced default protection: blocks secrets & injections, redacts PII, guards agent tools.",
  detectors: {},
});