import { normalizeText, scanInjectionRules } from "@warden/detectors";
import type { Finding, PolicyDocument } from "@warden/policy-schema";
import type { ChatCompletionRequest } from "../adapters/provider.js";

export interface IncomingToolCall {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
}

export interface ToolFirewallDecision {
  toolCallId: string;
  toolName: string;
  argumentsRedactedJson: string;
  status: "allowed" | "blocked" | "pending_approval";
  taintDetected: boolean;
  findings: Finding[];
}

export interface UntrustedContextTaint {
  isTainted: boolean;
  extractedTokens: string[]; // Emails, URLs, and paths originating from untrusted tool_results
  injectionFindings: Finding[];
}

const DENY_PATTERN_REGEXES = {
  path_traversal: /(?:\.\.[/\\]|\/etc\/passwd|\/etc\/shadow|c:\\windows\\system32)/i,
  ssrf_private_ip:
    /https?:\/\/(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[::1\])/i,
  shell_metacharacters: /(?:;\s*(?:rm|curl|wget|bash|sh|nc|python)\b|\|\|\s*(?:sh|bash)|\$\([^)]+\)|`[^`]+`)/i,
  destructive_sql: /\b(?:DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*(?:;|$|WHERE\s+1\s*=\s*1))\b/i,
} as const;

/**
 * Inspects `role: "tool"` messages (e.g. retrieved documents, web pages, emails)
 * for indirect prompt injections and extracts untrusted tokens (emails, URLs) for
 * confused-deputy taint tracking.
 */
export function analyzeUntrustedToolResults(
  messages: ChatCompletionRequest["messages"],
  policy: PolicyDocument
): UntrustedContextTaint {
  const extractedTokens = new Set<string>();
  const injectionFindings: Finding[] = [];

  for (const msg of messages) {
    if (msg.role !== "tool" || !msg.content) continue;

    const norm = normalizeText(msg.content);
    const inj = scanInjectionRules({
      normalizedText: norm.normalized,
      action: policy.detectors.injection.action,
      direction: "tool_result",
    });
    injectionFindings.push(...inj);

    // Extract emails and URLs present inside the untrusted tool result
    const emails = msg.content.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) ?? [];
    const urls = msg.content.match(/https?:\/\/[^\s"'<>]+/g) ?? [];
    for (const token of [...emails, ...urls]) {
      extractedTokens.add(token.toLowerCase());
    }
  }

  return {
    isTainted: injectionFindings.length > 0 || extractedTokens.size > 0,
    extractedTokens: Array.from(extractedTokens),
    injectionFindings,
  };
}

/**
 * Lightweight JSON-Schema validator for tool call arguments (required fields & primitive types).
 */
function validateArgumentsAgainstJsonSchema(
  argsObj: Record<string, unknown>,
  schema: Record<string, unknown>
): string | null {
  const required = Array.isArray(schema.required) ? (schema.required as string[]) : [];
  for (const reqField of required) {
    if (!(reqField in argsObj) || argsObj[reqField] === undefined) {
      return `Missing required argument '${reqField}'`;
    }
  }

  const properties =
    typeof schema.properties === "object" && schema.properties !== null
      ? (schema.properties as Record<string, { type?: string }>)
      : {};

  for (const [key, propSchema] of Object.entries(properties)) {
    if (key in argsObj && argsObj[key] !== undefined && propSchema.type) {
      const actualType = Array.isArray(argsObj[key]) ? "array" : typeof argsObj[key];
      if (actualType !== propSchema.type) {
        return `Argument '${key}' expected type '${propSchema.type}' but got '${actualType}'`;
      }
    }
  }

  return null;
}

/**
 * Evaluates a list of LLM tool_calls against policy.toolFirewall rules,
 * JSON schema constraints, dangerous argument patterns, and confused-deputy taint.
 */
export function evaluateToolCallsFirewall(options: {
  toolCalls: IncomingToolCall[];
  policy: PolicyDocument;
  taintContext: UntrustedContextTaint;
}): ToolFirewallDecision[] {
  const decisions: ToolFirewallDecision[] = [];
  const fw = options.policy.toolFirewall;

  for (const tc of options.toolCalls) {
    const toolName = tc.function.name;
    const rawArgs = tc.function.arguments || "{}";
    const findings: Finding[] = [];
    let status: "allowed" | "blocked" | "pending_approval" = "allowed";
    let taintDetected = false;

    const rule = fw.tools.find((t) => t.name === toolName);

    // 1. Check tool allowlist / defaultAction
    if (rule && !rule.allowed) {
      status = "blocked";
      findings.push({
        id: `fnd_tfw_${crypto.randomUUID().slice(0, 8)}`,
        detector: "tool_firewall",
        ruleId: `tool_firewall.denied_tool.${toolName}`,
        owaspCategory: "LLM06:2025-ExcessiveAgency",
        confidence: 1.0,
        action: "block",
        direction: "tool_call",
        evidenceSpan: { start: 0, end: toolName.length, snippetRedacted: toolName },
        message: `Tool '${toolName}' is explicitly disabled by policy`,
      });
    } else if (!rule && fw.defaultAction === "block" && fw.tools.length > 0) {
      status = "blocked";
      findings.push({
        id: `fnd_tfw_${crypto.randomUUID().slice(0, 8)}`,
        detector: "tool_firewall",
        ruleId: `tool_firewall.unlisted_tool.${toolName}`,
        owaspCategory: "LLM06:2025-ExcessiveAgency",
        confidence: 1.0,
        action: "block",
        direction: "tool_call",
        evidenceSpan: { start: 0, end: toolName.length, snippetRedacted: toolName },
        message: `Tool '${toolName}' is not on the policy allowlist`,
      });
    }

    // 2. Parse JSON arguments & validate JSON schema
    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(rawArgs) as Record<string, unknown>;
    } catch {
      status = "blocked";
      findings.push({
        id: `fnd_tfw_${crypto.randomUUID().slice(0, 8)}`,
        detector: "tool_firewall",
        ruleId: "tool_firewall.invalid_json_arguments",
        owaspCategory: "LLM05:2025-ImproperOutputHandling",
        confidence: 1.0,
        action: "block",
        direction: "tool_call",
        evidenceSpan: { start: 0, end: rawArgs.length, snippetRedacted: rawArgs.slice(0, 60) },
        message: `Tool '${toolName}' arguments are not valid JSON`,
      });
    }

    if (rule?.argumentJsonSchema && status !== "blocked") {
      const schemaError = validateArgumentsAgainstJsonSchema(parsedArgs, rule.argumentJsonSchema);
      if (schemaError) {
        status = "blocked";
        findings.push({
          id: `fnd_tfw_${crypto.randomUUID().slice(0, 8)}`,
          detector: "tool_firewall",
          ruleId: `tool_firewall.schema_violation.${toolName}`,
          owaspCategory: "LLM05:2025-ImproperOutputHandling",
          confidence: 1.0,
          action: "block",
          direction: "tool_call",
          evidenceSpan: { start: 0, end: rawArgs.length, snippetRedacted: rawArgs.slice(0, 60) },
          message: `Tool '${toolName}' failed JSON Schema check: ${schemaError}`,
        });
      }
    }

    // 3. Check dangerous argument patterns (Path traversal, SSRF, Shell metacharacters, Destructive SQL)
    const activeDenyPatterns = rule?.denyPatterns ?? [
      "path_traversal",
      "ssrf_private_ip",
      "shell_metacharacters",
      "destructive_sql",
    ];
    for (const patternName of activeDenyPatterns) {
      const regex = DENY_PATTERN_REGEXES[patternName];
      const match = regex.exec(rawArgs);
      if (match) {
        status = "blocked";
        findings.push({
          id: `fnd_tfw_${crypto.randomUUID().slice(0, 8)}`,
          detector: "tool_firewall",
          ruleId: `tool_firewall.${patternName}`,
          owaspCategory: "LLM06:2025-ExcessiveAgency",
          confidence: 0.99,
          action: "block",
          direction: "tool_call",
          evidenceSpan: {
            start: match.index,
            end: match.index + match[0].length,
            snippetRedacted: match[0].slice(0, 60),
          },
          message: `Tool '${toolName}' blocked by ${patternName} guard`,
        });
      }
    }

    // 4. Confused-Deputy Check: did an argument value come from a poisoned/untrusted tool_result?
    const checkTaint = rule?.blockUntrustedTaint ?? true;
    if (checkTaint && options.taintContext.isTainted) {
      const lowerArgs = rawArgs.toLowerCase();
      const matchedTaintToken = options.taintContext.extractedTokens.find((tok) =>
        lowerArgs.includes(tok)
      );
      if (matchedTaintToken || options.taintContext.injectionFindings.length > 0) {
        taintDetected = true;
        status = "blocked";
        findings.push({
          id: `fnd_tfw_${crypto.randomUUID().slice(0, 8)}`,
          detector: "tool_firewall",
          ruleId: "tool_firewall.confused_deputy_taint",
          owaspCategory: "LLM06:2025-ExcessiveAgency",
          confidence: 0.96,
          action: "block",
          direction: "tool_call",
          evidenceSpan: {
            start: 0,
            end: rawArgs.length,
            snippetRedacted: matchedTaintToken ?? rawArgs.slice(0, 60),
          },
          message: `Confused-deputy attack blocked: tool '${toolName}' arguments derived from tainted untrusted content`,
        });
      }
    }

    // 5. Human-in-the-loop Approval Queue check (if not already blocked)
    if (status === "allowed" && (rule?.requireApproval || (!rule && fw.defaultAction === "require_approval"))) {
      status = "pending_approval";
      findings.push({
        id: `fnd_tfw_${crypto.randomUUID().slice(0, 8)}`,
        detector: "tool_firewall",
        ruleId: `tool_firewall.approval_required.${toolName}`,
        owaspCategory: "LLM06:2025-ExcessiveAgency",
        confidence: 1.0,
        action: "flag",
        direction: "tool_call",
        evidenceSpan: { start: 0, end: rawArgs.length, snippetRedacted: rawArgs.slice(0, 60) },
        message: `High-risk tool '${toolName}' held in human approval queue`,
      });
    }

    decisions.push({
      toolCallId: tc.id,
      toolName,
      argumentsRedactedJson: rawArgs,
      status,
      taintDetected,
      findings,
    });
  }

  return decisions;
}