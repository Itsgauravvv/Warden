import { parse, stringify } from "yaml";
import { PolicyDocumentSchema, type PolicyDocument } from "./index.js";

export interface PolicyChangeEntry {
  path: string;
  before: unknown;
  after: unknown;
}

/**
 * Parses a YAML or JSON policy string and validates it against PolicyDocumentSchema.
 */
export function parsePolicyYamlOrJson(rawContent: string): {
  policy: PolicyDocument;
  canonicalYaml: string;
} {
  const trimmed = rawContent.trim();
  if (!trimmed) {
    throw new Error("Policy content cannot be empty");
  }

  let rawObject: unknown;
  try {
    rawObject = trimmed.startsWith("{") ? JSON.parse(trimmed) : parse(trimmed);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Invalid syntax";
    throw new Error(`Failed to parse YAML/JSON policy: ${msg}`);
  }

  const parsed = PolicyDocumentSchema.safeParse(rawObject);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
    throw new Error(`Policy schema validation failed: ${issues}`);
  }

  return {
    policy: parsed.data,
    canonicalYaml: stringify(parsed.data),
  };
}

/**
 * Computes a structural diff between two PolicyDocument objects.
 */
export function diffPolicyDocuments(
  beforeDoc: PolicyDocument,
  afterDoc: PolicyDocument
): PolicyChangeEntry[] {
  const changes: PolicyChangeEntry[] = [];

  function walk(a: unknown, b: unknown, currentPath: string) {
    if (Object.is(a, b)) return;

    if (Array.isArray(a) || Array.isArray(b)) {
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        changes.push({ path: currentPath, before: a, after: b });
      }
      return;
    }

    if (
      typeof a === "object" &&
      a !== null &&
      typeof b === "object" &&
      b !== null
    ) {
      const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
      for (const k of keys) {
        const nextPath = currentPath ? `${currentPath}.${k}` : k;
        walk(
          (a as Record<string, unknown>)[k],
          (b as Record<string, unknown>)[k],
          nextPath
        );
      }
      return;
    }

    changes.push({ path: currentPath, before: a, after: b });
  }

  walk(beforeDoc, afterDoc, "");
  return changes;
}