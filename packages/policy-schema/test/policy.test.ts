import { describe, expect, it } from "vitest";
import { DEFAULT_POLICY, PolicyDocumentSchema } from "../src/index.js";
import { BRAND } from "@warden/brand";

describe("@warden/policy-schema & @warden/brand", () => {
  it("exposes a single brand constant", () => {
    expect(BRAND.name).toBe("Warden");
    expect(BRAND.apiKeyPrefix).toBe("war_live_");
  });

  it("validates the default policy with sensible defaults", () => {
    expect(DEFAULT_POLICY.mode).toBe("enforce");
    expect(DEFAULT_POLICY.detectors.pii.action).toBe("redact");
    expect(DEFAULT_POLICY.detectors.secrets.action).toBe("block");
    expect(DEFAULT_POLICY.stageBudgetsMs.normalizer).toBe(5);
  });

  it("rejects out-of-range confidence thresholds", () => {
    const invalid = {
      version: "1.0",
      name: "bad-policy",
      detectors: {
        injection: {
          classifierThreshold: 1.5, // invalid: > 1
        },
      },
    };
    const result = PolicyDocumentSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });
});