import { describe, expect, it } from "vitest";
import { runEvaluationSuite } from "../src/index.js";

describe("Step 8: @warden/eval CI Regression Gate & Corpus Benchmark", () => {
  it("meets or exceeds TPR >= 95% and FPR <= 5% across all 24 corpus cases with valid SPDX licenses", () => {
    const report = runEvaluationSuite();

    // If any case fails, log it clearly for CI debugging
    const failedCases = report.outcomes.filter((o) => !o.passed);
    expect(failedCases).toEqual([]);

    expect(report.totalCases).toBe(24);
    expect(report.tpr).toBeGreaterThanOrEqual(0.95);
    expect(report.fpr).toBeLessThanOrEqual(0.05);
    expect(report.regressionGatePassed).toBe(true);

    // Verify fast-path latency budget (< 10ms P95 for Cloudflare Workers free tier)
    expect(report.p95LatencyMs).toBeLessThan(10);

    // Verify all dataset licenses are documented
    expect(report.licenses.length).toBeGreaterThanOrEqual(3);
  });
});