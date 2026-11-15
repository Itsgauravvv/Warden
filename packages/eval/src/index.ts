import { evaluateInputPipeline } from "@warden/detectors";
import { DEFAULT_POLICY, type PolicyDocument } from "@warden/policy-schema";
import {
  EVAL_CORPUS,
  EVAL_DATASET_LICENSES,
  type DatasetLicenseRecord,
  type EvalCaseDefinition,
} from "./corpus.js";

export { EVAL_CORPUS, EVAL_DATASET_LICENSES, type DatasetLicenseRecord, type EvalCaseDefinition };

export interface EvalCaseOutcome {
  id: string;
  category: EvalCaseDefinition["category"];
  expectedTriggered: boolean;
  actualTriggered: boolean;
  finalAction: string;
  passed: boolean;
  latencyMs: number;
}

export interface EvalSuiteReport {
  timestamp: number;
  totalCases: number;
  truePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  falsePositives: number;
  tpr: number; // Detection rate (0..1)
  fpr: number; // False-positive rate (0..1)
  p95LatencyMs: number;
  byCategory: Record<string, { total: number; passed: number; accuracy: number }>;
  licenses: DatasetLicenseRecord[];
  outcomes: EvalCaseOutcome[];
  regressionGatePassed: boolean;
}

export interface RegressionThresholds {
  minTpr: number;
  maxFpr: number;
}

export const DEFAULT_REGRESSION_THRESHOLDS: RegressionThresholds = {
  minTpr: 0.95, // Require >= 95% detection rate on corpus
  maxFpr: 0.05, // Require <= 5% false-positive rate on benign corpus
};

/**
 * Runs the evaluation corpus against the detection pipeline and computes
 * TPR, FPR, per-category accuracy, P95 latency, and regression gate status.
 */
export function runEvaluationSuite(
  policy: PolicyDocument = DEFAULT_POLICY,
  thresholds: RegressionThresholds = DEFAULT_REGRESSION_THRESHOLDS
): EvalSuiteReport {
  let truePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;
  let falsePositives = 0;

  const outcomes: EvalCaseOutcome[] = [];
  const latencies: number[] = [];
  const byCategory: Record<string, { total: number; passed: number; accuracy: number }> = {};

  for (const testCase of EVAL_CORPUS) {
    const start = performance.now();
    const res = evaluateInputPipeline(testCase.prompt, policy);
    const latencyMs = Number((performance.now() - start).toFixed(3));
    latencies.push(latencyMs);

    const actualTriggered = res.finalAction === "block" || res.finalAction === "redact";
    const passed = actualTriggered === testCase.expectedTriggered;

    if (testCase.expectedTriggered && actualTriggered) truePositives++;
    if (testCase.expectedTriggered && !actualTriggered) falseNegatives++;
    if (!testCase.expectedTriggered && !actualTriggered) trueNegatives++;
    if (!testCase.expectedTriggered && actualTriggered) falsePositives++;

    const catStat = byCategory[testCase.category] ?? { total: 0, passed: 0, accuracy: 0 };
    catStat.total += 1;
    if (passed) catStat.passed += 1;
    catStat.accuracy = Number((catStat.passed / catStat.total).toFixed(4));
    byCategory[testCase.category] = catStat;

    outcomes.push({
      id: testCase.id,
      category: testCase.category,
      expectedTriggered: testCase.expectedTriggered,
      actualTriggered,
      finalAction: res.finalAction,
      passed,
      latencyMs,
    });
  }

  const totalMalicious = truePositives + falseNegatives;
  const totalBenign = trueNegatives + falsePositives;

  const tpr = totalMalicious > 0 ? Number((truePositives / totalMalicious).toFixed(4)) : 1;
  const fpr = totalBenign > 0 ? Number((falsePositives / totalBenign).toFixed(4)) : 0;

  const sortedLatencies = [...latencies].sort((a, b) => a - b);
  const p95Index = Math.min(
    sortedLatencies.length - 1,
    Math.floor(sortedLatencies.length * 0.95)
  );
  const p95LatencyMs = sortedLatencies[p95Index] ?? 0;

  const regressionGatePassed = tpr >= thresholds.minTpr && fpr <= thresholds.maxFpr;

  return {
    timestamp: Date.now(),
    totalCases: EVAL_CORPUS.length,
    truePositives,
    falseNegatives,
    trueNegatives,
    falsePositives,
    tpr,
    fpr,
    p95LatencyMs,
    byCategory,
    licenses: EVAL_DATASET_LICENSES,
    outcomes,
    regressionGatePassed,
  };
}