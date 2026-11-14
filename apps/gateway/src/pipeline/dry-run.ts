import { evaluateInputPipeline } from "@warden/detectors";
import type { PolicyAction, PolicyDocument } from "@warden/policy-schema";
import type { TenantRepository } from "../db/repository.js";

export interface DryRunCaseDelta {
  requestId: string;
  previousAction: PolicyAction;
  candidateAction: PolicyAction;
  changed: boolean;
  newFindingsCount: number;
}

export interface DryRunReport {
  totalEvaluated: number;
  changedCount: number;
  newlyBlockedCount: number;
  newlyRedactedCount: number;
  newlyAllowedCount: number;
  deltas: DryRunCaseDelta[];
}

export async function runPolicyDryRunOnHistory(options: {
  repo: TenantRepository;
  tenantId: string;
  candidatePolicy: PolicyDocument;
  limit?: number;
}): Promise<DryRunReport> {
  const history = await options.repo.listRequests(options.tenantId, options.limit ?? 50);

  const deltas: DryRunCaseDelta[] = [];
  let changedCount = 0;
  let newlyBlockedCount = 0;
  let newlyRedactedCount = 0;
  let newlyAllowedCount = 0;

  for (const req of history) {
    const evaluation = evaluateInputPipeline(req.promptRedacted, options.candidatePolicy);
    const previousAction = req.finalAction;
    const candidateAction = evaluation.finalAction;
    const changed = previousAction !== candidateAction;

    if (changed) {
      changedCount++;
      if (candidateAction === "block" && previousAction !== "block") {
        newlyBlockedCount++;
      } else if (candidateAction === "redact" && previousAction !== "redact") {
        newlyRedactedCount++;
      } else if (candidateAction === "allow" && previousAction !== "allow") {
        newlyAllowedCount++;
      }
    }

    deltas.push({
      requestId: req.id,
      previousAction,
      candidateAction,
      changed,
      newFindingsCount: evaluation.findings.length,
    });
  }

  return {
    totalEvaluated: history.length,
    changedCount,
    newlyBlockedCount,
    newlyRedactedCount,
    newlyAllowedCount,
    deltas,
  };
}