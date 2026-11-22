import React from "react";
import { BRAND } from "@warden/brand";
import { runEvaluationSuite } from "@warden/eval";
import type { PolicyAction } from "@warden/policy-schema";
import { SectionGateLabel, VerdictBadge } from "@/components/ui/GatehouseKit";
import { WardenCrestSvg } from "@/components/ui/WardenCrestSvg";

function toPolicyAction(action: string): PolicyAction {
  if (
    action === "allow" ||
    action === "redact" ||
    action === "block" ||
    action === "flag" ||
    action === "shadow"
  ) {
    return action;
  }
  return "flag";
}

export default function EvalTransparencyPage() {
  const report = runEvaluationSuite();
  const tprPct = (report.tpr * 100).toFixed(1);
  const fprPct = (report.fpr * 100).toFixed(1);

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-12">
      {/* HERO & REGRESSION GATE BANNER */}
      <section className="gate-card p-6 sm:p-10 bg-[#061c24] border-[#29dfeb] text-[#f3ecdc] space-y-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-3 max-w-2xl">
            <SectionGateLabel gateNumber="EVAL" title="CI REGRESSION GATE & TRANSPARENCY" />
            <h1 className="text-3xl sm:text-5xl font-bold tracking-tight">
              Honest Detection Benchmarks.{" "}
              <span className="text-[#29dfeb]">Measured Every Commit.</span>
            </h1>
            <p className="text-sm sm:text-base text-[#c7d6df] leading-relaxed">
              These numbers are generated directly by <code>@warden/eval</code> running{" "}
              {BRAND.name}&apos;s live detection pipeline across {report.totalCases} labeled
              adversarial and tricky benign prompts. GitHub Actions blocks any merge if TPR drops
              below 95% or FPR exceeds 5%.
            </p>
          </div>
          <div className="p-5 rounded-2xl border-2 border-[#2fd27a] bg-[#041016] flex items-center gap-4 shrink-0">
            <WardenCrestSvg
              size={56}
              alertState={report.regressionGatePassed ? "calm" : "sonic_boom"}
            />
            <div className="font-mono">
              <div className="text-[11px] text-[#9ba8b8]">CI REGRESSION GATE</div>
              <div
                className={`text-2xl font-bold ${
                  report.regressionGatePassed ? "text-[#2fd27a]" : "text-[#ff4d4d]"
                }`}
              >
                {report.regressionGatePassed ? "✓ PASSED" : "✗ FAILED"}
              </div>
              <div className="text-[11px] text-[#7df9ff]">
                THRESHOLD: TPR ≥ 95% / FPR ≤ 5%
              </div>
            </div>
          </div>
        </div>

        {/* TOP KPI CARDS */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
          <div className="p-4 rounded-xl border-2 border-[#2fd27a]/60 bg-[#041016]">
            <div className="text-[11px] text-[#9ba8b8]">DETECTION RATE (TPR)</div>
            <div className="text-3xl font-bold text-[#2fd27a] mt-1">{tprPct}%</div>
            <div className="text-[11px] text-[#c7d6df] mt-1">
              {report.truePositives} TP / {report.falseNegatives} FN
            </div>
          </div>
          <div className="p-4 rounded-xl border-2 border-[#29dfeb]/60 bg-[#041016]">
            <div className="text-[11px] text-[#9ba8b8]">FALSE-POSITIVE RATE (FPR)</div>
            <div className="text-3xl font-bold text-[#29dfeb] mt-1">{fprPct}%</div>
            <div className="text-[11px] text-[#c7d6df] mt-1">
              {report.falsePositives} FP / {report.trueNegatives} TN
            </div>
          </div>
          <div className="p-4 rounded-xl border-2 border-[#ffb300]/60 bg-[#041016]">
            <div className="text-[11px] text-[#9ba8b8]">FAST-PATH P95 LATENCY</div>
            <div className="text-3xl font-bold text-[#ffb300] mt-1">
              {report.p95LatencyMs.toFixed(2)}ms
            </div>
            <div className="text-[11px] text-[#c7d6df] mt-1">BUDGET: &lt; 10ms ON WORKERS</div>
          </div>
          <div className="p-4 rounded-xl border-2 border-[#7c5cff]/60 bg-[#041016]">
            <div className="text-[11px] text-[#9ba8b8]">CORPUS SIZE</div>
            <div className="text-3xl font-bold text-[#7df9ff] mt-1">{report.totalCases}</div>
            <div className="text-[11px] text-[#c7d6df] mt-1">
              {report.licenses.length} SPDX-LICENSED SOURCES
            </div>
          </div>
        </div>

        {/* HONEST LIMITATIONS DISCLAIMER */}
        <div className="p-4 rounded-xl border-2 border-[#ffb300]/70 bg-[#261c05] text-[#ffe082] font-mono text-xs leading-relaxed">
          <strong>⚠ DEFENSE-IN-DEPTH NOTICE:</strong> Security detection is probabilistic, not
          infallible. Scoring 100% on a curated regression corpus guarantees zero regressions on
          known attack classes—it does not guarantee immunity against novel zero-day jailbreaks.
          Always combine {BRAND.name} with least-privilege tool schemas and human approvals.
        </div>
      </section>

      {/* PER-CATEGORY BREAKDOWN */}
      <section className="space-y-4">
        <SectionGateLabel gateNumber="CAT" title="ACCURACY BY ATTACK & BENIGN CATEGORY" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {Object.entries(report.byCategory).map(([cat, stats]) => {
            const pct = Math.round(stats.accuracy * 100);
            return (
              <div key={cat} className="gate-card p-5 space-y-3">
                <div className="flex items-center justify-between font-mono text-xs font-bold uppercase">
                  <span>{cat.replace(/_/g, " ")}</span>
                  <span className="text-[#2fd27a]">
                    {stats.passed}/{stats.total} ({pct}%)
                  </span>
                </div>
                <div className="w-full h-3 rounded bg-[#041016] border border-[var(--border-ink)] overflow-hidden">
                  <div
                    className="h-full bg-[#2fd27a]"
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* CASE-BY-CASE CORPUS TABLE */}
      <section className="space-y-4">
        <SectionGateLabel gateNumber="CASES" title={`ALL ${report.totalCases} CORPUS OUTCOMES`} />
        <div className="gate-card overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-[#061c24] text-[#7df9ff] border-b-2 border-[var(--border-ink)] uppercase">
              <tr>
                <th className="p-3">Case ID</th>
                <th className="p-3">Category</th>
                <th className="p-3">Expected</th>
                <th className="p-3">Actual Verdict</th>
                <th className="p-3">Latency</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-ink)]/20">
              {report.outcomes.map((o) => (
                <tr key={o.id} className="hover:bg-[var(--bg-elevated)]">
                  <td className="p-3 font-bold">{o.id}</td>
                  <td className="p-3 uppercase">{o.category.replace(/_/g, " ")}</td>
                  <td className="p-3">
                    {o.expectedTriggered ? "TRIGGER (BLOCK/REDACT)" : "ALLOW (BENIGN)"}
                  </td>
                  <td className="p-3">
                    <VerdictBadge action={toPolicyAction(o.finalAction)} />
                  </td>
                  <td className="p-3 tabular-nums">{o.latencyMs.toFixed(3)}ms</td>
                  <td className="p-3 font-bold">
                    <span className={o.passed ? "text-[#2fd27a]" : "text-[#ff4d4d]"}>
                      {o.passed ? "✓ PASS" : "✗ FAIL"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* SPDX LICENSE MANIFEST */}
      <section className="space-y-4">
        <SectionGateLabel gateNumber="SPDX" title="DATASET LICENSE MANIFEST" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {report.licenses.map((lic) => (
            <div key={lic.sourceId} className="gate-card p-5 space-y-2">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="font-bold text-[#29dfeb]">{lic.sourceId}</span>
                <span className="px-2 py-0.5 rounded bg-[#061c24] text-[#7df9ff] border border-[#29dfeb] font-bold">
                  {lic.spdxLicense}
                </span>
              </div>
              <h3 className="font-bold text-sm">{lic.name}</h3>
              <p className="text-xs text-[var(--ink-muted)]">{lic.attribution}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}