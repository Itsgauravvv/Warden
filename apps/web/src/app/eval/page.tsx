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
      <section
        className="gate-card p-6 sm:p-10 space-y-6"
        style={{
          backgroundImage:
            "linear-gradient(135deg, var(--bg-hero-from) 0%, var(--bg-hero-to) 100%)",
        }}
      >
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-3 max-w-2xl">
            <SectionGateLabel gateNumber="EVAL" title="CI REGRESSION GATE & TRANSPARENCY" />
            <h1 className="text-3xl sm:text-5xl font-bold tracking-tight">
              Honest Detection Benchmarks.{" "}
              <span style={{ color: "var(--sculk-cyan)" }}>Measured Every Commit.</span>
            </h1>
            <p className="text-sm sm:text-base text-[var(--ink-muted)] leading-relaxed">
              These numbers are generated directly by <code>@warden/eval</code> running{" "}
              {BRAND.name}&apos;s live detection pipeline across {report.totalCases} labeled
              adversarial and tricky benign prompts. GitHub Actions blocks any merge if TPR drops
              below 95% or FPR exceeds 5%.
            </p>
          </div>

          <div
            className="p-5 rounded-2xl border-2 flex items-center gap-4 shrink-0"
            style={{
              borderColor: report.regressionGatePassed
                ? "var(--signal-allow)"
                : "var(--signal-block)",
              backgroundColor: report.regressionGatePassed ? "var(--bg-ok)" : "var(--bg-danger)",
              color: report.regressionGatePassed ? "var(--text-ok)" : "var(--text-danger)",
            }}
          >
            <div className="p-1.5 rounded-xl border-2 border-[#29dfeb] bg-[#061c24]">
              <WardenCrestSvg
                size={48}
                alertState={report.regressionGatePassed ? "calm" : "sonic_boom"}
              />
            </div>
            <div className="font-mono">
              <div className="text-[11px] font-bold opacity-80">CI REGRESSION GATE</div>
              <div className="text-2xl font-bold">
                {report.regressionGatePassed ? "✓ PASSED" : "✗ FAILED"}
              </div>
              <div className="text-[11px] font-semibold">THRESHOLD: TPR ≥ 95% / FPR ≤ 5%</div>
            </div>
          </div>
        </div>

        {/* TOP KPI CARDS */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
          <div className="p-4 rounded-xl border-2 border-[var(--signal-allow)] bg-[var(--bg-card)]">
            <div className="text-[11px] font-bold text-[var(--ink-muted)]">DETECTION RATE (TPR)</div>
            <div className="text-3xl font-bold mt-1" style={{ color: "var(--signal-allow)" }}>
              {tprPct}%
            </div>
            <div className="text-[11px] text-[var(--ink-muted)] mt-1">
              {report.truePositives} TP / {report.falseNegatives} FN
            </div>
          </div>
          <div className="p-4 rounded-xl border-2 border-[var(--sculk-cyan)] bg-[var(--bg-card)]">
            <div className="text-[11px] font-bold text-[var(--ink-muted)]">FALSE-POSITIVE RATE (FPR)</div>
            <div className="text-3xl font-bold mt-1" style={{ color: "var(--sculk-cyan)" }}>
              {fprPct}%
            </div>
            <div className="text-[11px] text-[var(--ink-muted)] mt-1">
              {report.falsePositives} FP / {report.trueNegatives} TN
            </div>
          </div>
          <div className="p-4 rounded-xl border-2 border-[var(--signal-redact)] bg-[var(--bg-card)]">
            <div className="text-[11px] font-bold text-[var(--ink-muted)]">FAST-PATH P95 LATENCY</div>
            <div className="text-3xl font-bold mt-1" style={{ color: "var(--signal-redact)" }}>
              {report.p95LatencyMs.toFixed(2)}ms
            </div>
            <div className="text-[11px] text-[var(--ink-muted)] mt-1">BUDGET: &lt; 10ms ON WORKERS</div>
          </div>
          <div className="p-4 rounded-xl border-2 border-[var(--signal-accent)] bg-[var(--bg-card)]">
            <div className="text-[11px] font-bold text-[var(--ink-muted)]">CORPUS SIZE</div>
            <div className="text-3xl font-bold mt-1" style={{ color: "var(--signal-accent)" }}>
              {report.totalCases}
            </div>
            <div className="text-[11px] text-[var(--ink-muted)] mt-1">
              {report.licenses.length} SPDX-LICENSED SOURCES
            </div>
          </div>
        </div>

        {/* HONEST LIMITATIONS DISCLAIMER */}
        <div
          className="p-4 rounded-xl border-2 font-mono text-xs leading-relaxed"
          style={{
            borderColor: "var(--signal-redact)",
            backgroundColor: "var(--bg-warn)",
            color: "var(--text-warn)",
          }}
        >
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
                  <span style={{ color: "var(--signal-allow)" }}>
                    {stats.passed}/{stats.total} ({pct}%)
                  </span>
                </div>
                <div className="w-full h-3 rounded bg-[var(--bg-inset)] border border-[var(--border-ink)] overflow-hidden">
                  <div className="h-full bg-[#22c55e]" style={{ width: `${pct}%` }} />
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
            <thead
              className="border-b-2 border-[var(--border-ink)] uppercase"
              style={{ backgroundColor: "var(--badge-bg)", color: "var(--badge-text)" }}
            >
              <tr>
                <th className="p-3">Case ID</th>
                <th className="p-3">Category</th>
                <th className="p-3">Expected</th>
                <th className="p-3">Actual Verdict</th>
                <th className="p-3">Latency</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
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
                    <span
                      style={{ color: o.passed ? "var(--signal-allow)" : "var(--signal-block)" }}
                    >
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
                <span className="font-bold" style={{ color: "var(--sculk-cyan)" }}>
                  {lic.sourceId}
                </span>
                <span
                  className="px-2 py-0.5 rounded border font-bold"
                  style={{
                    backgroundColor: "var(--badge-bg)",
                    color: "var(--badge-text)",
                    borderColor: "var(--sculk-cyan)",
                  }}
                >
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