"use client";

import React, { useState } from "react";
import Link from "next/link";
import { BRAND } from "@warden/brand";
import { WardenCrestSvg } from "@/components/ui/WardenCrestSvg";
import {
  GateCodeWindow,
  SectionGateLabel,
  VerdictBadge,
} from "@/components/ui/GatehouseKit";
import { AttackSignatureMarquee } from "@/components/ui/SculkAtmosphere";
import { GatehouseScene } from "@/components/canvas/GatehouseScene";
import { ExtrudedTitle } from "@/components/canvas/title/ExtrudedTitle";
import { bakeSpriteToSvgDataUrl, type SpriteId } from "@/sprites/pixel-sprites";
import { playGatehouseSfx } from "@/lib/preferences-store";

const QUICKSTART_SNIPPETS = {
  typescript: {
    filename: "quickstart-gemini.ts",
    lang: "typescript",
    code: `import OpenAI from "openai";

// Change ONLY baseURL & apiKey — ${BRAND.name} routes to Gemini 2.5 Flash!
const client = new OpenAI({
  baseURL: "http://127.0.0.1:8787/v1",
  apiKey: "${BRAND.apiKeyPrefix}your_tenant_key",
  defaultHeaders: {
    "${BRAND.headerPrefix}-Provider": "gemini",
    "${BRAND.headerPrefix}-Provider-Key": process.env.GEMINI_API_KEY,
    "${BRAND.headerPrefix}-Session-Id": "sess_checkout_42",
  },
});

const response = await client.chat.completions.create({
  model: "gemini-3.5-flash-lite",
  messages: [{ role: "user", content: "Inspect this scroll at the gate!" }],
});`,
  },
  python: {
    filename: "quickstart_gemini.py",
    lang: "python",
    code: `import os
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8787/v1",
    api_key="${BRAND.apiKeyPrefix}your_tenant_key",
    default_headers={
        "${BRAND.headerPrefix}-Provider": "gemini",
        "${BRAND.headerPrefix}-Provider-Key": os.environ["GEMINI_API_KEY"],
    },
)

res = client.chat.completions.create(
    model="gemini-3.5-flash-lite",
    messages=[{"role": "user", "content": "Inspect this scroll at the gate!"}],
)
print(res.choices[0].message.content)`,
  },
  curl: {
    filename: "quickstart-curl.sh",
    lang: "bash",
    code: `curl -X POST http://127.0.0.1:8787/v1/chat/completions \\
  -H "Authorization: Bearer ${BRAND.apiKeyPrefix}your_tenant_key" \\
  -H "Content-Type: application/json" \\
  -H "${BRAND.headerPrefix}-Provider: gemini" \\
  -H "${BRAND.headerPrefix}-Provider-Key: $GEMINI_API_KEY" \\
  -d '{
    "model": "gemini-3.5-flash-lite",
    "messages": [{"role": "user", "content": "Inspect this scroll at the gate!"}]
  }'`,
  },
} as const;

const CAST_DETAILS: Record<
  string,
  { sprite: SpriteId; owasp: string; route: string; cta: string }
> = {
  gatekeeper: { sprite: "warden", owasp: "LLM06 Tool Firewall", route: "/app", cta: "Open Watchtower" },
  piiHound: { sprite: "sniffer", owasp: "LLM02 PII & Secrets", route: "/learn", cta: "Test X-Ray" },
  injectionRaven: { sprite: "hex", owasp: "LLM01 Prompt Injection", route: "/learn", cta: "Test Obfuscation" },
  auditTortoise: { sprite: "ledger", owasp: "SHA-256 Audit Chain", route: "/app", cta: "Tamper Demo" },
  budgetFrog: { sprite: "toll", owasp: "LLM10 Rate & Budgets", route: "/docs", cta: "View Limits" },
  cacheParrot: { sprite: "echo", owasp: "Tenant-Isolated Cache", route: "/docs", cta: "Cache Spec" },
  redTeamGoblin: { sprite: "imp", owasp: "Mutated Siege Mode", route: "/demo", cta: "Launch Siege" },
  policyFox: { sprite: "quill", owasp: "YAML Policy Copilot", route: "/app", cta: "Open Policy Lab" },
};

const CASCADE_STAGES = [
  {
    step: "STAGE 01",
    name: "De-Obfuscation Normalizer",
    latency: "< 5ms",
    summary:
      "Strips zero-width Unicode smuggling, folds Cyrillic/Greek homoglyphs to ASCII, and recursively decodes Base64/Hex/URL payloads before rules run.",
    accent: "var(--sculk-cyan)",
  },
  {
    step: "STAGE 02",
    name: "Deterministic Rules Engine",
    latency: "< 15ms",
    summary:
      "Luhn-verified credit cards, reversible PII tokens ([REDACTED_EMAIL_1]), Shannon-entropy AWS/Gemini/PEM secret scanners, and injection signatures.",
    accent: "var(--signal-allow)",
  },
  {
    step: "STAGE 03",
    name: "Weighted Feature Classifier",
    latency: "< 20ms",
    summary:
      "Scores structural risk [0.0–0.99]. Clean traffic (< 0.45) exits at zero LLM cost; obvious attacks (>= 0.80) block immediately without calling an external judge.",
    accent: "var(--signal-redact)",
  },
  {
    step: "STAGE 04",
    name: "Gray-Zone Gemini LLM Judge",
    latency: "< 1200ms",
    summary:
      "Invoked strictly for ambiguous scores [0.45–0.80) with Zod-validated JSON verdicts, per-tenant daily USD budgets, and fail-closed/fail-open controls.",
    accent: "var(--signal-accent)",
  },
];

const SECURITY_PILLARS = [
  {
    badge: "PILLAR 01",
    title: "Drop-In Gemini & OpenAI Edge Proxy",
    desc: "Switch only your baseURL and API key. Stored provider keys are encrypted at rest with AES-256-GCM + unique IVs, and custom endpoints pass a strict IPv4/IPv6 SSRF guard blocking localhost and 169.254.169.254 cloud metadata.",
  },
  {
    badge: "PILLAR 02",
    title: "Sliding-Window SSE Stream Cutoff",
    desc: "Maintains a rolling 512-character window across Server-Sent Event delta chunks so AWS keys or system-prompt canary tokens split across multiple packets are caught and terminated cleanly mid-stream.",
  },
  {
    badge: "PILLAR 03",
    title: "Agent Tool-Call Firewall & Taint Tracking",
    desc: "Validates LLM tool_calls against allowlists and JSON Schemas, blocks path traversal / SSRF / shell injection / DROP TABLE, tracks untrusted tokens from role:'tool' outputs (Confused Deputy), and pauses risky tools for human approval.",
  },
  {
    badge: "PILLAR 04",
    title: "Policy-as-Code + Quill Copilot",
    desc: "Draft Zod-validated YAML policies from natural language with Quill, inspect structural diffs between versions, run shadow mode or historical dry-runs, and execute instant zero-downtime rollbacks.",
  },
  {
    badge: "PILLAR 05",
    title: "Imp Multi-Round Red-Team Siege",
    desc: "Strictly restricted to sandbox tenants (403 on production). Imp attacks your active policy across 6 OWASP categories, mutates blocked attacks (zero-width, homoglyph, Base64, roleplay), and generates validated YAML patches.",
  },
  {
    badge: "PILLAR 06",
    title: "SHA-256 Tamper-Evident Audit Ledger",
    desc: "Every decision is appended to a per-tenant SHA-256 hash chain, sealed into HMAC-SHA256 signed R2 batches, and verified via /admin/v1/audit/verify to pinpoint the exact corrupted sequence number on tampering.",
  },
];

const COMPARISON_ROWS = [
  {
    vector: "Base64 / Homoglyph Prompt Injection",
    unprotected: "Bypasses naive keyword checks & hijacks assistant",
    warden: "Stage 1 normalizes & decodes recursively -> Blocked in < 2ms",
  },
  {
    vector: "Customer Email & Visa Card in Prompt",
    unprotected: "Sent verbatim to third-party LLM logs",
    warden: "Reversibly masked ([REDACTED_EMAIL_1]) & restored on response",
  },
  {
    vector: "Poisoned Document -> send_email() Tool Call",
    unprotected: "Agent silently exfiltrates DB to attacker@evil.com",
    warden: "Confused-Deputy Taint Firewall intercepts with HTTP 403",
  },
  {
    vector: "AWS Key Leaked Across Split SSE Chunks",
    unprotected: "Streamed straight to end-user browser",
    warden: "512-char sliding SSE scanner terminates stream mid-flight",
  },
  {
    vector: "Duplicate High-Volume FAQ Prompts",
    unprotected: "Billed full upstream tokens on every request",
    warden: "Echo serves tenant & policy-isolated cache hit in < 2ms",
  },
  {
    vector: "Insider Edits Historical Security Logs",
    unprotected: "Silent database tampering goes unnoticed",
    warden: "SHA-256 chain breaks & pinpoints exact firstCorruptedSeq",
  },
];

export default function HomePage() {
  const [wardenMood, setWardenMood] = useState<"calm" | "sniffing" | "sonic_boom">("calm");
  const [sdkTab, setSdkTab] = useState<keyof typeof QUICKSTART_SNIPPETS>("typescript");

  const activeSnippet = QUICKSTART_SNIPPETS[sdkTab];

  return (
    <div className="space-y-12 pb-14">
      <AttackSignatureMarquee />

      <div className="max-w-7xl mx-auto px-4 space-y-16">
        {/* INTERACTIVE EXTRUDED VOXEL TITLE */}
        <ExtrudedTitle />

        {/* GATE 01: HERO SECTION (Fully Theme-Aware for Light & Dark Modes) */}
        <section
          className="gate-card p-6 sm:p-10 md:p-12 relative overflow-hidden"
          style={{
            backgroundImage:
              "linear-gradient(135deg, var(--bg-hero-from) 0%, var(--bg-hero-to) 100%)",
          }}
        >
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
            <div className="space-y-5 max-w-2xl">
              <SectionGateLabel gateNumber="01" title="THE DEEP DARK GATEHOUSE" />
              <h1 className="text-3xl sm:text-5xl md:text-6xl font-bold tracking-tight leading-[1.06]">
                A GATEHOUSE FOR YOUR AI.{" "}
                <span
                  className="underline decoration-4 underline-offset-8"
                  style={{ color: "var(--sculk-cyan)" }}
                >
                  EVERY PROMPT, INSPECTED.
                </span>
              </h1>
              <p className="text-sm sm:text-base md:text-lg text-[var(--ink-muted)] leading-relaxed">
                {BRAND.name} is an open-source, OpenAI-compatible security gateway built for{" "}
                <strong style={{ color: "var(--ink)" }}>Google Gemini</strong>, Groq, OpenRouter,
                and autonomous AI agents. Every prompt, SSE stream, and tool call passes through our
                4-stage Sculk cascade—catching obfuscated injections, masking PII reversibly,
                blocking Confused-Deputy attacks, and sealing a SHA-256 audit book.
              </p>

              {/* Verdict + Chiptune SFX Interactive Bar */}
              <div className="pt-1 flex flex-wrap items-center gap-2.5">
                <button
                  type="button"
                  onClick={() => {
                    setWardenMood("calm");
                    playGatehouseSfx("allow");
                  }}
                  className="cursor-pointer"
                >
                  <VerdictBadge action="allow" />
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setWardenMood("sniffing");
                    playGatehouseSfx("redact");
                  }}
                  className="cursor-pointer"
                >
                  <VerdictBadge action="redact" />
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setWardenMood("sonic_boom");
                    playGatehouseSfx("block");
                  }}
                  className="cursor-pointer"
                >
                  <VerdictBadge action="block" />
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setWardenMood("calm");
                    playGatehouseSfx("cache");
                  }}
                  className="cursor-pointer"
                >
                  <VerdictBadge action="allow" cached />
                </button>
              </div>

              <div className="pt-3 flex flex-wrap gap-3.5">
                <Link
                  href="/demo"
                  className="px-5 py-3 rounded-xl border-2 border-[#14121b] bg-[#29dfeb] text-[#041016] font-mono text-xs sm:text-sm font-bold uppercase shadow-[0_5px_0_#14121b] hover:translate-y-[-2px] transition-transform"
                >
                  ⚔ Launch Siege Mode Demo
                </Link>
                <Link
                  href="/app"
                  className="px-5 py-3 rounded-xl border-2 border-[var(--border-ink)] bg-[var(--bg-elevated)] font-mono text-xs sm:text-sm font-bold uppercase hover:translate-y-[-2px] transition-transform"
                >
                  Open Live Watchtower →
                </Link>
                <Link
                  href="/eval"
                  className="px-5 py-3 rounded-xl border-2 border-[var(--border-subtle)] bg-[var(--bg-card)] font-mono text-xs sm:text-sm font-bold uppercase hover:border-[var(--border-ink)] transition-colors"
                >
                  CI Benchmarks
                </Link>
              </div>
            </div>

            
            {/* Interactive Minecraft-Inspired Sculk Warden Emblem Card */}
            <div
              className="relative w-full lg:w-80 gate-card p-6 flex flex-col items-center text-center space-y-4 animate-gate-reveal"
              style={{ backgroundColor: "var(--bg-panel)" }}
            >
              {/* Floating Status Chips */}
              <span className="hidden sm:inline-flex items-center gap-1 px-2.5 py-1 rounded-full border-2 border-[#14121b] bg-[#22c55e] text-[#041016] font-mono text-[10px] font-bold uppercase shadow-[0_3px_0_#14121b] absolute -top-3 -left-3 animate-levitate">
                ● 4-STAGE ACTIVE
              </span>
              <span className="hidden sm:inline-flex items-center gap-1 px-2.5 py-1 rounded-full border-2 border-[#14121b] bg-[#29dfeb] text-[#041016] font-mono text-[10px] font-bold uppercase shadow-[0_3px_0_#14121b] absolute -bottom-3 -right-3 animate-levitate-delayed">
                ◆ SHA-256 SEALED
              </span>

              <div className="p-4 rounded-2xl border-2 border-[#29dfeb] bg-[#061c24] animate-levitate animate-sculk-glow">
                <WardenCrestSvg size={116} alertState={wardenMood} />
              </div>
              <div className="space-y-1">
                <div
                  className="font-mono text-xs font-bold uppercase tracking-widest"
                  style={{ color: "var(--sculk-cyan)" }}
                >
                  ■ HEAD GATEKEEPER
                </div>
                <h2 className="text-xl font-bold">
                  {BRAND.cast.gatekeeper.name} (Sculk Sentinel)
                </h2>
                <p className="text-xs font-mono text-[var(--ink-muted)]">
                  Click any verdict badge on the left to test {BRAND.name}&apos;s live Sculk
                  sensor mood &amp; 8-bit chiptune SFX!
                </p>
              </div>
            </div>
          </div>

          {/* Key Architecture Metrics Strip */}
          <div className="mt-8 pt-6 border-t-2 border-[var(--border-subtle)] grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 font-mono">
            {[
              { k: "FAST-PATH P95", v: "< 2.0ms" },
              { k: "CI EVAL TPR", v: "100.0%" },
              { k: "CI EVAL FPR", v: "0.0%" },
              { k: "KEY VAULT", v: "AES-256-GCM" },
              { k: "AUDIT BOOK", v: "SHA-256" },
              { k: "EDGE RUNTIME", v: "WORKERS + D1" },
            ].map((stat) => (
              <div
                key={stat.k}
                className="p-3 rounded-xl border-2 border-[var(--border-subtle)] bg-[var(--bg-card)]"
              >
                <div className="text-[10px] font-bold text-[var(--ink-muted)]">{stat.k}</div>
                <div className="text-base font-bold mt-0.5" style={{ color: "var(--sculk-cyan)" }}>
                  {stat.v}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* GATE 02: LIVE INTERACTIVE GATEHOUSE SIMULATION */}
        <section className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-2">
            <SectionGateLabel gateNumber="02" title="LIVE 3-LANE GATEHOUSE INSPECTION" />
            <p className="font-mono text-xs text-[var(--ink-muted)]">
              Real prompts evaluated server-side via <code>/api/demo/stream</code> SSE
            </p>
          </div>
          <GatehouseScene />
        </section>

        {/* GATE 03: 4-STAGE DETECTION CASCADE */}
        <section className="space-y-5">
          <div className="space-y-2">
            <SectionGateLabel gateNumber="03" title="4-STAGE CHEAP-TO-EXPENSIVE CASCADE" />
            <h2 className="text-2xl sm:text-3xl font-bold">
              Sub-2ms Fast Path. Gemini Judge Only When Needed.
            </h2>
            <p className="text-sm text-[var(--ink-muted)] max-w-3xl">
              Every request starts at the cheapest deterministic stage and short-circuits the moment
              a verdict is certain—protecting your latency budget and keeping LLM Judge costs near
              zero on clean traffic.
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            {CASCADE_STAGES.map((stage) => (
              <div key={stage.step} className="gate-card gate-card-interactive p-5 space-y-3">
                <div className="flex items-center justify-between font-mono text-xs font-bold">
                  <span
                    className="px-2 py-0.5 rounded border border-[#14121b] text-[#041016]"
                    style={{ backgroundColor: stage.accent }}
                  >
                    {stage.step}
                  </span>
                  <span className="text-[var(--ink-muted)]">BUDGET {stage.latency}</span>
                </div>
                <h3 className="text-lg font-bold">{stage.name}</h3>
                <p className="text-sm text-[var(--ink-muted)] leading-relaxed">{stage.summary}</p>
              </div>
            ))}
          </div>
        </section>

        {/* GATE 04: SIX ENTERPRISE SECURITY PILLARS */}
        <section className="space-y-5">
          <div className="space-y-2">
            <SectionGateLabel gateNumber="04" title="SIX CORE SECURITY PILLARS" />
            <h2 className="text-2xl sm:text-3xl font-bold">
              Defense-in-Depth Built for Production AI &amp; Autonomous Agents
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {SECURITY_PILLARS.map((pillar) => (
              <div key={pillar.badge} className="gate-card gate-card-interactive p-6 space-y-2.5">
                <span
                  className="inline-block font-mono text-[11px] font-bold uppercase px-2 py-0.5 rounded border"
                  style={{
                    backgroundColor: "var(--badge-bg)",
                    color: "var(--badge-text)",
                    borderColor: "var(--sculk-cyan)",
                  }}
                >
                  {pillar.badge}
                </span>
                <h3 className="text-xl font-bold">{pillar.title}</h3>
                <p className="text-sm text-[var(--ink-muted)] leading-relaxed">{pillar.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* GATE 05: UNPROTECTED VS WARDEN DEFENSE MATRIX */}
        <section className="space-y-5">
          <SectionGateLabel gateNumber="05" title="THREAT DEFENSE COMPARISON" />
          <div className="gate-card overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead
                className="border-b-2 border-[var(--border-ink)] uppercase"
                style={{ backgroundColor: "var(--badge-bg)", color: "var(--badge-text)" }}
              >
                <tr>
                  <th className="p-3.5">Attack / Failure Vector</th>
                  <th className="p-3.5">Direct to LLM (Unprotected)</th>
                  <th className="p-3.5">Protected by {BRAND.name}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {COMPARISON_ROWS.map((row) => (
                  <tr key={row.vector} className="hover:bg-[var(--bg-elevated)]">
                    <td className="p-3.5 font-bold">{row.vector}</td>
                    <td className="p-3.5" style={{ color: "var(--signal-block)" }}>
                      ✗ {row.unprotected}
                    </td>
                    <td className="p-3.5 font-semibold" style={{ color: "var(--signal-allow)" }}>
                      ✓ {row.warden}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* GATE 06: THE CAST OF PIXEL GUARDS */}
        <section className="space-y-5">
          <div className="space-y-2">
            <SectionGateLabel gateNumber="06" title="THE CAST OF PIXEL GUARDS" />
            <h2 className="text-2xl sm:text-3xl font-bold">
              Eight Specialized Sentinels Watching Every Layer
            </h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            {Object.entries(BRAND.cast).map(([key, guard]) => {
              const meta = CAST_DETAILS[key] ?? {
                sprite: "warden" as SpriteId,
                owasp: "Core Defense",
                route: "/app",
                cta: "Explore",
              };
              return (
                <div
                  key={key}
                  className="gate-card gate-card-interactive p-5 flex flex-col justify-between gap-4"
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between gap-2">
                      <div className="p-2 rounded-xl border-2 border-[#29dfeb] bg-[#061c24]">
                        <img
                          src={bakeSpriteToSvgDataUrl(meta.sprite, 4)}
                          alt={guard.name}
                          className="w-12 h-12"
                        />
                      </div>
                      <span
                        className="font-mono text-[11px] font-bold uppercase px-2.5 py-1 rounded border"
                        style={{
                          backgroundColor: "var(--badge-bg)",
                          color: "var(--badge-text)",
                          borderColor: "var(--sculk-cyan)",
                        }}
                      >
                        {guard.species}
                      </span>
                    </div>
                    <div>
                      <h3 className="text-xl font-bold">{guard.name}</h3>
                      <div
                        className="font-mono text-[11px] font-bold uppercase mt-0.5"
                        style={{ color: "var(--sculk-cyan)" }}
                      >
                        {meta.owasp}
                      </div>
                    </div>
                    <p className="text-sm text-[var(--ink-muted)] leading-relaxed">{guard.role}</p>
                  </div>
                  <Link
                    href={meta.route}
                    className="font-mono text-xs font-bold uppercase underline underline-offset-4"
                    style={{ color: "var(--sculk-cyan)" }}
                  >
                    {meta.cta} →
                  </Link>
                </div>
              );
            })}
          </div>
        </section>

        {/* GATE 07: MULTI-LANGUAGE DROP-IN QUICKSTART */}
        <section className="space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <SectionGateLabel gateNumber="07" title="2-LINE GEMINI QUICKSTART" />
            <div className="flex items-center gap-2 font-mono text-xs font-bold uppercase">
              {(["typescript", "python", "curl"] as const).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setSdkTab(tab)}
                  className="px-3 py-1.5 rounded-lg border-2 border-[var(--border-ink)] cursor-pointer"
                  style={
                    sdkTab === tab
                      ? { backgroundColor: "var(--badge-bg)", color: "var(--badge-text)" }
                      : { backgroundColor: "var(--bg-elevated)" }
                  }
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>
          <GateCodeWindow
            filename={activeSnippet.filename}
            code={activeSnippet.code}
            language={activeSnippet.lang}
          />
        </section>

        {/* GATE 08: EXPLORE THE FULL SUITE CTA */}
        <section className="gate-card p-8 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-xl">
            <SectionGateLabel gateNumber="08" title="TOUR THE FORTRESS" />
            <h2 className="text-2xl sm:text-3xl font-bold">
              Test Every Defense Live — Zero Setup Required
            </h2>
            <p className="text-sm text-[var(--ink-muted)]">
              Attack a weak policy with Imp on <code>/demo</code>, tamper with SHA-256 blocks on{" "}
              <code>/app</code>, inspect obfuscation tricks on <code>/learn</code>, or verify real
              CI benchmark metrics on <code>/eval</code>.
            </p>
          </div>
          <div className="flex flex-wrap gap-3 font-mono text-xs font-bold uppercase">
            <Link
              href="/demo"
              className="px-4 py-2.5 rounded-xl border-2 border-[#14121b] bg-[#29dfeb] text-[#041016]"
            >
              ⚔ Siege Demo
            </Link>
            <Link
              href="/learn"
              className="px-4 py-2.5 rounded-xl border-2 border-[var(--border-ink)] bg-[var(--bg-elevated)]"
            >
              Security Lab
            </Link>
            <Link
              href="/docs"
              className="px-4 py-2.5 rounded-xl border-2 border-[var(--border-ink)] bg-[var(--bg-card)]"
            >
              API Docs →
            </Link>
          </div>
        </section>
        {/* GATEHOUSE SIGNATURE FOOTER (HOME PAGE ONLY) */}
        <footer className="gate-card p-6 sm:p-8 text-center space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-center gap-3">
            <div className="p-1.5 rounded-xl border-2 border-[#29dfeb] bg-[#061c24] animate-levitate">
              <WardenCrestSvg size={28} />
            </div>
            <span
              className="font-mono text-xs font-bold uppercase tracking-widest"
              style={{ color: "var(--sculk-cyan)" }}
            >
              ■ DEEP DARK WATCH — NEVER ASLEEP
            </span>
          </div>
          <p className="text-lg sm:text-2xl font-bold tracking-tight">
            &ldquo;Prompts whisper. Injections hide.{" "}
            <span style={{ color: "var(--sculk-cyan)" }}>Warden hears every vibration.</span>&rdquo;
          </p>
          <p className="font-mono text-xs sm:text-sm text-[var(--ink-muted)]">
            Crafted with precision &amp; Sculk-grade paranoia —{" "}
            <strong className="text-[var(--ink)] underline decoration-2 underline-offset-4">
              Made by Gaurav Joshi
            </strong>
          </p>
        </footer>
      </div>
    </div>
  );
}