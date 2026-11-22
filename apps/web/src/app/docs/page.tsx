"use client";

import React, { useState } from "react";
import { BRAND } from "@warden/brand";
import { GateCodeWindow, SectionGateLabel } from "@/components/ui/GatehouseKit";
import { WardenCrestSvg } from "@/components/ui/WardenCrestSvg";

const CURL_SNIPPET = `curl -X POST http://127.0.0.1:8787/v1/chat/completions \\
  -H "Authorization: Bearer ${BRAND.apiKeyPrefix}your_tenant_key" \\
  -H "Content-Type: application/json" \\
  -H "${BRAND.headerPrefix}-Provider: gemini" \\
  -H "${BRAND.headerPrefix}-Provider-Key: $GEMINI_API_KEY" \\
  -d '{
    "model": "gemini-2.5-flash",
    "messages": [
      { "role": "user", "content": "Explain Cloudflare Durable Objects in 2 sentences." }
    ]
  }'`;

const FULL_POLICY_YAML = `version: "1.0"
name: "production-fortress"
mode: "enforce"          # "enforce" | "shadow"
failMode: "closed"       # "closed" | "open" on Stage 4 Judge timeout

stageBudgetsMs:
  normalizer: 5
  rules: 15
  classifier: 150
  llmJudge: 1200

detectors:
  pii:
    enabled: true
    action: "redact"     # "allow" | "redact" | "block" | "flag"
    restoreOnResponse: true
    types: ["email", "phone", "credit_card", "iban", "ssn_us"]
  secrets:
    enabled: true
    action: "block"
    entropyThreshold: 4.3
  injection:
    enabled: true
    action: "block"
    classifierThreshold: 0.80
    judgeGrayZone: [0.45, 0.80]
  canary:
    enabled: true
    action: "block"

semanticCache:
  enabled: true
  similarityThreshold: 0.92
  ttlSeconds: 3600

toolFirewall:
  enabled: true
  defaultAction: "block"
  tools:
    - name: "read_file"
      allowed: true
      requireApproval: false
      denyPatterns: ["path_traversal", "shell_metacharacters"]
    - name: "send_email"
      allowed: true
      requireApproval: true
      blockUntrustedTaint: true
      argumentJsonSchema:
        required: ["to", "body"]
        properties:
          to: { type: "string" }
          body: { type: "string" }`;

const DEPLOY_COMMANDS = `# 1. Install workspace dependencies
pnpm install

# 2. Run strict TypeScript checks & full Vitest + Eval CI gate
pnpm typecheck
pnpm test

# 3. Run Gateway (127.0.0.1:8787) + Web Dashboard (localhost:3000) locally
pnpm dev

# 4. Deploy Gateway to Cloudflare Workers + D1
pnpm --filter @warden/gateway exec wrangler d1 migrations apply warden-db --remote
pnpm --filter @warden/gateway exec wrangler deploy`;

const HEADERS_SPEC = [
  { header: `${BRAND.headerPrefix}-Provider`, dir: "Request", desc: "Upstream adapter: gemini (default), openai_compatible, groq, openrouter." },
  { header: `${BRAND.headerPrefix}-Provider-Key`, dir: "Request", desc: "Optional ephemeral provider key (overrides AES-256-GCM stored credential)." },
  { header: `${BRAND.headerPrefix}-Provider-Base-Url`, dir: "Request", desc: "Custom upstream URL for openai_compatible (protected by SSRF IPv4/IPv6 guard)." },
  { header: `${BRAND.headerPrefix}-Project-Id`, dir: "Request", desc: "Routes request through a project-level policy override if configured." },
  { header: `${BRAND.headerPrefix}-Session-Id`, dir: "Request", desc: "Links multi-turn agent calls into a session taint graph." },
  { header: `${BRAND.headerPrefix}-Action`, dir: "Response", desc: "Final enforcement action: allow, redact, block, flag, or shadow." },
  { header: `${BRAND.headerPrefix}-Cache`, dir: "Response", desc: "Echo Semantic Cache status: HIT or MISS (strictly tenant + policy isolated)." },
  { header: `${BRAND.headerPrefix}-RateLimit-Remaining-RPM`, dir: "Response", desc: "Remaining requests in the current Toll token-bucket window." },
  { header: `${BRAND.headerPrefix}-Signature-256`, dir: "Webhook", desc: "HMAC-SHA256 hex signature (sha256=...) verifying webhook authenticity." },
];

const ADMIN_ENDPOINTS = [
  { method: "POST", path: "/v1/chat/completions", scope: "proxy:write", desc: "OpenAI-compatible proxy endpoint (streaming SSE & JSON + Tool Firewall)." },
  { method: "GET", path: "/admin/v1/requests/:id", scope: "admin:read", desc: "Fetch tenant-scoped request log." },
  { method: "GET", path: "/admin/v1/requests/:id/explain", scope: "admin:read", desc: "Grounded Incident Explainer citing verified finding IDs." },
  { method: "POST", path: "/admin/v1/policies/:id/versions", scope: "admin:write", desc: "Validate & save immutable YAML/JSON policy version." },
  { method: "GET", path: "/admin/v1/policies/:id/diff", scope: "admin:read", desc: "Structural diff between ?from=1&to=2." },
  { method: "POST", path: "/admin/v1/policies/:id/rollback", scope: "admin:write", desc: "Instant zero-downtime rollback to any historical version." },
  { method: "POST", path: "/admin/v1/policies/dry-run", scope: "admin:write", desc: "Replay candidate policy against historical tenant traffic." },
  { method: "PUT", path: "/admin/v1/budgets", scope: "admin:write", desc: "Update Toll RPM, daily token, and monthly USD limits." },
  { method: "GET", path: "/admin/v1/audit/verify", scope: "admin:read", desc: "Verify SHA-256 audit chain and pinpoint firstCorruptedSeq." },
  { method: "POST", path: "/admin/v1/audit/seal", scope: "admin:write", desc: "Seal audit records into an HMAC-signed R2 archive batch." },
  { method: "GET", path: "/admin/v1/approvals", scope: "admin:read", desc: "List held high-risk agent tool calls awaiting human sign-off." },
  { method: "POST", path: "/admin/v1/approvals/:id/decide", scope: "admin:write", desc: "Approve or reject a pending tool call." },
  { method: "POST", path: "/admin/v1/redteam/siege", scope: "admin:write", desc: "Run Imp multi-round mutated Siege Mode (sandbox tenants only)." },
  { method: "POST", path: "/admin/v1/redteam/copilot/draft", scope: "admin:write", desc: "Draft validated policy YAML with Quill + dry-run diff." },
  { method: "GET", path: "/eval/summary", scope: "public", desc: "Live TPR/FPR/latency benchmark JSON from @warden/eval." },
];

export default function DocsPage() {
  const [section, setSection] = useState<"quickstart" | "policy" | "api" | "deploy">("quickstart");

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* HEADER */}
      <div className="gate-card p-6 sm:p-8 bg-[#061c24] border-[#29dfeb] text-[#f3ecdc] flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
        <div className="flex items-center gap-4">
          <WardenCrestSvg size={52} />
          <div>
            <SectionGateLabel gateNumber="DOCS" title="DEVELOPER REFERENCE & SELF-HOSTING" />
            <h1 className="text-2xl sm:text-4xl font-bold mt-1">
              {BRAND.name} Gateway Documentation
            </h1>
          </div>
        </div>
        <a
          href="/llms.txt"
          target="_blank"
          rel="noreferrer"
          className="px-4 py-2 rounded-xl border-2 border-[#29dfeb] bg-[#082732] text-[#7df9ff] font-mono text-xs font-bold uppercase hover:bg-[#0b4f60]"
        >
          🤖 View /llms.txt
        </a>
      </div>

      {/* SECTION TABS */}
      <div className="flex flex-wrap gap-2 font-mono text-xs font-bold uppercase">
        {[
          { id: "quickstart", label: "1. Quickstart & Headers" },
          { id: "policy", label: "2. Policy-as-Code YAML" },
          { id: "api", label: "3. REST & Admin API" },
          { id: "deploy", label: "4. Self-Hosting & Workers" },
        ].map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setSection(t.id as typeof section)}
            className={`px-4 py-2 rounded-xl border-2 cursor-pointer ${
              section === t.id
                ? "border-[#14121b] bg-[#29dfeb] text-[#041016] shadow-[0_4px_0_#14121b]"
                : "border-[var(--border-ink)] bg-[var(--bg-elevated)]"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* TAB 1: QUICKSTART & HEADERS */}
      {section === "quickstart" && (
        <div className="space-y-8">
          <GateCodeWindow filename="curl-gemini-proxy.sh" code={CURL_SNIPPET} language="bash" />

          <div className="gate-card overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-[#061c24] text-[#7df9ff] border-b-2 border-[var(--border-ink)] uppercase">
                <tr>
                  <th className="p-3">Header</th>
                  <th className="p-3">Direction</th>
                  <th className="p-3">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-ink)]/20">
                {HEADERS_SPEC.map((h) => (
                  <tr key={h.header}>
                    <td className="p-3 font-bold text-[#29dfeb] whitespace-nowrap">{h.header}</td>
                    <td className="p-3 uppercase">{h.dir}</td>
                    <td className="p-3">{h.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: POLICY YAML */}
      {section === "policy" && (
        <div className="space-y-4">
          <p className="text-sm text-[var(--ink-muted)]">
            Every policy is validated strictly with Zod (<code>@warden/policy-schema</code>),
            versioned immutably, diffable, and supports shadow mode and instant rollback.
          </p>
          <GateCodeWindow filename="warden.policy.yaml" code={FULL_POLICY_YAML} language="yaml" />
        </div>
      )}

      {/* TAB 3: API ENDPOINTS */}
      {section === "api" && (
        <div className="gate-card overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-[#061c24] text-[#7df9ff] border-b-2 border-[var(--border-ink)] uppercase">
              <tr>
                <th className="p-3">Method</th>
                <th className="p-3">Path</th>
                <th className="p-3">Scope</th>
                <th className="p-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-ink)]/20">
              {ADMIN_ENDPOINTS.map((ep) => (
                <tr key={`${ep.method}-${ep.path}`}>
                  <td className="p-3 font-bold text-[#2fd27a]">{ep.method}</td>
                  <td className="p-3 font-bold whitespace-nowrap">{ep.path}</td>
                  <td className="p-3 text-[#ffb300]">{ep.scope}</td>
                  <td className="p-3">{ep.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 4: SELF-HOSTING */}
      {section === "deploy" && (
        <div className="space-y-5">
          <GateCodeWindow filename="deploy-warden.sh" code={DEPLOY_COMMANDS} language="bash" />
          <div className="gate-card p-6 space-y-2 text-sm">
            <h2 className="font-bold text-lg">Monorepo Architecture</h2>
            <ul className="list-disc pl-5 space-y-1 font-mono text-xs text-[var(--ink-muted)]">
              <li><strong>packages/brand</strong>: Shared identity, headers, API key prefix, and cast metadata.</li>
              <li><strong>packages/policy-schema</strong>: Zod policy v1.0 schema, YAML parser, and structural diff engine.</li>
              <li><strong>packages/detectors</strong>: Stage 1 normalizer, Luhn PII redactor, Shannon entropy secret scanner, injection rules, and canary tokens.</li>
              <li><strong>packages/eval</strong>: SPDX-licensed adversarial &amp; benign corpus with CI TPR/FPR regression gate.</li>
              <li><strong>apps/gateway</strong>: Hono edge gateway (Cloudflare Workers + D1 SQLite + Durable Objects).</li>
              <li><strong>apps/web</strong>: Next.js 15 App Router Gatehouse showcase &amp; security watchtower dashboard.</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}