"use client";

import React, { useEffect, useState, useCallback } from "react";
import { BRAND } from "@warden/brand";
import { playGatehouseSfx } from "@/lib/preferences-store";

interface ListedKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  revokedAt: number | null;
  createdAt: number;
}

interface ListedCredential {
  id: string;
  provider: string;
  baseUrl: string | null;
  createdAt: number;
}

interface LiveProxyResponse {
  status: number;
  action: string;
  cache: string;
  requestId: string;
  replyText: string;
  rawJson: string;
}

const STORAGE_KEY_API = "warden_local_wrd_key";
const STORAGE_KEY_URL = "warden_local_gateway_url";
const DEFAULT_MODEL_BY_PROVIDER: Record<
  "gemini" | "groq" | "openrouter" | "openai_compatible",
  { model: string; placeholder: string }
> = {
  gemini: { model: "gemini-3.5-flash-lite", placeholder: "Paste Gemini API key (AIza...)" },
  groq: { model: "llama-3.3-70b-versatile", placeholder: "Paste Groq API key (gsk_...)" },
  openrouter: { model: "google/gemini-3.5-flash-lite", placeholder: "Paste OpenRouter key (sk-or-...)" },
  openai_compatible: { model: "gpt-4o-mini", placeholder: "Paste OpenAI-compatible key (sk-...)" },
};
export function KeysVaultTab() {
  const [gatewayUrl, setGatewayUrl] = useState("http://127.0.0.1:8787");
  const [gatewayStatus, setGatewayStatus] = useState<"checking" | "online" | "offline">("checking");

  // Active Tenant wrd_ key
  const [activeApiKey, setActiveApiKey] = useState("");
  const [tenantName, setTenantName] = useState("Gaurav's AI Gatehouse");
  const [isSandbox, setIsSandbox] = useState(true);
  const [freshKeyBanner, setFreshKeyBanner] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<{ kind: "ok" | "err"; text: string } | null>(
    null
  );

  // Listed D1 keys & provider credentials
  const [keys, setKeys] = useState<ListedKey[]>([]);
  const [newKeyName, setNewKeyName] = useState("Production App Key");
  const [credentials, setCredentials] = useState<ListedCredential[]>([]);

  // Provider Vault form
  const [provider, setProvider] = useState<"gemini" | "groq" | "openrouter" | "openai_compatible">(
    "gemini"
  );
  const [providerApiKey, setProviderApiKey] = useState("");
  const [providerBaseUrl, setProviderBaseUrl] = useState("");

  // Live End-to-End Proxy Tester
  const [testModel, setTestModel] = useState("gemini-3.5-flash-lite");
  const [testPrompt, setTestPrompt] = useState(
    "Explain why SHA-256 hash chains protect audit logs in 2 sentences."
  );
  const [sendingTest, setSendingTest] = useState(false);
  const [liveResult, setLiveResult] = useState<LiveProxyResponse | null>(null);

  // Restore saved local gateway URL & wrd_ key
  useEffect(() => {
    const savedUrl = localStorage.getItem(STORAGE_KEY_URL);
    const savedKey = localStorage.getItem(STORAGE_KEY_API);
    if (savedUrl) setGatewayUrl(savedUrl);
    if (savedKey) setActiveApiKey(savedKey);
  }, []);

  const checkHealth = useCallback(async (urlToTest: string) => {
    setGatewayStatus("checking");
    try {
      const res = await fetch(`${urlToTest.replace(/\/$/, "")}/healthz`);
      setGatewayStatus(res.ok ? "online" : "offline");
    } catch {
      setGatewayStatus("offline");
    }
  }, []);

  const refreshVaultLists = useCallback(
    async (baseUrl: string, key: string) => {
      if (!key.trim()) return;
      const cleanBase = baseUrl.replace(/\/$/, "");
      try {
        const [kRes, cRes] = await Promise.all([
          fetch(`${cleanBase}/admin/v1/vault/keys`, {
            headers: { Authorization: `Bearer ${key}` },
          }),
          fetch(`${cleanBase}/admin/v1/vault/credentials`, {
            headers: { Authorization: `Bearer ${key}` },
          }),
        ]);
        if (kRes.ok) {
          const kJson = (await kRes.json()) as { data: ListedKey[] };
          setKeys(kJson.data);
        }
        if (cRes.ok) {
          const cJson = (await cRes.json()) as { data: ListedCredential[] };
          setCredentials(cJson.data);
        }
      } catch {
        // Gateway offline
      }
    },
    []
  );

  useEffect(() => {
    checkHealth(gatewayUrl);
  }, [gatewayUrl, checkHealth]);

  useEffect(() => {
    if (gatewayStatus === "online" && activeApiKey) {
      refreshVaultLists(gatewayUrl, activeApiKey);
    }
  }, [gatewayStatus, gatewayUrl, activeApiKey, refreshVaultLists]);

  const handleBootstrapTenant = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMessage(null);
    const cleanBase = gatewayUrl.replace(/\/$/, "");
    try {
      const res = await fetch(`${cleanBase}/bootstrap/tenant`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: tenantName.trim(), isSandbox }),
      });
      const json = (await res.json()) as {
        data?: { apiKey: string; tenantId: string; name: string };
        error?: { message: string };
      };
      if (!res.ok || !json.data) {
        setStatusMessage({
          kind: "err",
          text: json.error?.message ?? "Bootstrap failed — ensure D1 local migrations are applied.",
        });
        playGatehouseSfx("block");
        return;
      }

      setActiveApiKey(json.data.apiKey);
      setFreshKeyBanner(json.data.apiKey);
      localStorage.setItem(STORAGE_KEY_API, json.data.apiKey);
      localStorage.setItem(STORAGE_KEY_URL, cleanBase);
      setStatusMessage({
        kind: "ok",
        text: `Tenant '${json.data.name}' (${json.data.tenantId}) created in D1! Copy your wrd_ key below.`,
      });
      playGatehouseSfx("allow");
      await refreshVaultLists(cleanBase, json.data.apiKey);
    } catch {
      setStatusMessage({
        kind: "err",
        text: "Could not reach gateway. Run `pnpm dev` so Wrangler is listening on http://127.0.0.1:8787.",
      });
    }
  };

  const handleIssueExtraKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeApiKey || !newKeyName.trim()) return;
    const cleanBase = gatewayUrl.replace(/\/$/, "");
    const res = await fetch(`${cleanBase}/admin/v1/vault/keys`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${activeApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: newKeyName.trim(),
        scopes: ["proxy:write", "admin:read"],
        isSandbox,
      }),
    });
    const json = (await res.json()) as { data?: { rawKey: string }; error?: { message: string } };
    if (!res.ok || !json.data) {
      setStatusMessage({ kind: "err", text: json.error?.message ?? "Failed to create key" });
      return;
    }
    setFreshKeyBanner(json.data.rawKey);
    setStatusMessage({ kind: "ok", text: "New scoped wrd_ key issued (shown once below)." });
    playGatehouseSfx("allow");
    await refreshVaultLists(cleanBase, activeApiKey);
  };

  const handleRevokeKey = async (keyId: string) => {
    const cleanBase = gatewayUrl.replace(/\/$/, "");
    await fetch(`${cleanBase}/admin/v1/vault/keys/${keyId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${activeApiKey}` },
    });
    playGatehouseSfx("block");
    await refreshVaultLists(cleanBase, activeApiKey);
  };

  const handleSaveProviderCred = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeApiKey || !providerApiKey.trim()) return;
    setStatusMessage(null);
    const cleanBase = gatewayUrl.replace(/\/$/, "");

    const body: Record<string, string> = {
      provider,
      apiKey: providerApiKey.trim(),
    };
    if (provider === "openai_compatible" && providerBaseUrl.trim()) {
      body.baseUrl = providerBaseUrl.trim();
    }

    const res = await fetch(`${cleanBase}/admin/v1/vault/credentials`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${activeApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    const json = (await res.json()) as { error?: { message: string } };
    if (!res.ok) {
      setStatusMessage({
        kind: "err",
        text: json.error?.message ?? "Failed to save provider key",
      });
      playGatehouseSfx("block");
      return;
    }

    setProviderApiKey("");
    setStatusMessage({
      kind: "ok",
      text: `Encrypted ${provider.toUpperCase()} API key saved in D1 (AES-256-GCM)!`,
    });
    playGatehouseSfx("sculk_ping");
    await refreshVaultLists(cleanBase, activeApiKey);
  };

  const handleLiveGeminiTest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeApiKey || !testPrompt.trim()) return;
    setSendingTest(true);
    setLiveResult(null);
    const cleanBase = gatewayUrl.replace(/\/$/, "");

    try {
      const res = await fetch(`${cleanBase}/v1/chat/completions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${activeApiKey}`,
          "Content-Type": "application/json",
          [`${BRAND.headerPrefix}-Provider`]: provider,
        },
        body: JSON.stringify({
          model: testModel,
          messages: [{ role: "user", content: testPrompt }],
        }),
      });

      const action = res.headers.get(`${BRAND.headerPrefix}-Action`) ?? "unknown";
      const cache = res.headers.get(`${BRAND.headerPrefix}-Cache`) ?? "MISS";
      const requestId = res.headers.get(`${BRAND.headerPrefix}-Request-Id`) ?? "n/a";
      const data = (await res.json()) as
        | {
            choices?: { message?: { content?: string } }[];
            error?: { message?: string };
          }
        | { error?: { message?: string } }[];

      const arrayError = Array.isArray(data) ? data[0]?.error?.message : undefined;
      const objectChoice = !Array.isArray(data) ? data.choices?.[0]?.message?.content : undefined;
      const objectError = !Array.isArray(data) ? data.error?.message : undefined;

      const replyText =
        objectChoice ??
        objectError ??
        arrayError ??
        JSON.stringify(data, null, 2);

      setLiveResult({
        status: res.status,
        action,
        cache,
        requestId,
        replyText,
        rawJson: JSON.stringify(data, null, 2),
      });
      playGatehouseSfx(res.status === 403 ? "block" : cache === "HIT" ? "cache" : "allow");
    } catch (err) {
      setLiveResult({
        status: 0,
        action: "network_error",
        cache: "N/A",
        requestId: "n/a",
        replyText: err instanceof Error ? err.message : "Failed to reach gateway",
        rawJson: "{}",
      });
    } finally {
      setSendingTest(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Gateway Connection Bar */}
      <div className="gate-card p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="font-mono text-xs font-bold uppercase" style={{ color: "var(--sculk-cyan)" }}>
            ■ LIVE D1 GATEWAY CONNECTION
          </div>
          <p className="text-xs font-mono text-[var(--ink-muted)]">
            Connect directly to your running Cloudflare Worker / local Miniflare D1 gateway.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="url"
            value={gatewayUrl}
            onChange={(e) => {
              setGatewayUrl(e.target.value);
              localStorage.setItem(STORAGE_KEY_URL, e.target.value);
            }}
            aria-label="Warden Gateway Base URL"
            className="w-60 px-3 py-2 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-inset)] text-[var(--ink)] font-mono text-xs"
          />
          <button
            type="button"
            onClick={() => checkHealth(gatewayUrl)}
            className="px-3 py-2 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-elevated)] font-mono text-xs font-bold uppercase cursor-pointer"
          >
            Check Health
          </button>
          <span
            className="px-3 py-2 rounded-lg border-2 font-mono text-xs font-bold uppercase"
            style={
              gatewayStatus === "online"
                ? {
                    backgroundColor: "var(--bg-ok)",
                    color: "var(--text-ok)",
                    borderColor: "var(--signal-allow)",
                  }
                : {
                    backgroundColor: "var(--bg-danger)",
                    color: "var(--text-danger)",
                    borderColor: "var(--signal-block)",
                  }
            }
          >
            {gatewayStatus === "online"
              ? "● GATEWAY ONLINE"
              : gatewayStatus === "checking"
              ? "… CHECKING"
              : "✗ GATEWAY OFFLINE"}
          </span>
        </div>
      </div>

      {/* Status & One-Time Key Reveal Banner */}
      {statusMessage && (
        <div
          className="p-4 rounded-xl border-2 font-mono text-xs font-bold"
          style={
            statusMessage.kind === "ok"
              ? {
                  backgroundColor: "var(--bg-ok)",
                  color: "var(--text-ok)",
                  borderColor: "var(--signal-allow)",
                }
              : {
                  backgroundColor: "var(--bg-danger)",
                  color: "var(--text-danger)",
                  borderColor: "var(--signal-block)",
                }
          }
        >
          {statusMessage.text}
        </div>
      )}

      {freshKeyBanner && (
        <div
          className="p-4 rounded-xl border-2 space-y-2 font-mono text-xs"
          style={{
            backgroundColor: "var(--bg-warn)",
            color: "var(--text-warn)",
            borderColor: "var(--signal-redact)",
          }}
        >
          <div className="font-bold uppercase">
            🔑 COPY THIS KEY NOW (SHOWN ONCE — ONLY ITS SHA-256 HASH IS SAVED IN D1):
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <code className="px-3 py-1.5 rounded bg-[var(--bg-card)] text-[var(--ink)] border border-[var(--border-ink)] break-all">
              {freshKeyBanner}
            </code>
            <button
              type="button"
              onClick={() => navigator.clipboard.writeText(freshKeyBanner)}
              className="px-3 py-1.5 rounded border-2 border-[#14121b] bg-[#29dfeb] text-[#041016] font-bold uppercase cursor-pointer"
            >
              Copy Key
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* LEFT: Step 1 (Bootstrap Tenant) & Step 2 (Manage wrd_ Keys) */}
        <div className="lg:col-span-6 space-y-6">
          <div className="gate-card p-6 space-y-4">
            <h2 className="text-lg font-bold font-mono uppercase">
              1. Bootstrap Tenant &amp; Active <code>wrd_</code> Key
            </h2>
            <form onSubmit={handleBootstrapTenant} className="space-y-3">
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="text"
                  value={tenantName}
                  onChange={(e) => setTenantName(e.target.value)}
                  placeholder="Tenant / Organization Name"
                  className="flex-1 px-3 py-2 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-inset)] text-[var(--ink)] font-mono text-xs"
                />
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg border-2 border-[#14121b] bg-[#29dfeb] text-[#041016] font-mono text-xs font-bold uppercase cursor-pointer shrink-0"
                >
                  + Create Tenant &amp; Key
                </button>
              </div>
              <label className="inline-flex items-center gap-2 font-mono text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={isSandbox}
                  onChange={(e) => setIsSandbox(e.target.checked)}
                />
                <span>Enable Sandbox Mode (allows Imp Siege Mode red-teaming)</span>
              </label>
            </form>

            <div className="pt-3 border-t-2 border-[var(--border-subtle)] space-y-2">
              <label className="block font-mono text-xs font-bold text-[var(--ink-muted)]">
                Active Warden Tenant Key (stored locally in browser for this console):
              </label>
              <input
                type="password"
                value={activeApiKey}
                onChange={(e) => {
                  setActiveApiKey(e.target.value);
                  localStorage.setItem(STORAGE_KEY_API, e.target.value);
                }}
                placeholder="wrd_..."
                className="w-full px-3 py-2 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-inset)] text-[var(--ink)] font-mono text-xs"
              />
            </div>
          </div>

          {/* Manage wrd_ Keys in D1 */}
          <div className="gate-card p-6 space-y-4">
            <h2 className="text-lg font-bold font-mono uppercase">
              2. Issued <code>wrd_</code> API Keys ({keys.length})
            </h2>
            <form onSubmit={handleIssueExtraKey} className="flex gap-2">
              <input
                type="text"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="Key label (e.g. Backend Service)"
                className="flex-1 px-3 py-2 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-inset)] text-[var(--ink)] font-mono text-xs"
              />
              <button
                type="submit"
                disabled={!activeApiKey}
                className="px-3.5 py-2 rounded-lg border-2 border-[#14121b] bg-[#22c55e] text-[#041016] font-mono text-xs font-bold uppercase cursor-pointer disabled:opacity-40"
              >
                + Issue Key
              </button>
            </form>

            <div className="space-y-2">
              {keys.length === 0 ? (
                <p className="font-mono text-xs text-[var(--ink-muted)]">
                  No keys loaded yet. Bootstrap a tenant above to mint your first <code>wrd_</code> key.
                </p>
              ) : (
                keys.map((k) => (
                  <div
                    key={k.id}
                    className="p-3 rounded-xl border-2 border-[var(--border-subtle)] bg-[var(--bg-panel)] flex items-center justify-between gap-2 font-mono text-xs"
                  >
                    <div className="min-w-0">
                      <div className="font-bold truncate">
                        {k.name} <span style={{ color: "var(--sculk-cyan)" }}>({k.prefix}…)</span>
                      </div>
                      <div className="text-[11px] text-[var(--ink-muted)]">
                        Scopes: {k.scopes.join(", ")} • {k.revokedAt ? "REVOKED" : "ACTIVE"}
                      </div>
                    </div>
                    {!k.revokedAt && (
                      <button
                        type="button"
                        onClick={() => handleRevokeKey(k.id)}
                        className="px-2.5 py-1 rounded border-2 border-[#14121b] bg-[#ef4444] text-white text-[11px] font-bold uppercase cursor-pointer"
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* RIGHT: Step 3 (AES-256-GCM Provider Vault) & Step 4 (Live Gemini Proxy Test) */}
        <div className="lg:col-span-6 space-y-6">
          <div className="gate-card p-6 space-y-4">
            <h2 className="text-lg font-bold font-mono uppercase">
              3. Save Upstream Provider Key (AES-256-GCM Vault)
            </h2>
            <p className="text-xs font-mono text-[var(--ink-muted)]">
              Bring your own Gemini / Groq / OpenRouter key. Warden encrypts it with AES-256-GCM +
              random IV in D1 before storing.
            </p>
            <form onSubmit={handleSaveProviderCred} className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <select
                  value={provider}
                  onChange={(e) => {
                    const next = e.target.value as typeof provider;
                    setProvider(next);
                    setTestModel(DEFAULT_MODEL_BY_PROVIDER[next].model);
                  }}
                  className="px-3 py-2 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-inset)] text-[var(--ink)] font-mono text-xs font-bold"
                >
                  <option value="gemini">Gemini (Default)</option>
                  <option value="groq">Groq</option>
                  <option value="openrouter">OpenRouter</option>
                  <option value="openai_compatible">OpenAI-Compatible</option>
                </select>
                <input
                  type="password"
                  value={providerApiKey}
                  onChange={(e) => setProviderApiKey(e.target.value)}
                  placeholder={DEFAULT_MODEL_BY_PROVIDER[provider].placeholder}
                  className="sm:col-span-2 px-3 py-2 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-inset)] text-[var(--ink)] font-mono text-xs"
                />
                
              </div>

              {provider === "openai_compatible" && (
                <input
                  type="url"
                  value={providerBaseUrl}
                  onChange={(e) => setProviderBaseUrl(e.target.value)}
                  placeholder="Custom Base URL (e.g. https://api.openai.com/v1) — SSRF-checked"
                  className="w-full px-3 py-2 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-inset)] text-[var(--ink)] font-mono text-xs"
                />
              )}

              <button
                type="submit"
                disabled={!activeApiKey || !providerApiKey.trim()}
                className="px-4 py-2 rounded-lg border-2 border-[#14121b] bg-[#f59e0b] text-[#041016] font-mono text-xs font-bold uppercase cursor-pointer disabled:opacity-40"
              >
                🔒 Encrypt &amp; Save to D1 Vault
              </button>
            </form>

            <div className="space-y-1.5 pt-2">
              <div className="font-mono text-[11px] font-bold uppercase text-[var(--ink-muted)]">
                Saved Encrypted Credentials ({credentials.length}):
              </div>
              {credentials.map((cred) => (
                <div
                  key={cred.id}
                  className="p-2.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-panel)] flex items-center justify-between font-mono text-xs"
                >
                  <span className="font-bold uppercase" style={{ color: "var(--sculk-cyan)" }}>
                    🔒 {cred.provider}
                  </span>
                  <span className="text-[11px] text-[var(--ink-muted)]">
                    AES-256-GCM • {cred.baseUrl ?? "Official endpoint"}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Step 4: Live End-to-End Proxy Call */}
          <div className="gate-card p-6 space-y-4">
            <h2 className="text-lg font-bold font-mono uppercase">
              4. Live End-to-End {provider.toUpperCase()} Test via Warden Gateway
            </h2>
            <form onSubmit={handleLiveGeminiTest} className="space-y-3">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={testModel}
                  onChange={(e) => setTestModel(e.target.value)}
                  className="w-48 px-3 py-2 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-inset)] text-[var(--ink)] font-mono text-xs"
                  aria-label="Model ID"
                />
                <button
                  type="submit"
                  disabled={!activeApiKey || sendingTest}
                  className="flex-1 px-4 py-2 rounded-lg border-2 border-[#14121b] bg-[#22c55e] text-[#041016] font-mono text-xs font-bold uppercase cursor-pointer disabled:opacity-40"
                >
                  {sendingTest ? "Sending via Warden..." : "⚡ Send Real /v1/chat/completions"}
                </button>
              </div>
              <textarea
                rows={3}
                value={testPrompt}
                onChange={(e) => setTestPrompt(e.target.value)}
                className="w-full p-3 rounded-xl border-2 border-[var(--border-ink)] bg-[var(--bg-inset)] text-[var(--ink)] font-mono text-xs"
              />
            </form>

            {liveResult && (
              <div className="p-4 rounded-xl border-2 border-[var(--border-subtle)] bg-[var(--bg-panel)] space-y-2 font-mono text-xs">
                <div className="flex flex-wrap items-center gap-3 font-bold">
                  <span>HTTP {liveResult.status}</span>
                  <span style={{ color: "var(--sculk-cyan)" }}>ACTION: {liveResult.action}</span>
                  <span>CACHE: {liveResult.cache}</span>
                </div>
                <p className="p-3 rounded-lg bg-[var(--bg-card)] border border-[var(--border-subtle)] whitespace-pre-wrap leading-relaxed">
                  {liveResult.replyText}
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}