"use client";

import React, { useEffect, useState } from "react";
import { Check, ShieldAlert, EyeOff, Zap, Flag, Copy } from "lucide-react";
import type { PolicyAction } from "@warden/policy-schema";

/**
 * Accessible Verdict Badge:
 * Combines Color + Distinct Icon + Border Shape + Uppercase Text Label
 */
export function VerdictBadge({
  action,
  cached = false,
}: {
  action: PolicyAction;
  cached?: boolean;
}) {
  if (cached) {
    return (
      <span
        className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold uppercase tracking-wider border-2 border-[#14121b] rounded-full"
        style={{ backgroundColor: "var(--signal-cache)", color: "#14121b" }}
      >
        <Zap className="w-3.5 h-3.5 stroke-[2.5]" aria-hidden="true" />
        <span>◆ ECHO CACHED</span>
      </span>
    );
  }

  switch (action) {
    case "allow":
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold uppercase tracking-wider border-2 border-[#14121b] rounded-full"
          style={{ backgroundColor: "var(--signal-allow)", color: "#14121b" }}
        >
          <Check className="w-3.5 h-3.5 stroke-[3]" aria-hidden="true" />
          <span>● ALLOW</span>
        </span>
      );
    case "redact":
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold uppercase tracking-wider border-2 border-[#14121b] rounded-md"
          style={{ backgroundColor: "var(--signal-redact)", color: "#14121b" }}
        >
          <EyeOff className="w-3.5 h-3.5 stroke-[2.5]" aria-hidden="true" />
          <span>▲ REDACT</span>
        </span>
      );
    case "block":
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold uppercase tracking-wider border-2 border-[#14121b] rounded-none"
          style={{ backgroundColor: "var(--signal-block)", color: "#ffffff" }}
        >
          <ShieldAlert className="w-3.5 h-3.5 stroke-[2.5]" aria-hidden="true" />
          <span>■ BLOCK</span>
        </span>
      );
    case "flag":
    case "shadow":
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold uppercase tracking-wider border-2 border-[#14121b] rounded-lg"
          style={{ backgroundColor: "var(--signal-accent)", color: "#ffffff" }}
        >
          <Flag className="w-3.5 h-3.5 stroke-[2.5]" aria-hidden="true" />
          <span>◈ {action.toUpperCase()}</span>
        </span>
      );
  }
}

/**
 * Mono Uppercase Section Label with Colored Square, e.g. "■ GATE 02 / INSPECTION"
 */
export function SectionGateLabel({
  gateNumber,
  title,
  color = "var(--sculk-cyan)",
}: {
  gateNumber: string;
  title: string;
  color?: string;
}) {
  return (
    <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md border-2 border-[var(--border-ink)] bg-[var(--bg-elevated)] text-[var(--ink)] font-mono text-xs font-bold uppercase tracking-widest">
      <span
        className="w-2.5 h-2.5 inline-block border border-[#14121b] shrink-0"
        style={{ backgroundColor: color }}
        aria-hidden="true"
      />
      <span>
        GATE {gateNumber} / {title}
      </span>
    </div>
  );
}

/**
 * Code Window with Traffic-Light Dots, Filename Tab, and Pixel "COPIED!" State
 */
export function GateCodeWindow({
  filename,
  code,
  language = "typescript",
}: {
  filename: string;
  code: string;
  language?: string;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="gate-card overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b-2 border-[var(--border-ink)] bg-[#061c24] text-[#f3ecdc]">
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-[#ff4d4d] border border-black" />
          <span className="w-3 h-3 rounded-full bg-[#ffb300] border border-black" />
          <span className="w-3 h-3 rounded-full bg-[#2fd27a] border border-black" />
          <span className="ml-2 font-mono text-xs font-bold tracking-wide text-[#29dfeb]">
            {filename}
          </span>
        </div>
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono font-bold uppercase rounded border border-[#29dfeb] bg-[#082732] text-[#7df9ff] hover:bg-[#0b4f60] cursor-pointer"
          aria-label={`Copy code from ${filename}`}
        >
          <Copy className="w-3.5 h-3.5" />
          <span>{copied ? "★ COPIED!" : language}</span>
        </button>
      </div>
      <pre className="p-4 overflow-x-auto bg-[#091319] text-[#e6f9ff] font-mono text-xs leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  );
}

/**
 * Fixed Bottom Scroll-Progress Bar Styled as a Fortress Wall-Height & Sculk Depth Gauge
 */
export function WallHeightGauge() {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const onScroll = () => {
      const scrollTop = window.scrollY;
      const docHeight = document.documentElement.scrollHeight - window.innerHeight;
      if (docHeight <= 0) {
        setProgress(0);
        return;
      }
      setProgress(Math.min(100, Math.max(0, Math.round((scrollTop / docHeight) * 100))));
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div
      className="fixed bottom-0 left-0 right-0 z-50 h-7 border-t-2 border-[var(--border-ink)] bg-[var(--bg-card)] text-[var(--ink)] flex items-center px-4 font-mono text-[11px] justify-between"
      role="region"
      aria-label="Rampart Wall Height Scroll Gauge"
    >
      <div className="flex items-center gap-2">
        <span className="font-bold" style={{ color: "var(--sculk-cyan)" }}>
          ■ RAMPART GAUGE
        </span>
        <span className="hidden sm:inline text-[var(--ink-muted)]">| SCULK DEPTH SENSOR</span>
      </div>
      <div className="flex-1 mx-4 h-2.5 bg-[var(--bg-inset)] border border-[var(--border-subtle)] rounded-sm overflow-hidden">
        <div
          className="h-full transition-all duration-150"
          style={{
            width: `${progress}%`,
            background: "linear-gradient(90deg, #22c55e 0%, #29dfeb 60%, #7c5cff 100%)",
          }}
        />
      </div>
      <span className="font-bold tabular-nums" style={{ color: "var(--sculk-cyan)" }}>
        {progress}% WATCH
      </span>
    </div>
  );
}