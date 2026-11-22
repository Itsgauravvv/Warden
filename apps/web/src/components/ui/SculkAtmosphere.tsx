"use client";

import React, { useEffect, useState } from "react";
import { useUiPreferences } from "@/lib/preferences-store";

interface CursorParticle {
  id: number;
  x: number;
  y: number;
  color: string;
  createdAt: number;
}

const PARTICLE_TTL_MS = 380;

const FLOATING_ELEMENTS = [
  { id: 1, left: "4%", glyph: "■", size: 10, delay: "0s", duration: "16s", color: "#29dfeb" },
  { id: 2, left: "14%", glyph: "◆", size: 12, delay: "3s", duration: "21s", color: "#7c5cff" },
  { id: 3, left: "26%", glyph: "▲", size: 9, delay: "6s", duration: "18s", color: "#2fd27a" },
  { id: 4, left: "39%", glyph: "❖", size: 11, delay: "1.5s", duration: "23s", color: "#29dfeb" },
  { id: 5, left: "52%", glyph: "■", size: 8, delay: "8s", duration: "17s", color: "#ffb300" },
  { id: 6, left: "66%", glyph: "◆", size: 12, delay: "4s", duration: "20s", color: "#29dfeb" },
  { id: 7, left: "78%", glyph: "▲", size: 10, delay: "9s", duration: "19s", color: "#7c5cff" },
  { id: 8, left: "88%", glyph: "❖", size: 11, delay: "2s", duration: "22s", color: "#2fd27a" },
  { id: 9, left: "95%", glyph: "■", size: 9, delay: "5s", duration: "15s", color: "#29dfeb" },
];

const ATTACK_SIGNATURES = [
  "■ LLM01:2025 DIRECT PROMPT INJECTION",
  "▲ BASE64 OBFUSCATED PAYLOAD",
  "◆ CYRILLIC HOMOGLYPH BYPASS",
  "■ LLM02:2025 AWS IAM SECRET LEAK",
  "▲ LUHN CREDIT CARD PII REDACTION",
  "◆ LLM06:2025 CONFUSED DEPUTY TOOL TAINT",
  "■ SSRF METADATA 169.254.169.254 BLOCK",
  "▲ LLM07:2025 SYSTEM PROMPT CANARY LEAK",
  "◆ SHA-256 TAMPER-EVIDENT AUDIT CHAIN",
];

export function SculkAtmosphere() {
  const { reduceMotion } = useUiPreferences();
  const [trail, setTrail] = useState<CursorParticle[]>([]);
  const [nowMs, setNowMs] = useState<number>(0);

  useEffect(() => {
    if (reduceMotion) {
      setTrail([]);
      return;
    }

    let counter = 0;
    let lastSpawn = 0;
    const colors = ["#29dfeb", "#0e6b7d", "#2fd27a", "#7c5cff"];

    const onMouseMove = (e: MouseEvent) => {
      const now = Date.now();
      if (now - lastSpawn < 40) return;
      lastSpawn = now;
      const id = ++counter;
      const color = colors[id % colors.length] ?? "#29dfeb";

      setNowMs(now);
      setTrail((prev) => [
        ...prev.filter((p) => now - p.createdAt < PARTICLE_TTL_MS).slice(-9),
        { id, x: e.clientX, y: e.clientY, color, createdAt: now },
      ]);
    };

    // Prune expired particles every 50ms so the trail vanishes completely once the cursor stops
    const cleanupTimer = setInterval(() => {
      const now = Date.now();
      setNowMs(now);
      setTrail((prev) => {
        if (prev.length === 0) return prev;
        const alive = prev.filter((p) => now - p.createdAt < PARTICLE_TTL_MS);
        return alive.length === prev.length ? prev : alive;
      });
    }, 50);

    window.addEventListener("mousemove", onMouseMove, { passive: true });
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      clearInterval(cleanupTimer);
    };
  }, [reduceMotion]);

  if (reduceMotion) return null;

  return (
    <div className="pointer-events-none fixed inset-0 z-30 overflow-hidden" aria-hidden="true">
      {/* Soft Ambient Floating Sculk Glow Orbs */}
      <div
        className="absolute -top-24 -left-24 w-72 h-72 rounded-full blur-3xl opacity-15 animate-levitate"
        style={{ backgroundColor: "var(--sculk-cyan)" }}
      />
      <div
        className="absolute top-1/3 -right-24 w-80 h-80 rounded-full blur-3xl opacity-10 animate-levitate-delayed"
        style={{ backgroundColor: "var(--signal-accent)" }}
      />

      {/* Rising Bioluminescent Pixel Spores & Runes */}
      {FLOATING_ELEMENTS.map((item) => (
        <span
          key={item.id}
          className="absolute -bottom-8 font-mono font-bold select-none animate-spore-rise"
          style={{
            left: item.left,
            fontSize: `${item.size}px`,
            color: item.color,
            textShadow: `0 0 10px ${item.color}`,
            animationDelay: item.delay,
            animationDuration: item.duration,
          }}
        >
          {item.glyph}
        </span>
      ))}

      {/* Auto-Vanishing Pixel Cursor Trail */}
      {trail.map((p) => {
        const age = Math.max(0, nowMs - p.createdAt);
        const life = Math.max(0, 1 - age / PARTICLE_TTL_MS);
        return (
          <span
            key={p.id}
            className="fixed w-2 h-2 pointer-events-none"
            style={{
              left: p.x + 10,
              top: p.y + 10,
              backgroundColor: p.color,
              opacity: Number(life.toFixed(2)),
              transform: `scale(${(0.4 + life * 0.6).toFixed(2)})`,
              boxShadow: `0 0 6px ${p.color}`,
            }}
          />
        );
      })}
    </div>
  );
}

export function AttackSignatureMarquee() {
  const { reduceMotion } = useUiPreferences();

  return (
    <div
      className="w-full overflow-hidden border-b-2 border-[var(--border-ink)] py-2.5"
      style={{
        backgroundColor: "var(--bg-marquee)",
        color: "var(--marquee-text)",
      }}
    >
      {reduceMotion ? (
        <div className="max-w-7xl mx-auto px-4 flex flex-wrap items-center justify-center gap-x-6 gap-y-1.5 font-mono text-xs font-bold tracking-wider">
          {ATTACK_SIGNATURES.map((sig, i) => (
            <span key={i} className="inline-flex items-center gap-2">
              <span>{sig}</span>
              <span style={{ color: "var(--marquee-sep)" }}>///</span>
            </span>
          ))}
        </div>
      ) : (
        <div className="marquee-track font-mono text-xs font-bold tracking-wider">
          {[0, 1].map((dup) => (
            <div
              key={dup}
              className="flex items-center gap-8 pr-8 whitespace-nowrap"
              aria-hidden={dup === 1}
            >
              {ATTACK_SIGNATURES.map((sig, i) => (
                <span key={`${dup}-${i}`} className="inline-flex items-center gap-3">
                  <span>{sig}</span>
                  <span style={{ color: "var(--marquee-sep)" }}>///</span>
                </span>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}