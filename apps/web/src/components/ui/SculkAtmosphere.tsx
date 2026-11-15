"use client";

import React, { useEffect, useState } from "react";
import { useUiPreferences } from "@/lib/preferences-store";

interface CursorParticle {
  id: number;
  x: number;
  y: number;
  color: string;
}

const FLOATING_SPORES = [
  { id: 1, left: "8%", size: 6, delay: "0s", duration: "11s", color: "#29dfeb" },
  { id: 2, left: "22%", size: 8, delay: "2s", duration: "14s", color: "#7df9ff" },
  { id: 3, left: "38%", size: 5, delay: "4s", duration: "10s", color: "#2fd27a" },
  { id: 4, left: "57%", size: 7, delay: "1s", duration: "13s", color: "#29dfeb" },
  { id: 5, left: "74%", size: 6, delay: "3s", duration: "12s", color: "#7c5cff" },
  { id: 6, left: "89%", size: 8, delay: "5s", duration: "15s", color: "#29dfeb" },
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

  useEffect(() => {
    if (reduceMotion) {
      setTrail([]);
      return;
    }

    let counter = 0;
    let lastSpawn = 0;
    const colors = ["#29dfeb", "#7df9ff", "#2fd27a", "#7c5cff"];

    const onMouseMove = (e: MouseEvent) => {
      const now = performance.now();
      if (now - lastSpawn < 45) return; // Throttle to 22fps for zero lag
      lastSpawn = now;
      const id = ++counter;
      const color = colors[id % colors.length] ?? "#29dfeb";

      setTrail((prev) => [...prev.slice(-10), { id, x: e.clientX, y: e.clientY, color }]);
    };

    window.addEventListener("mousemove", onMouseMove, { passive: true });
    return () => window.removeEventListener("mousemove", onMouseMove);
  }, [reduceMotion]);

  if (reduceMotion) return null;

  return (
    <div className="pointer-events-none fixed inset-0 z-30 overflow-hidden" aria-hidden="true">
      {/* Floating Deep Dark Sculk Spores */}
      {FLOATING_SPORES.map((spore) => (
        <span
          key={spore.id}
          className="absolute bottom-[-20px] opacity-40 animate-bounce"
          style={{
            left: spore.left,
            width: spore.size,
            height: spore.size,
            backgroundColor: spore.color,
            boxShadow: `0 0 10px ${spore.color}`,
            animationDelay: spore.delay,
            animationDuration: spore.duration,
          }}
        />
      ))}

      {/* Pixel Cursor Trail */}
      {trail.map((p, idx) => (
        <span
          key={p.id}
          className="fixed w-2 h-2 transition-opacity duration-300"
          style={{
            left: p.x + 10,
            top: p.y + 10,
            backgroundColor: p.color,
            opacity: (idx + 1) / trail.length,
            boxShadow: `0 0 6px ${p.color}`,
          }}
        />
      ))}
    </div>
  );
}

/**
 * Responsive Neo-Brutalist Attack Signature Marquee
 */
export function AttackSignatureMarquee() {
  const { reduceMotion } = useUiPreferences();

  return (
    <div className="w-full overflow-hidden border-y-2 border-[var(--border-ink)] bg-[#061c24] text-[#7df9ff] py-2.5">
      <div
        className={`flex items-center gap-8 whitespace-nowrap font-mono text-xs font-bold tracking-wider ${
          reduceMotion ? "flex-wrap justify-center px-4" : "animate-pulse"
        }`}
      >
        {ATTACK_SIGNATURES.map((sig, i) => (
          <span key={i} className="inline-flex items-center gap-2">
            <span className="text-[#29dfeb]">{sig}</span>
            <span className="text-[#0b4f60]">///</span>
          </span>
        ))}
      </div>
    </div>
  );
}