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
import { bakeSpriteToSvgDataUrl, type SpriteId } from "@/sprites/pixel-sprites";
import { playGatehouseSfx } from "@/lib/preferences-store";

const QUICKSTART_CODE = `import OpenAI from "openai";

// Change ONLY your baseURL & apiKey — ${BRAND.name} routes to Gemini 2.5 Flash!
const client = new OpenAI({
  baseURL: "http://localhost:8787/v1",
  apiKey: "${BRAND.apiKeyPrefix}your_tenant_key",
  defaultHeaders: {
    "${BRAND.headerPrefix}-Provider": "gemini",
    "${BRAND.headerPrefix}-Provider-Key": process.env.GEMINI_API_KEY,
  },
});

const response = await client.chat.completions.create({
  model: "gemini-2.5-flash",
  messages: [{ role: "user", content: "Inspect this scroll at the gate!" }],
});`;

const CAST_SPRITE_MAP: Record<string, SpriteId> = {
  gatekeeper: "warden",
  piiHound: "sniffer",
  injectionRaven: "hex",
  auditTortoise: "ledger",
  budgetFrog: "toll",
  cacheParrot: "echo",
  redTeamGoblin: "imp",
  policyFox: "quill",
};

export default function HomePage() {
  const [wardenMood, setWardenMood] = useState<"calm" | "sniffing" | "sonic_boom">("calm");

  return (
    <div className="space-y-12 pb-10">
      <AttackSignatureMarquee />

      <div className="max-w-7xl mx-auto px-4 space-y-16">
        {/* HERO SECTION */}
        <section className="gate-card p-6 sm:p-10 md:p-12 relative overflow-hidden bg-gradient-to-br from-[#061c24] via-[#09222c] to-[#0d0b14] text-[#f3ecdc]">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
            <div className="space-y-5 max-w-2xl">
              <SectionGateLabel gateNumber="01" title="THE DEEP DARK GATEHOUSE" />
              <h1 className="text-3xl sm:text-5xl md:text-6xl font-bold tracking-tight leading-none">
                A GATEHOUSE FOR YOUR AI.{" "}
                <span className="text-[#29dfeb] underline decoration-4 underline-offset-8">
                  EVERY PROMPT, INSPECTED.
                </span>
              </h1>
              <p className="text-sm sm:text-base md:text-lg text-[#c7d6df] leading-relaxed">
                {BRAND.name} is an open-source, OpenAI-compatible security proxy built for{" "}
                <strong className="text-[#7df9ff]">Google Gemini</strong>, Groq, OpenRouter, and
                Workers AI. Every scroll passes through our Sculk sensor cascade: catching obfuscated
                prompt injections, redacting PII reversibly, locking down agent tool calls, and
                sealing a SHA-256 hash-chained audit book.
              </p>

              {/* Verdict + Chiptune SFX Interactive Bar */}
              <div className="pt-2 flex flex-wrap items-center gap-3">
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

              <div className="pt-4 flex flex-wrap gap-4">
                <Link
                  href="/demo"
                  className="px-5 py-3 rounded-xl border-2 border-[#14121b] bg-[#29dfeb] text-[#061c24] font-mono text-xs sm:text-sm font-bold uppercase shadow-[0_5px_0_#14121b] hover:translate-y-[-2px] transition-transform"
                >
                  ⚔ Launch Siege Mode Demo
                </Link>
                <Link
                  href="/app"
                  className="px-5 py-3 rounded-xl border-2 border-[#29dfeb] bg-[#082732] text-[#7df9ff] font-mono text-xs sm:text-sm font-bold uppercase hover:bg-[#0b4f60] transition-colors"
                >
                  Open Live Dashboard →
                </Link>
              </div>
            </div>

            {/* Interactive Minecraft-Inspired Sculk Warden Emblem Card */}
            <div className="w-full lg:w-80 gate-card p-6 bg-[#041016] border-[#29dfeb] flex flex-col items-center text-center space-y-4">
              <div className="p-4 rounded-2xl border-2 border-[#29dfeb]/60 bg-[#061c24] shadow-[0_0_30px_rgba(41,223,235,0.25)] animate-pulse">
                <WardenCrestSvg size={120} alertState={wardenMood} />
              </div>
              <div className="space-y-1">
                <div className="font-mono text-xs uppercase tracking-widest text-[#29dfeb]">
                  ■ HEAD GATEKEEPER
                </div>
                <h2 className="text-xl font-bold text-[#f3ecdc]">
                  {BRAND.cast.gatekeeper.name} (Sculk Sentinel)
                </h2>
                <p className="text-xs font-mono text-[#9ba8b8]">
                  Click any verdict badge to test {BRAND.name}&apos;s Sculk sensor state!
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* GATE 02: LIVE INTERACTIVE GATEHOUSE SIMULATION */}
        <section className="space-y-4">
          <SectionGateLabel gateNumber="02" title="LIVE 3-LANE GATEHOUSE INSPECTION" />
          <GatehouseScene />
        </section>

        {/* GATE 03: THE CAST OF PIXEL GUARDS (WITH BAKED STRING-GRID SPRITES!) */}
        <section className="space-y-6">
          <SectionGateLabel gateNumber="03" title="THE CAST OF PIXEL GUARDS" />
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            {Object.entries(BRAND.cast).map(([key, guard]) => {
              const spriteId = CAST_SPRITE_MAP[key] ?? "warden";
              return (
                <div key={key} className="gate-card gate-card-interactive p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="p-2 rounded-xl border-2 border-[#29dfeb]/50 bg-[#061c24]">
                      <img
                        src={bakeSpriteToSvgDataUrl(spriteId, 4)}
                        alt={guard.name}
                        className="w-12 h-12"
                      />
                    </div>
                    <span className="font-mono text-xs font-bold uppercase px-2.5 py-1 rounded bg-[#061c24] text-[#29dfeb] border border-[#29dfeb]">
                      {guard.species}
                    </span>
                  </div>
                  <h3 className="text-xl font-bold">{guard.name}</h3>
                  <p className="text-sm text-[var(--ink-muted)]">{guard.role}</p>
                </div>
              );
            })}
          </div>
        </section>

        {/* GATE 04: TWO-LINE GEMINI QUICKSTART */}
        <section className="space-y-6">
          <SectionGateLabel gateNumber="04" title="GEMINI DROP-IN QUICKSTART" />
          <GateCodeWindow filename="quickstart-gemini.ts" code={QUICKSTART_CODE} />
        </section>
      </div>
    </div>
  );
}