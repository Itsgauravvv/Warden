"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useTheme } from "next-themes";
import { Volume2, VolumeX, Sparkles, Sun, Moon, Contrast } from "lucide-react";
import { BRAND } from "@warden/brand";
import { WardenCrestSvg } from "./WardenCrestSvg";
import { useUiPreferences, playGatehouseSfx } from "@/lib/preferences-store";

const KONAMI_SEQUENCE = [
  "ArrowUp",
  "ArrowUp",
  "ArrowDown",
  "ArrowDown",
  "ArrowLeft",
  "ArrowRight",
  "ArrowLeft",
  "ArrowRight",
  "b",
  "a",
];

export function TopNav() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const {
    reduceMotion,
    sfxEnabled,
    sonicBoomActive,
    toggleReduceMotion,
    toggleSfx,
    triggerSonicBoom,
  } = useUiPreferences();

  useEffect(() => {
    setMounted(true);
    let idx = 0;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === KONAMI_SEQUENCE[idx]) {
        idx += 1;
        if (idx === KONAMI_SEQUENCE.length) {
          triggerSonicBoom();
          playGatehouseSfx("sculk_ping");
          idx = 0;
        }
      } else {
        idx = 0;
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [triggerSonicBoom]);

  const cycleTheme = () => {
    if (theme === "light") setTheme("dark");
    else if (theme === "dark") setTheme("high-contrast");
    else setTheme("light");
  };

  return (
    <header className="sticky top-0 z-40 border-b-2 border-[var(--border-ink)] bg-[var(--bg-card)]/95 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between gap-4">
        {/* Brand Logo + Minecraft Warden Pixel Crest */}
        <Link
          href="/"
          onClick={() => playGatehouseSfx("sculk_ping")}
          className="flex items-center gap-3 group"
        >
          <div className="p-1 rounded-xl border-2 border-[#29dfeb] bg-[#061c24] shadow-[0_3px_0_#14121b] group-hover:scale-105 transition-transform">
            <WardenCrestSvg
              size={36}
              alertState={sonicBoomActive ? "sonic_boom" : "calm"}
            />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-lg tracking-tight uppercase">
                {BRAND.name}
              </span>
              <span className="px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-[#061c24] text-[#29dfeb] border border-[#29dfeb]">
                v1.0 SCULK-GATE
              </span>
            </div>
            <p className="text-[11px] font-mono text-[var(--ink-muted)] hidden sm:block">
              {BRAND.tagline}
            </p>
          </div>
        </Link>

        {/* Primary Navigation Links */}
        <nav aria-label="Main Gatehouse Navigation" className="hidden md:flex items-center gap-1 font-mono text-xs font-bold uppercase">
          {[
            { href: "/", label: "Gatehouse" },
            { href: "/demo", label: "Siege Demo" },
            { href: "/app", label: "Dashboard" },
            { href: "/learn", label: "Learn" },
            { href: "/eval", label: "CI Eval" },
            { href: "/docs", label: "Docs" },
          ].map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="px-3 py-1.5 rounded-lg hover:bg-[var(--bg-elevated)] border border-transparent hover:border-[var(--border-ink)] transition-colors"
            >
              {item.label}
            </Link>
          ))}
        </nav>

        {/* Accessibility & Atmosphere Controls */}
        <div className="flex items-center gap-2">
          {/* Visible Reduce Motion Toggle */}
          <button
            type="button"
            onClick={toggleReduceMotion}
            aria-pressed={reduceMotion}
            className="px-2.5 py-1.5 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-elevated)] font-mono text-xs font-bold uppercase flex items-center gap-1.5 cursor-pointer"
            title="Toggle Reduced Motion"
          >
            <Sparkles className="w-3.5 h-3.5 text-[#29dfeb]" />
            <span className="hidden lg:inline">
              {reduceMotion ? "Motion: Static" : "Motion: Live"}
            </span>
          </button>

          {/* Chiptune SFX Mute Toggle (OFF by default) */}
          <button
            type="button"
            onClick={toggleSfx}
            aria-pressed={sfxEnabled}
            className="px-2.5 py-1.5 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-elevated)] font-mono text-xs font-bold uppercase flex items-center gap-1.5 cursor-pointer"
            title="Toggle 8-bit Chiptune SFX"
          >
            {sfxEnabled ? (
              <Volume2 className="w-3.5 h-3.5 text-[#2fd27a]" />
            ) : (
              <VolumeX className="w-3.5 h-3.5 text-[var(--ink-muted)]" />
            )}
            <span className="hidden lg:inline">{sfxEnabled ? "SFX: ON" : "SFX: OFF"}</span>
          </button>

          {/* Theme Switcher: Day Watch / Night Watch (Sculk) / High Contrast */}
          {mounted && (
            <button
              type="button"
              onClick={cycleTheme}
              className="px-2.5 py-1.5 rounded-lg border-2 border-[var(--border-ink)] bg-[#061c24] text-[#7df9ff] font-mono text-xs font-bold uppercase flex items-center gap-1.5 cursor-pointer"
              title="Cycle Theme: Day Watch / Night Sculk / High Contrast"
            >
              {theme === "light" && <Sun className="w-3.5 h-3.5 text-[#ffb300]" />}
              {theme === "dark" && <Moon className="w-3.5 h-3.5 text-[#29dfeb]" />}
              {theme === "high-contrast" && <Contrast className="w-3.5 h-3.5 text-white" />}
              <span>
                {theme === "light"
                  ? "Day Watch"
                  : theme === "high-contrast"
                  ? "Hi-Contrast"
                  : "Night Sculk"}
              </span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
}