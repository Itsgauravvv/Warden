"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import { Volume2, VolumeX, Sparkles, Sun, Moon, Contrast, Menu, X } from "lucide-react";
import { BRAND } from "@warden/brand";
import { WardenCrestSvg } from "./WardenCrestSvg";
import { useUiPreferences, playGatehouseSfx } from "@/lib/preferences-store";

// Update this URL to your exact GitHub repository URL
const GITHUB_REPO_URL = "https://github.com/Itsgauravvv/Warden";

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

const NAV_ITEMS = [
  { href: "/", label: "Gatehouse" },
  { href: "/demo", label: "Siege Demo" },
  { href: "/app", label: "Dashboard" },
  { href: "/learn", label: "Learn" },
  { href: "/eval", label: "CI Eval" },
  { href: "/docs", label: "Docs" },
];

function GitHubMarkSvg({ className = "w-4 h-4" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  );
}

export function TopNav() {
  const { theme, setTheme } = useTheme();
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

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

  const activeTheme = mounted ? theme : "dark";

  return (
    <header className="sticky top-0 z-40 border-b-2 border-[var(--border-ink)] bg-[var(--bg-card)]/95 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-3 sm:px-4 h-16 flex items-center justify-between gap-2">
        {/* Brand Logo + Minecraft Warden Pixel Crest */}
        <Link
          href="/"
          onClick={() => playGatehouseSfx("sculk_ping")}
          className="flex items-center gap-2 shrink-0 group"
        >
          <div className="p-1 rounded-xl border-2 border-[var(--sculk-cyan)] bg-[#061c24] shadow-[0_3px_0_var(--shadow-ink)] group-hover:scale-105 transition-transform">
            <WardenCrestSvg
              size={30}
              alertState={sonicBoomActive ? "sonic_boom" : "calm"}
            />
          </div>
          <div className="leading-tight">
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-base sm:text-lg tracking-tight uppercase whitespace-nowrap">
                {BRAND.name}
              </span>
              <span
                className="hidden sm:inline-block px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase rounded border whitespace-nowrap"
                style={{
                  backgroundColor: "var(--badge-bg)",
                  color: "var(--badge-text)",
                  borderColor: "var(--sculk-cyan)",
                }}
              >
                v1.0
              </span>
            </div>
          </div>
        </Link>

        {/* Primary Navigation Links (Always Single-Line) */}
        <nav
          aria-label="Main Gatehouse Navigation"
          className="hidden lg:flex items-center gap-0.5 font-mono text-xs font-bold uppercase shrink-0"
        >
          {NAV_ITEMS.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`px-2.5 py-1.5 rounded-lg border whitespace-nowrap transition-colors ${
                  isActive
                    ? "border-[var(--border-ink)] bg-[var(--bg-elevated)] text-[var(--sculk-cyan)]"
                    : "border-transparent hover:bg-[var(--bg-elevated)] hover:border-[var(--border-ink)]"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Controls + Star on GitHub */}
        <div className="flex items-center gap-1.5 shrink-0">
          {/* Star on GitHub: Icon + Text on Desktop, Icon-Only on Phone */}
          <a
            href={GITHUB_REPO_URL}
            target="_blank"
            rel="noreferrer"
            aria-label="Star Warden on GitHub"
            title="Star on GitHub"
            className="h-9 px-2.5 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-elevated)] hover:translate-y-[-1px] transition-transform font-mono text-[11px] font-bold uppercase inline-flex items-center gap-1.5 whitespace-nowrap"
          >
            <GitHubMarkSvg className="w-4 h-4 shrink-0" />
            <span className="hidden md:inline">Star on GitHub</span>
          </a>

          <button
            type="button"
            onClick={toggleReduceMotion}
            aria-pressed={reduceMotion}
            className="h-9 px-2 sm:px-2.5 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-elevated)] font-mono text-[11px] font-bold uppercase inline-flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
            title="Toggle Reduced Motion"
          >
            <Sparkles className="w-3.5 h-3.5 shrink-0" style={{ color: "var(--sculk-cyan)" }} />
            <span className="hidden xl:inline">{reduceMotion ? "Static" : "Motion"}</span>
          </button>

          <button
            type="button"
            onClick={toggleSfx}
            aria-pressed={sfxEnabled}
            className="h-9 px-2 sm:px-2.5 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-elevated)] font-mono text-[11px] font-bold uppercase inline-flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
            title="Toggle 8-bit Chiptune SFX"
          >
            {sfxEnabled ? (
              <Volume2 className="w-3.5 h-3.5 shrink-0 text-[#22c55e]" />
            ) : (
              <VolumeX className="w-3.5 h-3.5 shrink-0 text-[var(--ink-muted)]" />
            )}
            <span className="hidden xl:inline">{sfxEnabled ? "SFX On" : "SFX Off"}</span>
          </button>

          {/* Theme Switcher — Fixed Size Prevents Refresh Shift */}
          <button
            type="button"
            onClick={cycleTheme}
            className="h-9 px-2.5 rounded-lg border-2 border-[var(--border-ink)] font-mono text-[11px] font-bold uppercase inline-flex items-center justify-center gap-1.5 whitespace-nowrap cursor-pointer"
            style={{
              backgroundColor: "var(--badge-bg)",
              color: "var(--badge-text)",
            }}
            title="Cycle Theme: Day Watch / Night Sculk / High Contrast"
          >
            {activeTheme === "light" && <Sun className="w-3.5 h-3.5 shrink-0 text-[#ffb300]" />}
            {activeTheme === "dark" && <Moon className="w-3.5 h-3.5 shrink-0 text-[#29dfeb]" />}
            {activeTheme === "high-contrast" && (
              <Contrast className="w-3.5 h-3.5 shrink-0 text-white" />
            )}
            <span className="hidden sm:inline">
              {activeTheme === "light"
                ? "Day Watch"
                : activeTheme === "high-contrast"
                ? "Hi-Contrast"
                : "Night Sculk"}
            </span>
          </button>

          {/* Mobile Menu Toggle */}
          <button
            type="button"
            onClick={() => setMobileOpen((o) => !o)}
            className="lg:hidden h-9 w-9 rounded-lg border-2 border-[var(--border-ink)] bg-[var(--bg-elevated)] inline-flex items-center justify-center cursor-pointer"
            aria-label="Toggle Navigation Menu"
            aria-expanded={mobileOpen}
          >
            {mobileOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Responsive Mobile Navigation Drawer */}
      {mobileOpen && (
        <nav
          aria-label="Mobile Navigation"
          className="lg:hidden border-t-2 border-[var(--border-ink)] bg-[var(--bg-card)] px-4 py-3 flex flex-wrap gap-2 font-mono text-xs font-bold uppercase"
        >
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setMobileOpen(false)}
              className={`px-3 py-2 rounded-lg border whitespace-nowrap ${
                pathname === item.href
                  ? "border-[var(--border-ink)] bg-[var(--bg-elevated)] text-[var(--sculk-cyan)]"
                  : "border-[var(--border-subtle)] bg-[var(--bg-panel)]"
              }`}
            >
              {item.label}
            </Link>
          ))}
        </nav>
      )}
    </header>
  );
}