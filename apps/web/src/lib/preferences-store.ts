"use client";

import { create } from "zustand";

interface UiPreferencesState {
  reduceMotion: boolean;
  sfxEnabled: boolean;
  crtScanlines: boolean;
  sonicBoomActive: boolean;
  toggleReduceMotion: () => void;
  toggleSfx: () => void;
  toggleCrtScanlines: () => void;
  triggerSonicBoom: () => void;
}

export const useUiPreferences = create<UiPreferencesState>((set) => ({
  reduceMotion: false,
  sfxEnabled: false, // Strictly OFF by default per accessibility rules
  crtScanlines: false,
  sonicBoomActive: false,
  toggleReduceMotion: () => set((s) => ({ reduceMotion: !s.reduceMotion })),
  toggleSfx: () => set((s) => ({ sfxEnabled: !s.sfxEnabled })),
  toggleCrtScanlines: () => set((s) => ({ crtScanlines: !s.crtScanlines })),
  triggerSonicBoom: () => {
    set({ sonicBoomActive: true });
    setTimeout(() => set({ sonicBoomActive: false }), 1200);
  },
}));

/**
 * Pure WebAudio 8-bit Chiptune SFX generator (zero external audio files).
 * Plays distinct retro sounds for Allow, Redact, Block (Portcullis slam), and Sculk Sensor ping.
 */
export function playGatehouseSfx(
  effect: "allow" | "redact" | "block" | "cache" | "sculk_ping"
): void {
  if (typeof window === "undefined") return;
  const { sfxEnabled } = useUiPreferences.getState();
  if (!sfxEnabled) return;

  const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
  if (!AudioCtx) return;

  const ctx = new AudioCtx();
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.connect(gain);
  gain.connect(ctx.destination);

  const now = ctx.currentTime;
  gain.gain.setValueAtTime(0.08, now);

  if (effect === "allow") {
    osc.type = "square";
    osc.frequency.setValueAtTime(523.25, now); // C5
    osc.frequency.setValueAtTime(659.25, now + 0.07); // E5
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.18);
    osc.start(now);
    osc.stop(now + 0.18);
  } else if (effect === "redact") {
    osc.type = "triangle";
    osc.frequency.setValueAtTime(440, now);
    osc.frequency.setValueAtTime(392, now + 0.08);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
    osc.start(now);
    osc.stop(now + 0.2);
  } else if (effect === "block") {
    osc.type = "sawtooth";
    osc.frequency.setValueAtTime(196, now);
    osc.frequency.exponentialRampToValueAtTime(65, now + 0.25);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.26);
    osc.start(now);
    osc.stop(now + 0.26);
  } else if (effect === "cache") {
    osc.type = "sine";
    osc.frequency.setValueAtTime(587.33, now);
    osc.frequency.setValueAtTime(880, now + 0.06);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.16);
    osc.start(now);
    osc.stop(now + 0.16);
  } else if (effect === "sculk_ping") {
    // Deep Dark Warden Sculk sensor vibration sound
    osc.type = "sine";
    osc.frequency.setValueAtTime(160, now);
    osc.frequency.exponentialRampToValueAtTime(540, now + 0.14);
    osc.frequency.exponentialRampToValueAtTime(220, now + 0.28);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
    osc.start(now);
    osc.stop(now + 0.3);
  }
}