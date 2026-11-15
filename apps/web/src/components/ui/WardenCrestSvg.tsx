"use client";

import React from "react";

interface WardenCrestSvgProps {
  size?: number;
  alertState?: "calm" | "sniffing" | "sonic_boom";
  className?: string;
}

/**
 * 16x16 Pixel-Art SVG inspired by Minecraft's Deep Dark Warden:
 * - Bioluminescent Sculk tendrils/horns (#29dfeb & #7df9ff)
 * - Deep Dark abyssal slate head (#061c24 & #0d2b36)
 * - Bone-parchment jaw/brow (#e2d9c5)
 * - Glowing cyan core that pulses on alert
 */
export function WardenCrestSvg({
  size = 44,
  alertState = "calm",
  className = "",
}: WardenCrestSvgProps) {
  const glowColor =
    alertState === "sonic_boom"
      ? "#ff4d4d"
      : alertState === "sniffing"
      ? "#ffb300"
      : "#29dfeb";

  const innerGlow =
    alertState === "sonic_boom"
      ? "#ff9999"
      : alertState === "sniffing"
      ? "#ffe082"
      : "#7df9ff";

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      shapeRendering="crispEdges"
      className={className}
      role="img"
      aria-label="Warden Deep Dark Gatekeeper Crest"
    >
      {/* Left & Right Outer Sculk Horns / Tendrils */}
      <rect x="1" y="2" width="2" height="1" fill={glowColor} />
      <rect x="13" y="2" width="2" height="1" fill={glowColor} />
      <rect x="0" y="3" width="2" height="2" fill="#0b4f60" />
      <rect x="14" y="3" width="2" height="2" fill="#0b4f60" />

      {/* Bioluminescent Cyan Tendril Tips (Vibrate on alert) */}
      <rect x="1" y="3" width="1" height="2" fill={innerGlow} />
      <rect x="14" y="3" width="1" height="2" fill={innerGlow} />
      <rect x="1" y="5" width="3" height="2" fill="#0b4f60" />
      <rect x="12" y="5" width="3" height="2" fill="#0b4f60" />
      <rect x="2" y="5" width="1" height="1" fill={glowColor} />
      <rect x="13" y="5" width="1" height="1" fill={glowColor} />

      {/* Head Crown & Deep Dark Sculk Carapace */}
      <rect x="4" y="3" width="8" height="10" fill="#061c24" />
      <rect x="3" y="4" width="10" height="8" fill="#082732" />

      {/* Pale Bone/Tusk Brow & Side Plates (Classic Warden silhouette) */}
      <rect x="4" y="4" width="2" height="2" fill="#d8ceb8" />
      <rect x="10" y="4" width="2" height="2" fill="#d8ceb8" />
      <rect x="3" y="8" width="1" height="3" fill="#c2b69d" />
      <rect x="12" y="8" width="1" height="3" fill="#c2b69d" />

      {/* Deep Dark Hollow Void Mouth / Face Center */}
      <rect x="5" y="6" width="6" height="4" fill="#030d12" />

      {/* Bioluminescent Sculk Sensor Core Spots on Face */}
      <rect x="4" y="7" width="1" height="1" fill={glowColor} />
      <rect x="11" y="7" width="1" height="1" fill={glowColor} />
      <rect x="6" y="7" width="4" height="2" fill={glowColor} />
      <rect x="7" y="7" width="2" height="2" fill={innerGlow} />

      {/* Lower Jaw & Sculk Rib Chest Glow */}
      <rect x="5" y="11" width="2" height="1" fill="#d8ceb8" />
      <rect x="9" y="11" width="2" height="1" fill="#d8ceb8" />
      <rect x="6" y="13" width="4" height="2" fill={glowColor} />
      <rect x="7" y="13" width="2" height="1" fill={innerGlow} />
    </svg>
  );
}