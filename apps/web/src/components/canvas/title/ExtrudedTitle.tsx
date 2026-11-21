"use client";

import React, { useEffect, useRef } from "react";
import { BRAND } from "@warden/brand";
import { bakeSpriteToSvgDataUrl } from "@/sprites/pixel-sprites";
import { useUiPreferences, playGatehouseSfx } from "@/lib/preferences-store";

// 5x7 Pixel Bitmap Font so any BRAND.name renders as true extruded voxel blocks
const PIXEL_FONT: Record<string, string[]> = {
  A: ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
  B: ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
  C: ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
  D: ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
  E: ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
  F: ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
  G: ["01111", "10000", "10000", "10111", "10001", "10001", "01110"],
  H: ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
  I: ["11111", "00100", "00100", "00100", "00100", "00100", "11111"],
  J: ["00111", "00010", "00010", "00010", "10010", "10010", "01100"],
  K: ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
  L: ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
  M: ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
  N: ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
  O: ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
  P: ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
  Q: ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
  R: ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
  S: ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
  T: ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
  U: ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
  V: ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
  W: ["10001", "10001", "10001", "10101", "10101", "11011", "10001"],
  X: ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
  Y: ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
  Z: ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
  " ": ["000", "000", "000", "000", "000", "000", "000"],
};

interface VoxelBlock {
  targetX: number;
  targetY: number;
  y: number;
  vy: number;
  size: number;
  colIndex: number;
  settled: boolean;
}

interface RippleWave {
  x: number;
  y: number;
  radius: number;
  alpha: number;
}

export function ExtrudedTitle() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const { reduceMotion } = useUiPreferences();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const titleText = BRAND.name.toUpperCase();
    let animationFrameId = 0;
    let width = 640;
    const height = 160;
    let blocks: VoxelBlock[] = [];
    let topSurfaceY = 48;
    let textStartX = 24;
    let textEndX = 500;

    const pointer = { x: -9999, y: -9999 };
    const ripples: RippleWave[] = [];

    // Load two patrolling pixel creatures (Warden & Hex) onto HTMLImageElements
    const wardenImg = new Image();
    wardenImg.src = bakeSpriteToSvgDataUrl("warden", 3);
    const hexImg = new Image();
    hexImg.src = bakeSpriteToSvgDataUrl("hex", 3);

    const walkers = [
      { img: wardenImg, x: 60, dir: 1, speed: 1.1, bobPhase: 0 },
      { img: hexImg, x: 340, dir: -1, speed: 1.5, bobPhase: Math.PI },
    ];

    const buildBlocks = () => {
      width = Math.max(300, canvas.parentElement?.clientWidth ?? 640);
      canvas.width = width;
      canvas.height = height;

      // Calculate total grid columns for the word
      let totalCols = 0;
      for (let i = 0; i < titleText.length; i++) {
        const ch = titleText[i] ?? " ";
        const glyph = PIXEL_FONT[ch] ?? PIXEL_FONT[" "]!;
        totalCols += (glyph[0]?.length ?? 5) + (i < titleText.length - 1 ? 1 : 0);
      }

      const maxBlockByWidth = Math.floor((width - 48) / Math.max(1, totalCols));
      const blockSize = Math.max(6, Math.min(14, maxBlockByWidth));
      const totalWidthPx = totalCols * blockSize;
      const totalHeightPx = 7 * blockSize;

      textStartX = Math.floor((width - totalWidthPx) / 2);
      textEndX = textStartX + totalWidthPx;
      topSurfaceY = Math.floor((height - totalHeightPx) / 2) + 12;

      const nextBlocks: VoxelBlock[] = [];
      let colCursor = 0;

      for (let i = 0; i < titleText.length; i++) {
        const ch = titleText[i] ?? " ";
        const glyph = PIXEL_FONT[ch] ?? PIXEL_FONT[" "]!;
        const glyphWidth = glyph[0]?.length ?? 5;

        for (let r = 0; r < glyph.length; r++) {
          const rowStr = glyph[r] ?? "";
          for (let c = 0; c < rowStr.length; c++) {
            if (rowStr[c] === "1") {
              const targetX = textStartX + (colCursor + c) * blockSize;
              const targetY = topSurfaceY + r * blockSize;
              nextBlocks.push({
                targetX,
                targetY,
                y: reduceMotion ? targetY : -30 - (colCursor + c) * 7 - Math.random() * 60,
                vy: 0,
                size: blockSize,
                colIndex: colCursor + c,
                settled: reduceMotion,
              });
            }
          }
        }
        colCursor += glyphWidth + 1;
      }

      blocks = nextBlocks;
      walkers[0]!.x = textStartX + 10;
      walkers[1]!.x = Math.max(textStartX + 40, textEndX - 40);
    };

    buildBlocks();

    const onMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      pointer.x = e.clientX - rect.left;
      pointer.y = e.clientY - rect.top;
    };

    const onMouseLeave = () => {
      pointer.x = -9999;
      pointer.y = -9999;
    };

    const onClick = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      ripples.push({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
        radius: 6,
        alpha: 1,
      });
      playGatehouseSfx("sculk_ping");
    };

    let tick = 0;

    const render = () => {
      tick += 1;
      ctx.clearRect(0, 0, width, height);

      // Subtle Deep Dark Sculk grid backdrop
      ctx.fillStyle = "#041016";
      ctx.fillRect(0, 0, width, height);
      ctx.fillStyle = "rgba(41, 223, 235, 0.08)";
      for (let gx = 12; gx < width; gx += 20) {
        for (let gy = 12; gy < height; gy += 20) {
          ctx.fillRect(gx, gy, 2, 2);
        }
      }

      // Advance click ripples
      for (let i = ripples.length - 1; i >= 0; i--) {
        const rp = ripples[i];
        if (!rp) continue;
        rp.radius += 5.5;
        rp.alpha -= 0.025;
        if (rp.alpha <= 0) {
          ripples.splice(i, 1);
          continue;
        }
        ctx.strokeStyle = `rgba(41, 223, 235, ${rp.alpha.toFixed(2)})`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(rp.x, rp.y, rp.radius, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Draw extruded 3D voxel blocks
      const depth = 5;
      for (const b of blocks) {
        if (!b.settled) {
          b.vy += 0.85; // Gravity rain-in
          b.y += b.vy;
          if (b.y >= b.targetY) {
            b.y = b.targetY;
            b.vy = -b.vy * 0.25;
            if (Math.abs(b.vy) < 1.2) {
              b.y = b.targetY;
              b.vy = 0;
              b.settled = true;
            }
          }
        }

        // Cursor proximity lift
        let offsetY = 0;
        if (!reduceMotion) {
          const dx = b.targetX + b.size / 2 - pointer.x;
          const dy = b.y + b.size / 2 - pointer.y;
          const dist = Math.hypot(dx, dy);
          if (dist < 75) {
            offsetY -= ((75 - dist) / 75) * 10;
          }

          // Click ripple wave displacement
          for (const rp of ripples) {
            const rDist = Math.hypot(b.targetX - rp.x, b.y - rp.y);
            if (Math.abs(rDist - rp.radius) < 22) {
              offsetY -= 9 * rp.alpha;
            }
          }
        }

        const drawX = b.targetX;
        const drawY = b.y + offsetY;

        // 3D Extruded Shadow/Side Face (Deep Sculk Teal)
        ctx.fillStyle = "#0b4f60";
        ctx.fillRect(drawX + depth, drawY + depth, b.size - 1, b.size - 1);

        // Front Block Face (Sculk Cyan + Soul Glow Highlight)
        ctx.fillStyle = "#29dfeb";
        ctx.fillRect(drawX, drawY, b.size - 1, b.size - 1);

        // Inner pixel bevel highlight
        ctx.fillStyle = "#7df9ff";
        ctx.fillRect(drawX + 1, drawY + 1, Math.max(2, b.size - 5), 2);
      }

      // Draw pixel creatures walking across the top of the extruded letters
      for (const w of walkers) {
        if (!reduceMotion) {
          w.x += w.dir * w.speed;
          if (w.x > textEndX - 28) w.dir = -1;
          if (w.x < textStartX) w.dir = 1;
        }
        const bob = reduceMotion ? 0 : Math.abs(Math.sin(tick * 0.12 + w.bobPhase)) * 4;
        const creatureSize = 30;
        const drawY = topSurfaceY - creatureSize - bob + 2;

        if (w.img.complete && w.img.naturalWidth > 0) {
          ctx.save();
          if (w.dir < 0) {
            ctx.translate(w.x + creatureSize, drawY);
            ctx.scale(-1, 1);
            ctx.drawImage(w.img, 0, 0, creatureSize, creatureSize);
          } else {
            ctx.drawImage(w.img, w.x, drawY, creatureSize, creatureSize);
          }
          ctx.restore();
        }
      }

      if (!reduceMotion) {
        animationFrameId = requestAnimationFrame(render);
      }
    };

    render();

    window.addEventListener("resize", buildBlocks);
    canvas.addEventListener("mousemove", onMouseMove);
    canvas.addEventListener("mouseleave", onMouseLeave);
    canvas.addEventListener("click", onClick);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", buildBlocks);
      canvas.removeEventListener("mousemove", onMouseMove);
      canvas.removeEventListener("mouseleave", onMouseLeave);
      canvas.removeEventListener("click", onClick);
    };
  }, [reduceMotion]);

  return (
    <div className="gate-card overflow-hidden bg-[#041016] border-[#29dfeb] relative">
      <div className="px-4 py-1.5 border-b border-[#29dfeb]/40 bg-[#061c24] flex items-center justify-between font-mono text-[10px] uppercase text-[#7df9ff]">
        <span>■ INTERACTIVE VOXEL CREST — HOVER TO LIFT, CLICK FOR SCULK RIPPLE</span>
        <span className="hidden sm:inline text-[#29dfeb]">PATROL: WARDEN &amp; HEX</span>
      </div>
      <canvas
        ref={canvasRef}
        className="w-full h-[160px] block cursor-pointer"
        aria-label={`Interactive pixel-block title for ${BRAND.name}`}
      />
    </div>
  );
}