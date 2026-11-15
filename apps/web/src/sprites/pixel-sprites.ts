/**
 * Runtime String-Grid Pixel Sprite Authoring System.
 * Each character is a 12x12 string grid where characters map to palette colors.
 * Zero external image assets required!
 */

export const SPRITE_PALETTE: Record<string, string> = {
  ".": "transparent",
  K: "#041016", // Deep Dark Sculk Black/Abyss
  S: "#0b4f60", // Sculk Teal Armor
  C: "#29dfeb", // Bioluminescent Sculk Cyan
  L: "#7df9ff", // Bright Soul Cyan Glow
  B: "#d8ceb8", // Bone / Tusk Parchment
  W: "#ffffff", // Pure White
  G: "#2fd27a", // Signal Green (Allow)
  A: "#ffb300", // Torch Amber (Redact / Gold)
  R: "#ff4d4d", // Crimson (Block / Imp)
  V: "#7c5cff", // Arcane Violet (Hex / Magic)
  Z: "#3d8bff", // Azure (Echo Cache)
  H: "#b4693c", // Hound Brown (Sniffer)
  D: "#6e3b1e", // Dark Fur
  F: "#ff7832", // Fox Orange (Quill)
};

export type SpriteId =
  | "warden"
  | "sniffer"
  | "hex"
  | "ledger"
  | "toll"
  | "echo"
  | "imp"
  | "quill"
  | "courier";

/**
 * 12x12 Original Pixel Art String Grids for the entire cast
 */
export const SPRITE_GRIDS: Record<SpriteId, string[]> = {
  // Warden: Deep Dark Sculk Badger/Sentinel with glowing cyan horns & lantern
  warden: [
    ".C........C.",
    "CSL......LSC",
    ".SSBBBBBBSS.",
    "..SKKKKKKS..",
    "..BKCLLCKB..",
    "..BKKKKKKB..",
    "...BBBBBB...",
    "..SSSSSSSS..",
    ".SSCCLLCCSS.",
    ".SS.CCCC.SS.",
    "..K..KK..K..",
    "..B......B..",
  ],
  // Sniffer: Loyal Bloodhound who sniffs scrolls for PII & secrets
  sniffer: [
    "..DD....DD..",
    ".DHHDDDDHHD.",
    ".DHHHHHHHH..",
    "DDHHKHHKHH..",
    "DHHHHHHHHKK.",
    ".DHHHHHHHKK.",
    "..BBBBBBBB..",
    "..HHHHHHHH..",
    "..HHHHHHHH..",
    "..HH....HH..",
    "..DD....DD..",
    "............",
  ],
  // Hex: Arcane Raven on the ramparts who spots hidden prompt injections
  hex: [
    "....KKKK....",
    "...KKKKKK...",
    "..KKVKKVKK..",
    "..KKKKKKKKAA",
    "...KKKKKKAAA",
    "..KKKKKKKK..",
    ".KKKKVVKKKK.",
    ".KKKKKKKKKK.",
    "..KKKKKKKK..",
    "....K..K....",
    "...AA..AA...",
    "............",
  ],
  // Ledger: Ancient Tortoise scribe writing the SHA-256 hash chain
  ledger: [
    "............",
    "....GGGG....",
    "..GGSSSSGG..",
    ".GSSSSSSSSG.",
    ".GSSCAACSSGG",
    "GGSSSSSSSSGG",
    "BBBBBBBBBBBB",
    "..GG....GG..",
    "..GG....GG..",
    "............",
    "............",
    "............",
  ],
  // Toll: Frog toll collector counting tokens & coins
  toll: [
    "..GG....GG..",
    ".GWWG..GWWG.",
    ".GKKG..GKKG.",
    ".GGGGGGGGGG.",
    "GGGGGGGGGGGG",
    "GAAAGGGGAAAG",
    ".GGGGGGGGGG.",
    "..GGGGGGGG..",
    ".GG..GG..GG.",
    "GGG..GG..GGG",
    "............",
    "............",
  ],
  // Echo: Azure Parrot who repeats semantically cached answers
  echo: [
    "....ZZZZ....",
    "...ZZZZZZ...",
    "..ZZWKKZZAA.",
    "..ZZZZZZZAAA",
    "..ZZCCZZZZ..",
    ".ZZZZCCZZZZ.",
    ".ZZZZZZZZZZ.",
    "..ZZZZZZZZ..",
    "....ZZZZ....",
    "....A..A....",
    "............",
    "............",
  ],
  // Imp: Mischievous Red-Team Goblin in disguise
  imp: [
    ".R........R.",
    "RRR..KK..RRR",
    ".RRRRRRRRRR.",
    "..RAAKKAA R..",
    "..RRRRRRRR..",
    ".KKKKKKKKKK.",
    "...RRRRRR...",
    "..VVVVVVVV..",
    "..VV.VV.VV..",
    "....R..R....",
    "...KK..KK...",
    "............",
  ],
  // Quill: Clever Fox clerk who drafts YAML policy scrolls
  quill: [
    ".F........F.",
    "FFF......FFF",
    "FFFFFFFFFFFF",
    "FFWKKFFKKWFF",
    "FFFFFFFFFFFF",
    ".WWFFFFFFWW.",
    "..WWWWWWWW..",
    "..VVVVVVVV..",
    ".FFVVVVVVFF.",
    "..FF....FF..",
    "..KK....KK..",
    "............",
  ],
  // Courier: Small hooded messenger carrying a prompt scroll
  courier: [
    "....SSSS....",
    "...SSSSSS...",
    "..SSBBBBSS..",
    "..SSKBBKSS..",
    "...SSSSSS...",
    "..SSSSSSSSBB",
    ".SSSSSSSSSBB",
    "..SSSSSSSSBB",
    "...SSSSSS...",
    "...KK..KK...",
    "...BB..BB...",
    "............",
  ],
};

/**
 * Bakes any 12x12 string-grid sprite into a crisp SVG Data URL for instant rendering in Canvas/Pixi/Img.
 */
export function bakeSpriteToSvgDataUrl(spriteId: SpriteId, scale = 4): string {
  const grid = SPRITE_GRIDS[spriteId];
  const size = 12 * scale;
  const rects: string[] = [];

  grid.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) {
      const key = row[x] ?? ".";
      const color = SPRITE_PALETTE[key];
      if (color && color !== "transparent") {
        rects.push(
          `<rect x="${x * scale}" y="${y * scale}" width="${scale}" height="${scale}" fill="${color}" />`
        );
      }
    }
  });

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges">${rects.join("")}</svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}