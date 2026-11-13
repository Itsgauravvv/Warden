/**
 * SINGLE SOURCE OF TRUTH FOR PRODUCT NAMING
 * Change BRAND_NAME here to rename the entire gateway, headers, and UI.
 */
export const BRAND_NAME = "Warden" as const;

export const BRAND = {
  name: BRAND_NAME,
  slug: BRAND_NAME.toLowerCase(),
  tagline: "A gatehouse for your AI. Every prompt, inspected.",
  apiKeyPrefix: `${BRAND_NAME.slice(0, 3).toLowerCase()}_live_`,
  sandboxKeyPrefix: `${BRAND_NAME.slice(0, 3).toLowerCase()}_test_`,
  headerPrefix: `X-${BRAND_NAME}`,
  cast: {
    gatekeeper: { name: BRAND_NAME, species: "Badger", role: "Final verdicts & passport stamps" },
    piiHound: { name: "Sniffer", species: "Hound", role: "Sniffs scrolls for PII & secrets" },
    injectionRaven: { name: "Hex", species: "Raven", role: "Spots obfuscated prompt injections" },
    auditTortoise: { name: "Ledger", species: "Tortoise", role: "Writes the SHA-256 hash-chained book" },
    budgetFrog: { name: "Toll", species: "Frog", role: "Counts tokens, rate limits & budgets" },
    cacheParrot: { name: "Echo", species: "Parrot", role: "Repeats semantically cached answers" },
    redTeamGoblin: { name: "Imp", species: "Goblin", role: "Mutates & fires red-team attacks" },
    policyFox: { name: "Quill", species: "Fox", role: "Drafts signed YAML policy scrolls" },
  },
  palette: {
    dayWatch: {
      parchment: "#f3ecdc",
      ink: "#14121b",
      allow: "#2fd27a",
      redact: "#ffb300",
      block: "#ff4d4d",
      cache: "#3d8bff",
      accent: "#7c5cff",
    },
    nightWatch: {
      stone: "#0d0b14",
      parchment: "#ede6d6",
      torchAmber: "#ffb300",
      allow: "#2fd27a",
      redact: "#ffb300",
      block: "#ff4d4d",
      cache: "#3d8bff",
      accent: "#7c5cff",
    },
  },
} as const;