import type { Metadata } from "next";
import { Space_Grotesk, JetBrains_Mono, Silkscreen } from "next/font/google";
import { ThemeProvider } from "next-themes";
import { BRAND } from "@warden/brand";
import { TopNav } from "@/components/ui/TopNav";
import { WallHeightGauge } from "@/components/ui/GatehouseKit";
import { SculkAtmosphere } from "@/components/ui/SculkAtmosphere";
import "./globals.css";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space",
  weight: ["500", "700"],
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  weight: ["400", "600", "700"],
});

const silkscreen = Silkscreen({
  subsets: ["latin"],
  variable: "--font-pixel",
  weight: ["400", "700"],
});

export const metadata: Metadata = {
  title: `${BRAND.name} — ${BRAND.tagline}`,
  description:
    "Open-source LLM & AI Agent security gateway. Prompt injection detection, reversible PII redaction, tool-call firewall, and hash-chained audit logs.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${spaceGrotesk.variable} ${jetbrainsMono.variable} ${silkscreen.variable}`}
    >
      <body
        suppressHydrationWarning
        className="pb-12 antialiased selection:bg-[#29dfeb] selection:text-[#061c24]"
      >
        <ThemeProvider
          attribute="data-theme"
          defaultTheme="dark"
          themes={["light", "dark", "high-contrast"]}
          disableTransitionOnChange
        >
          <SculkAtmosphere />
          <TopNav />
          <main>{children}</main>
          <WallHeightGauge />
        </ThemeProvider>
      </body>
    </html>
  );
}