import type { Metadata } from "next";
import { Source_Serif_4, Noto_Serif_TC } from "next/font/google";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { loadSiteStats } from "@/lib/stats";
import { BASE_OPEN_GRAPH, SITE_URL } from "@/lib/seo";
import "./globals.css";

const stats = loadSiteStats();

// Geist for interface and headings, Geist Mono for identifiers and metadata,
// loaded from the geist package (local files, OFL) rather than Google Fonts:
// Turbopack fails to resolve the multi-subset Google CSS for Geist Mono, and
// local files keep the build independent of a font CDN.

// Serif for spec body — gives W3C / IETF document feel.
// Applied via `font-spec` utility on .spec-document wrappers.
const sourceSerif = Source_Serif_4({
  variable: "--font-source-serif",
  subsets: ["latin"],
  weight: ["400", "600", "700"],
  display: "swap",
});

// Traditional Chinese serif companion (used on zh-TW spec pages).
const notoSerifTC = Noto_Serif_TC({
  variable: "--font-noto-serif-tc",
  subsets: ["latin"],
  weight: ["400", "600", "700"],
  display: "swap",
  preload: false,
});

export const metadata: Metadata = {
  title: {
    default: "ATR - Agent Threat Rules",
    template: "%s | ATR",
  },
  description:
    `Open-source detection standard for AI agent security. ${stats.ruleCount} effective rules, ${stats.megaScanTotal.toLocaleString()} agent skills scanned in the wild, RFC-001 quality standard. MIT Licensed.`,
  metadataBase: new URL(SITE_URL),
  // No `alternates` here: a canonical set in a layout is inherited by every
  // page that does not set its own. Each page sets it through lib/seo.ts.
  openGraph: {
    ...BASE_OPEN_GRAPH,
    title: "ATR - Agent Threat Rules",
    description:
      `The open detection standard for AI agent security. ${stats.ruleCount} effective rules. ${stats.megaScanTotal.toLocaleString()} agent skills scanned in the wild. MIT Licensed.`,
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    title: "ATR - Agent Threat Rules",
    description:
      `The open detection standard for AI agent security. ${stats.ruleCount} effective rules. ${stats.megaScanTotal.toLocaleString()} agent skills scanned in the wild. MIT Licensed.`,
    images: ["https://agentthreatrule.org/og-image.png"],
  },
  keywords: [
    "AI agent security",
    "MCP security",
    "prompt injection detection",
    "agent threat rules",
    "ATR",
    "OWASP agentic",
    "YARA for AI",
    "Sigma for AI agents",
    "AI security rules",
    "LLM security",
    "AI agent firewall",
    "agentic AI defense",
    "MCP threat detection",
    "SKILL.md security",
  ],
  authors: [{ name: "ATR Community" }],
  creator: "ATR Community",
  publisher: "Agent Threat Rules",
};

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      name: "Agent Threat Rules",
      alternateName: "ATR",
      url: "https://agentthreatrule.org",
      logo: "https://agentthreatrule.org/atr-logo-black.png",
      description:
        "The open detection standard for AI agent security. Community-driven rules to protect AI agents from prompt injection, tool poisoning, and context exfiltration.",
      sameAs: [
        "https://github.com/Agent-Threat-Rule/agent-threat-rules",
        "https://www.npmjs.com/package/agent-threat-rules",
        "https://doi.org/10.5281/zenodo.19178002",
      ],
    },
    {
      "@type": "SoftwareSourceCode",
      name: "agent-threat-rules",
      description:
        `Open-source detection standard for AI agent security. ${stats.ruleCount} effective rules, ${stats.megaScanTotal.toLocaleString()} agent skills scanned in the wild. By default the engine runs in process, with no network or model calls.`,
      codeRepository: "https://github.com/Agent-Threat-Rule/agent-threat-rules",
      programmingLanguage: ["YAML", "TypeScript"],
      license: "https://opensource.org/licenses/MIT",
      runtimePlatform: "Node.js",
      author: { "@type": "Organization", name: "ATR Community" },
    },
    {
      "@type": "WebSite",
      url: "https://agentthreatrule.org",
      name: "ATR - Agent Threat Rules",
      inLanguage: ["en", "zh-TW"],
    },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${GeistSans.variable} ${GeistMono.variable} ${sourceSerif.variable} ${notoSerifTC.variable} h-full`}
    >
      <body className="min-h-full flex flex-col antialiased">
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        {children}
      </body>
    </html>
  );
}
