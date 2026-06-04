import type { Metadata } from "next";
import { Inter, Inter_Tight, JetBrains_Mono, Source_Serif_4, Noto_Serif_TC } from "next/font/google";
import { loadSiteStats } from "@/lib/stats";
import "./globals.css";

const stats = loadSiteStats();

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const interTight = Inter_Tight({
  variable: "--font-inter-tight",
  subsets: ["latin"],
  weight: ["400", "600", "800", "900"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
  weight: ["400", "500", "700"],
});

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
    `Open-source detection standard for AI agent security. ${stats.ruleCount} rules, 96K skills scanned, 552 confirmed malware, RFC-001 quality standard. Shipped in Cisco AI Defense. MIT Licensed.`,
  metadataBase: new URL("https://agentthreatrule.org"),
  alternates: {
    canonical: "https://agentthreatrule.org",
    languages: {
      en: "https://agentthreatrule.org/en",
      zh: "https://agentthreatrule.org/zh",
    },
  },
  openGraph: {
    title: "ATR - Agent Threat Rules",
    description:
      `The open detection standard for AI agent security. ${stats.ruleCount} rules. 96K skills scanned. 552 confirmed malware. Shipped in Cisco.`,
    url: "https://agentthreatrule.org",
    siteName: "ATR - Agent Threat Rules",
    type: "website",
    locale: "en_US",
    alternateLocale: "zh_TW",
    images: [
      {
        url: "https://agentthreatrule.org/og-image.png",
        width: 1200,
        height: 630,
        alt: "ATR - Agent Threat Rules: The open detection standard for AI agent security",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "ATR - Agent Threat Rules",
    description:
      `The open detection standard for AI agent security. ${stats.ruleCount} rules. 96K skills scanned. 552 confirmed malware. Shipped in Cisco.`,
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
        `Open-source detection standard for AI agent security. ${stats.ruleCount} rules, 96K skills scanned, 552 confirmed malware. Sub-millisecond, zero dependencies.`,
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
      className={`${inter.variable} ${interTight.variable} ${jetbrainsMono.variable} ${sourceSerif.variable} ${notoSerifTC.variable} h-full`}
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
