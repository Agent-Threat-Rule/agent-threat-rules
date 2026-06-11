/**
 * Blog post registry. Each post is a static page under app/[locale]/blog/<slug>/.
 * Metadata lives here so the index page and sitemaps stay in sync.
 * Posts are timestamped public bets: state the claim, date it, link the evidence.
 */

export type Bilingual = { en: string; zh: string };

export interface BlogPost {
  slug: string;
  date: string; // ISO yyyy-mm-dd
  title: Bilingual;
  summary: Bilingual;
  atrRules: string[];
}

export const posts: BlogPost[] = [
  {
    slug: "hades-credential-theft",
    date: "2026-06-12",
    title: {
      en: "Hades is stealing Anthropic API keys through poisoned packages. ATR detects the theft pattern.",
      zh: "Hades 正透過投毒套件竊取 Anthropic API key。ATR 偵測這個竊取模式。",
    },
    summary: {
      en: "The June 2026 Shai-Hulud wave hunts AI-agent credentials: ANTHROPIC_API_KEY, Claude configs, .mcp.json. Rule ATR-2026-00576 covers the credential-theft stage.",
      zh: "2026 年 6 月的 Shai-Hulud 新一波鎖定 AI agent 憑證：ANTHROPIC_API_KEY、Claude 設定檔、.mcp.json。規則 ATR-2026-00576 涵蓋憑證竊取階段。",
    },
    atrRules: ["ATR-2026-00576", "ATR-2026-00575"],
  },
];

export function getPost(slug: string): BlogPost | undefined {
  return posts.find((p) => p.slug === slug);
}
