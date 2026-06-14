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
    slug: "five-eyes-supply-chain",
    date: "2026-06-14",
    title: {
      en: "The Five Eyes told you to inspect your agent's dependencies. We scanned 96,096 of them.",
      zh: "Five Eyes 要你檢查 agent 的依賴。我們掃了 96,096 個。",
    },
    summary: {
      en: "The April 2026 Five Eyes guidance names third-party agent components — MCP servers, tools, skills — as a critical supply-chain risk, and gives no tool to check them. ATR scanned 96,096 across five registries: 1,302 flagged, 552 confirmed malicious after manual review, three coordinated publishers.",
      zh: "2026 年 4 月 Five Eyes 指引點名第三方 agent 元件(MCP server、工具、skill)為關鍵供應鏈風險，卻沒給檢查的工具。ATR 掃了五個 registry 的 96,096 個：1,302 個有風險、人工複審後 552 個確認惡意、三個協同發布者。",
    },
    atrRules: ["ATR-2026-00531", "ATR-2026-00161"],
  },
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
