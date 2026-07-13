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
    slug: "unit42-skill-supply-chain",
    date: "2026-07-13",
    title: {
      en: "Palo Alto's Unit 42 scanned 49,943 agent skills. It's the same story our 96,096 told.",
      zh: "Palo Alto Unit 42 掃了 49,943 個 agent skill。跟我們掃 96,096 個講的是同一件事。",
    },
    summary: {
      en: "Unit 42's Behavioral Integrity Verification research found 80% of agent skills deviate from their declared behavior, 18.9% adversarially — an independent second dataset landing on the conclusion our 96,096-skill scan reached: the agent-skill supply chain is the attack surface. BIV verifies declared-vs-actual at install time; ATR detects the attack at runtime. We mapped their 29-capability taxonomy to ATR, and their canonical credential-exfil payload exposed a real gap — a code-surface chain our shell-syntax rules missed — so we shipped ATR-2026-02261. Honest about the seam: ATR covers the observed-behavior half, not the manifest diff.",
      zh: "Unit 42 的 Behavioral Integrity Verification 研究發現 80% 的 agent skill 行為與宣告不符、18.9% 帶對抗性——這是一份獨立的第二資料集，落在我們掃 96,096 個 skill 得到的同一個結論上：agent-skill 供應鏈就是攻擊面。BIV 在安裝時驗證「宣告 vs 實際」；ATR 在 runtime 偵測攻擊本身。我們把他們的 29 能力 taxonomy 對映到 ATR，而他們的 canonical 憑證外洩 payload 曝出一個真缺口——一條我們的 shell 語法規則漏掉的 code-surface 鏈——於是我們補上 ATR-2026-02261。也老實說清楚接縫：ATR 只覆蓋 observed-behavior 那半,不做 manifest diff。",
    },
    atrRules: ["ATR-2026-02261", "ATR-2026-00201", "ATR-2026-00224"],
  },
  {
    slug: "neutral-benchmarks",
    date: "2026-07-10",
    title: {
      en: "We ran ATR through two neutral agent-security benchmarks. Here's the honest result.",
      zh: "我們拿 ATR 跑了兩個中立的 agent 安全 benchmark。這是誠實的結果。",
    },
    summary: {
      en: "Self-published numbers are the easiest to game, so we ran ATR through two open benchmarks we didn't build. On OpenGuardrails (runtime traffic) ATR placed first of seven reference detectors with zero false positives. On OASB (static skill artifacts) it had the lowest false-positive rate on the board — zero across 3,881 benign skills — but low recall, because ATR is a runtime detector, not a package scanner. We publish the numbers we got, including where ATR is weak.",
      zh: "自己發布的數字最容易灌水,所以我們拿 ATR 去跑兩個不是我們做的開放 benchmark。在 OpenGuardrails(runtime 流量)ATR 在七個參考偵測器裡排第一、零誤報;在 OASB(靜態 skill 工件)它是全榜誤報率最低的——3,881 個良性 skill 零誤報——但 recall 低,因為 ATR 是 runtime 偵測器,不是套件掃描器。我們公開跑到的數字,包括 ATR 表現差的地方。",
    },
    atrRules: [],
  },
  {
    slug: "nsa-mcp-security",
    date: "2026-06-29",
    title: {
      en: "The NSA wrote 9 MCP security recommendations. Two of them are ATR's job.",
      zh: "NSA 寫了 9 條 MCP 安全建議。其中兩條,正是 ATR 在做的事。",
    },
    summary: {
      en: "In May 2026 the NSA published MCP security design considerations: 8 named risks, 9 recommendations, zero executable rules. Two of those recommendations — track and patch MCP CVEs, and filter agent output pipelines — are exactly what ATR's rule corpus does. We map all nine, and we're honest about the rest: ATR is not a scanner and emits no logs.",
      zh: "2026 年 5 月,NSA 發布 MCP 安全設計考量:8 項風險、9 條建議、零條可執行規則。其中兩條——追蹤修補 MCP CVE、過濾 agent 輸出管線——正是 ATR 規則庫在做的事。我們對映全部九條,也老實說清楚其餘:ATR 不是掃描器,也不產生 log。",
    },
    atrRules: [
      "ATR-2026-00451",
      "ATR-2026-00534",
      "ATR-2026-00002",
      "ATR-2026-00010",
    ],
  },
  {
    slug: "this-weeks-mcp-cves",
    date: "2026-06-21",
    title: {
      en: "Does your ruleset see this week's attacks?",
      zh: "你的規則庫看得到本週的攻擊嗎?",
    },
    summary: {
      en: "This week's batch of Critical MCP/agent CVEs is all the same shape — a poisoned input flows through a tool parameter into execution. We checked ATR against it: dedicated rules for the gemini-mcp-tool CVSS 9.8 and all four PraisonAI CVEs, within days of disclosure. The gap between a CVE landing and a rule shipping is the metric — days, not weeks.",
      zh: "本週這批 Critical 級 MCP/agent CVE 形態都一樣——被下毒的輸入經工具參數流進執行。我們拿 ATR 對它實測:gemini-mcp-tool 的 CVSS 9.8 與 PraisonAI 全部四個 CVE 都有專屬規則,在揭露後幾天內到位。CVE 落地到規則上線之間的差距,才是真正的指標——以天計,不是以週計。",
    },
    atrRules: [
      "ATR-2026-01931",
      "ATR-2026-00540",
      "ATR-2026-00544",
      "ATR-2026-00545",
      "ATR-2026-00528",
    ],
  },
  {
    slug: "static-guardrails-lose",
    date: "2026-06-21",
    title: {
      en: "The math says static guardrails lose",
      zh: "數學證明:靜態防護必輸",
    },
    summary: {
      en: "A June 2026 NIST proof shows no finite set of guardrails is universally robust against adversarial prompts — defense has to be continuous, not one-and-done. NVIDIA shipping an install-time skill scanner says the same thing. ATR is the open, continuously-updated rules layer for it.",
      zh: "NIST 2026 年 6 月的數學證明:沒有任何有限的 guardrail 集合能普遍抵禦對抗式 prompt — 防禦必須持續更新,不能一次到位。NVIDIA 推出安裝前 skill 掃描器說明了同一件事。ATR 就是為此而生的開放、持續更新規則層。",
    },
    atrRules: ["ATR-2026-01931", "ATR-2026-00576"],
  },
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
