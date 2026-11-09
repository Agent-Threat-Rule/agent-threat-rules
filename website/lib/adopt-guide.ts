/*
 * The home page "where do you start" guide and the three tools. Only
 * integrations that exist in this repository are named (src/adapters,
 * src/converters, integrations/). ATR Router and ATR Eval are not published.
 */
type B = { en: string; zh: string };

export interface Audience {
  key: string;
  who: B;
  need: B;
  how: B;
  where: B;
  first: { label: B; href: string; code?: string };
}

export const AUDIENCES: ReadonlyArray<Audience> = [
  {
    key: "build",
    who: { en: "You build agents", zh: "做 agent 的人" },
    need: { en: "Your agent spends its day reading things other people wrote. Web pages, tool descriptions, files from strangers.", zh: "你的 agent 每天都在讀別人寫的東西。網頁、工具說明、陌生人傳來的檔案。" },
    how: {
      en: "Run ATR on what your agent reads and on every tool call. The engine and the Claude Code hook only report. They block nothing until you turn blocking on. Some adapters are the exception: Mastra, OpenShell and NemoClaw block high and critical matches out of the box, and you can change that in their settings. Blocking is meant for the enforce lane. That lane loads only the stable rules, so it catches far fewer attacks. ATR runs inside your own process, so the data stays where it is.",
      zh: "讓 ATR 檢查 agent 讀進來的內容，和每一次工具呼叫。引擎和 Claude Code hook 只回報，不攔截；要攔截，得自己打開。例外是幾個轉接器：Mastra、OpenShell、NemoClaw 裝好就會攔下 high 和 critical 的命中，可以在它們的設定裡改。攔截是給 enforce 車道用的。這條車道只載入 stable 規則，所以抓到的攻擊少很多。ATR 跑在你自己的程式裡，資料不會離開。",
    },
    where: { en: "Node · MCP stdio · Claude Code hook · goose · LangChain · Pydantic AI · Mastra", zh: "Node · MCP stdio · Claude Code hook · goose · LangChain · Pydantic AI · Mastra" },
    first: { label: { en: "Integration guide", zh: "整合說明" }, href: "/docs/integrations", code: "npm install agent-threat-rules" },
  },
  {
    key: "secops",
    who: { en: "You run security", zh: "資安團隊" },
    need: { en: "Agent incidents land in the same queue as everything else, with no name and no query that finds them.", zh: "agent 出事的那張單，跟其他告警混在同一個佇列裡。沒有名字，也查不到。" },
    how: { en: "Turn the rules into the queries your SIEM already runs, and put the rule ID on the ticket. Whoever picks it up next knows exactly what it was.", zh: "把規則轉成你 SIEM 本來就在跑的查詢，工單上直接寫規則編號。下一個接手的人，一看就知道是哪一招。" },
    where: { en: "Splunk · Elastic · SARIF · MISP", zh: "Splunk · Elastic · SARIF · MISP" },
    first: { label: { en: "See the converters", zh: "看轉換器" }, href: "/docs/integrations" },
  },
  {
    key: "platform",
    who: { en: "You ship an AI product", zh: "做 AI 產品的人" },
    need: { en: "Customers ask what you can stop. A feature page can't answer that. A list of rule IDs can.", zh: "客戶會問：你們擋得住什麼？一頁功能介紹答不了，一張規則編號清單可以。" },
    how: { en: "Ship the rules, pass the public conformance tests, then list yourself in ADOPTERS.md with a link anyone can open.", zh: "把規則放進產品，跑過公開的符規測試，再到 ADOPTERS.md 登記，附一個誰都點得開的連結。" },
    where: { en: "Your cloud · your customers' environments", zh: "你的雲端 · 客戶的環境" },
    first: { label: { en: "Run conformance", zh: "跑符規測試" }, href: "/conformance" },
  },
  {
    key: "assure",
    who: { en: "You have to answer for it", zh: "要負責交代的人" },
    need: { en: "Auditors, regulators and insurers won't take your word for it. They want something they can check themselves.", zh: "稽核、主管機關、保險公司，不會因為你說安全就相信。他們要自己查得了的東西。" },
    how: { en: "The rules run fully offline and map to the EU AI Act, NIST AI RMF and ISO/IEC 42001. ATR Eval, still in development, is meant to measure how a given agent release holds up against hijacking.", zh: "規則可以完全離線執行，也對應到 EU AI Act、NIST AI RMF 和 ISO/IEC 42001。ATR Eval 還在開發中，之後可以用來量測某一版 agent 面對劫持的表現。" },
    where: { en: "Offline · OSCAL · SARIF", zh: "離線 · OSCAL · SARIF" },
    first: { label: { en: "Auditor kit", zh: "稽核工具包" }, href: "/docs/auditor-kit" },
  },
  {
    key: "research",
    who: { en: "You find attacks", zh: "找攻擊的人" },
    need: { en: "You found a hole. It shouldn't get fixed only in the one system where you found it.", zh: "你找到一個漏洞。只有你發現它的那個系統補好，是不夠的。" },
    how: { en: "Send it as a rule with tests, or report it and let a maintainer write it. Bypasses and false positives count too. Anything accepted carries your name.", zh: "寫成一條附測試的規則送 PR，或直接回報，讓維護者來寫。繞過和誤判一樣算數，被收下的會掛上你的名字。" },
    where: { en: "GitHub pull requests · report forms", zh: "GitHub PR · 回報表單" },
    first: { label: { en: "Write a rule", zh: "寫一條規則" }, href: "/contribute" },
  },
];

export type ToolKey = "rules" | "router" | "eval";

export const TOOLS: Record<ToolKey, { name: string; line: B; body: B; href: string; released: boolean }> = {
  rules: {
    name: "ATR Rules",
    line: { en: "Spot the attack.", zh: "認出攻擊。" },
    body: { en: "Rules that run inside your own process. Nothing has to leave.", zh: "規則跑在你自己的程式裡，什麼都不用送出去。" },
    href: "/rules",
    released: true,
  },
  router: {
    name: "ATR Router",
    line: { en: "Work out what to test.", zh: "想清楚要測什麼。" },
    body: { en: "Reads what your agent can reach and keeps only the tests that matter for it.", zh: "讀出你的 agent 碰得到什麼，只留下跟它有關的測試。" },
    href: "/router",
    released: false,
  },
  eval: {
    name: "ATR Eval",
    line: { en: "Then prove it.", zh: "再拿出證據。" },
    body: { en: "Each attack runs many times. The result is signed, and anyone can recompute it.", zh: "每一題跑很多次，結果簽名，誰都能拿去重算。" },
    href: "/eval",
    released: false,
  },
};
