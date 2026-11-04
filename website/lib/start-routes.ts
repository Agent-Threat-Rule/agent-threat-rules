/** Reader routes for /start and the home page: one sentence and two links each. */

export type Bilingual = { en: string; zh: string };

export interface StartRoute {
  key: string;
  title: Bilingual;
  body: Bilingual;
  links: ReadonlyArray<{ href: string; label: Bilingual }>;
}

// One sentence and two links per reader. Every link points at a page that
// already exists; this page adds no content of its own.
export const START_ROUTES: ReadonlyArray<StartRoute> = [
  {
    key: "integrate",
    title: { en: "I want to integrate ATR", zh: "我要整合 ATR" },
    body: {
      en: "Load the rules into your scanner, gateway or SIEM, and choose the lane that matches how much you want to block.",
      zh: "把規則載入你的掃描器、閘道或 SIEM,並依你想擋多少選擇對應的 lane。",
    },
    links: [
      { href: "/integrate", label: { en: "Integration paths", zh: "整合方式" } },
      { href: "/rules", label: { en: "Rules by lane", zh: "依 lane 看規則" } },
    ],
  },
  {
    key: "contribute",
    title: { en: "I want to write a rule or report a false positive", zh: "我要寫規則或回報誤判" },
    body: {
      en: "Submit a rule, an evasion or a false positive; every rule passes the same quality gates before it merges.",
      zh: "提交規則、繞過手法或誤判;每條規則合併前都要通過同一套品質閘。",
    },
    links: [
      { href: "/contribute", label: { en: "How to contribute", zh: "如何貢獻" } },
      { href: "/quality-standard", label: { en: "Quality standard", zh: "品質標準" } },
    ],
  },
  {
    key: "audit",
    title: { en: "I am doing procurement or an audit", zh: "我在做採購或稽核" },
    body: {
      en: "See what a conforming engine must do and how rules map to the frameworks you report against; the mappings are ATR's own, not endorsements.",
      zh: "看符規引擎必須做到什麼,以及規則如何對應到你要回報的框架;對應是 ATR 自己的文件,不是背書。",
    },
    links: [
      { href: "/conformance", label: { en: "Conformance", zh: "符規" } },
      { href: "/compliance", label: { en: "Framework mappings", zh: "框架對應" } },
    ],
  },
  {
    key: "cite",
    title: { en: "I want to cite ATR", zh: "我要引用 ATR" },
    body: {
      en: "Cite the specification by version and DOI, so the version you cited stays reachable after the standard moves on.",
      zh: "以版本與 DOI 引用規格,標準往前走之後,你引用的那一版仍然找得到。",
    },
    links: [
      { href: "/citations", label: { en: "Citation formats", zh: "引用格式" } },
      { href: "/spec", label: { en: "Specification", zh: "規格" } },
    ],
  },
  {
    key: "governance",
    title: { en: "I want to see how ATR is governed", zh: "我要看 ATR 怎麼治理" },
    body: {
      en: "Who maintains ATR, how changes merge, how errors are corrected, and how the steering committee is seated.",
      zh: "誰在維護 ATR、變更如何合併、錯誤如何更正,以及技術指導委員會如何就任。",
    },
    links: [
      { href: "/governance", label: { en: "Governance", zh: "治理" } },
      { href: "/charter", label: { en: "Charter", zh: "章程" } },
    ],
  },
  {
    key: "public-sector",
    title: { en: "I represent a government or standards body", zh: "我代表政府或標準組織" },
    body: {
      en: "ATR is a vendor-neutral, MIT-licensed rule format that any country or organization can adopt, audit or fork.",
      zh: "ATR 是廠商中立、MIT 授權的規則格式,任何國家或組織都能採用、稽核或分支。",
    },
    links: [
      { href: "/sovereign-ai-defense", label: { en: "Sovereign AI context", zh: "主權 AI 語境" } },
      { href: "/compliance/nist-ai-rmf", label: { en: "NIST AI RMF mappings", zh: "NIST AI RMF 對應" } },
    ],
  },
];

