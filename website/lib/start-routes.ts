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
      en: "Load the rules into your scanner, gateway or SIEM. Then pick a lane by how much you want blocked.",
      zh: "把規則放進你的掃描器、閘道或 SIEM。想擋多少，就選哪一條 lane。",
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
      en: "Send a rule, a bypass or a false positive. Every rule goes through the same quality gates before it merges.",
      zh: "送一條規則、一個繞過手法，或一筆誤判都可以。每條規則合併前，都要過同一套品質閘。",
    },
    links: [
      { href: "/contribute", label: { en: "How to contribute", zh: "怎麼貢獻" } },
      { href: "/quality-standard", label: { en: "Quality standard", zh: "品質標準" } },
    ],
  },
  {
    key: "audit",
    title: { en: "I am doing procurement or an audit", zh: "我在做採購或稽核" },
    body: {
      en: "See what a conforming engine has to do, and how the rules map to the frameworks you report against. ATR wrote those mappings itself. They are not endorsements.",
      zh: "看一個符規引擎要做到哪些事，規則又怎麼對到你要交代的框架。這些對應是 ATR 自己寫的，不是框架方的背書。",
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
      en: "Cite the specification by version and DOI. The version you cited stays reachable after the standard moves on.",
      zh: "引用規格時寫上版本和 DOI。標準之後再怎麼改，你引的那一版都還找得到。",
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
      en: "Who maintains ATR and how a change gets merged. Also how mistakes get corrected, and how seats on the steering committee are filled.",
      zh: "誰在維護 ATR，改動怎麼合併。寫錯了怎麼更正，技術指導委員會的席次又怎麼產生。",
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
      en: "ATR is a rule format under the MIT licence, tied to no vendor. Any country or organization can adopt it, audit it or fork it.",
      zh: "ATR 是 MIT 授權的規則格式，不綁任何廠商。任何國家或組織都能拿去用、拿去稽核，也能自己分支。",
    },
    links: [
      { href: "/sovereign-ai-defense", label: { en: "Sovereign AI", zh: "主權 AI" } },
      { href: "/compliance/nist-ai-rmf", label: { en: "NIST AI RMF mappings", zh: "NIST AI RMF 對應" } },
    ],
  },
];

