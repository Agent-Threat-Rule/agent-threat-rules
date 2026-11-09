/**
 * Site navigation: six groups, used by the header dropdowns, the mobile
 * drawer and the footer index, so the three never list different pages.
 * Paths are below the locale prefix. Pages left out of the header (partner
 * sync, red team, sovereign AI, the old wall) keep their URLs and appear in
 * the footer only.
 */

export type Bilingual = { en: string; zh: string };

export interface NavLink {
  path: string;
  label: Bilingual;
}

export interface NavGroup {
  key: string;
  label: Bilingual;
  /** Where the group label itself links. */
  path: string;
  links: ReadonlyArray<NavLink>;
}

export const NAV_GROUPS: ReadonlyArray<NavGroup> = [
  {
    key: "standard",
    label: { en: "Standard", zh: "標準" },
    path: "/docs",
    links: [
      { path: "/docs", label: { en: "Documentation", zh: "文件" } },
      { path: "/spec", label: { en: "Specification", zh: "規格" } },
      { path: "/conformance", label: { en: "Conformance", zh: "符規" } },
      { path: "/changelog", label: { en: "Changelog", zh: "版本歷程" } },
      { path: "/errata", label: { en: "Errata", zh: "勘誤" } },
      { path: "/glossary", label: { en: "Glossary", zh: "詞彙表" } },
      { path: "/citations", label: { en: "Citation", zh: "引用" } },
    ],
  },
  {
    key: "rules",
    label: { en: "Rules", zh: "規則" },
    path: "/rules",
    links: [
      { path: "/rules", label: { en: "Rule explorer", zh: "規則庫" } },
      { path: "/coverage", label: { en: "Framework coverage", zh: "框架覆蓋" } },
      { path: "/atd", label: { en: "ATD techniques", zh: "ATD 技法" } },
      { path: "/quality-standard", label: { en: "Quality standard", zh: "品質標準" } },
      { path: "/threats", label: { en: "Threat feed", zh: "威脅情資" } },
    ],
  },
  {
    key: "tools",
    label: { en: "Tools", zh: "工具" },
    path: "/router",
    links: [
      { path: "/router", label: { en: "ATR Router (not public yet)", zh: "ATR Router（尚未公開）" } },
      { path: "/eval", label: { en: "ATR Eval (not public yet)", zh: "ATR Eval（尚未公開）" } },
    ],
  },
  {
    key: "adopt",
    label: { en: "Adopt", zh: "採用" },
    path: "/start",
    links: [
      { path: "/start", label: { en: "Start here", zh: "從這裡開始" } },
      { path: "/integrate", label: { en: "Integrate", zh: "整合" } },
      { path: "/docs/integrations", label: { en: "Integrations matrix", zh: "整合對照表" } },
      { path: "/compliance", label: { en: "Compliance mappings", zh: "合規對應" } },
      { path: "/ecosystem", label: { en: "Adopters", zh: "採用者" } },
      { path: "/implementers", label: { en: "Implementer report", zh: "實作者報告" } },
    ],
  },
  {
    key: "community",
    label: { en: "Community", zh: "社群" },
    path: "/community",
    links: [
      { path: "/community", label: { en: "People", zh: "成員" } },
      { path: "/contribute", label: { en: "Contribute", zh: "參與貢獻" } },
      { path: "/governance", label: { en: "Governance", zh: "治理" } },
      { path: "/charter", label: { en: "Charter", zh: "章程" } },
    ],
  },
  {
    key: "about",
    label: { en: "About", zh: "關於" },
    path: "/about",
    links: [
      { path: "/about", label: { en: "About ATR", zh: "關於 ATR" } },
      { path: "/research", label: { en: "Research", zh: "研究" } },
      { path: "/blog", label: { en: "Blog", zh: "部落格" } },
      { path: "/responsible-use", label: { en: "Responsible use", zh: "負責任使用" } },
      { path: "/faq", label: { en: "FAQ", zh: "常見問題" } },
      { path: "/contact", label: { en: "Contact", zh: "聯絡" } },
    ],
  },
];

/** Footer-only links: pages kept at their URLs but out of the header. */
export const FOOTER_EXTRA: ReadonlyArray<NavLink> = [
  { path: "/red-team", label: { en: "Red team program", zh: "紅隊計畫" } },
  { path: "/sovereign-ai-defense", label: { en: "Sovereign AI", zh: "主權 AI" } },
  { path: "/partner-sync", label: { en: "Partner live sync", zh: "夥伴即時同步" } },
  { path: "/integrate/garak", label: { en: "garak and ATR", zh: "garak 與 ATR" } },
  { path: "/privacy", label: { en: "Privacy (draft)", zh: "隱私（草稿）" } },
  { path: "/terms", label: { en: "Terms (draft)", zh: "條款（草稿）" } },
];

export function pick(text: Bilingual, locale: string): string {
  return locale === "zh" ? text.zh : text.en;
}
