import { CATEGORY_DESC } from "./category-desc";
import { categoryDisplayName } from "./categories";

/**
 * Documentation sidebar: the standard as one navigable document, in the same
 * order a reader meets it. Paths are below the locale prefix; some point at
 * pages that live outside /docs and are linked, not duplicated.
 */

export type Bilingual = { en: string; zh: string };

export interface DocsLink {
  path: string;
  label: Bilingual;
}

export interface DocsSection {
  key: string;
  numeral: string;
  label: Bilingual;
  links: ReadonlyArray<DocsLink>;
}

export const CATEGORY_ORDER: ReadonlyArray<string> = Object.keys(CATEGORY_DESC);

const GREEK = ["Α", "Β", "Γ", "Δ", "Ε", "Ζ", "Η", "Θ", "Ι", "Κ", "Λ", "Μ"];

/** Greek letter for a category, in CATEGORY_ORDER: the home frieze, the rule list and the docs pages all use it. */
export function categoryLetter(category: string): string {
  const i = CATEGORY_ORDER.indexOf(category);
  return GREEK[i] ?? "?";
}

export const DOCS_SECTIONS: ReadonlyArray<DocsSection> = [
  {
    key: "standard",
    numeral: "I",
    label: { en: "Standard", zh: "標準" },
    links: [
      { path: "/docs", label: { en: "Overview", zh: "總覽" } },
      { path: "/spec", label: { en: "Specification", zh: "規格" } },
      { path: "/quality-standard", label: { en: "Maturity and lanes", zh: "成熟度與 lane" } },
      { path: "/changelog", label: { en: "Changelog", zh: "版本歷程" } },
      { path: "/errata", label: { en: "Errata", zh: "勘誤" } },
      { path: "/glossary", label: { en: "Glossary", zh: "詞彙表" } },
    ],
  },
  {
    key: "categories",
    numeral: "II",
    label: { en: "Threat categories", zh: "威脅類別" },
    links: CATEGORY_ORDER.map((c) => ({
      path: `/docs/categories/${c}`,
      label: { en: `${categoryLetter(c)}. ${categoryDisplayName(c, "en")}`, zh: `${categoryLetter(c)}. ${categoryDisplayName(c, "zh")}` },
    })),
  },
  {
    key: "crosswalks",
    numeral: "III",
    label: { en: "Crosswalks", zh: "框架對照" },
    links: [
      { path: "/docs/crosswalks", label: { en: "All crosswalks", zh: "全部對照" } },
      { path: "/docs/crosswalks/owasp-agentic-top-10", label: { en: "OWASP Agentic Top 10", zh: "OWASP Agentic Top 10" } },
      { path: "/docs/crosswalks/owasp-agentic-skills-top-10", label: { en: "OWASP Agentic Skills Top 10", zh: "OWASP Agentic Skills Top 10" } },
      { path: "/docs/crosswalks/safe-mcp", label: { en: "SAF-MCP", zh: "SAF-MCP" } },
      { path: "/docs/crosswalks/nsa-mcp", label: { en: "NSA MCP guidance", zh: "NSA MCP 指引" } },
      { path: "/coverage", label: { en: "Coverage overview", zh: "覆蓋總覽" } },
      { path: "/compliance", label: { en: "Compliance mappings", zh: "合規對應" } },
      { path: "/compliance/nist-ai-rmf", label: { en: "NIST AI RMF", zh: "NIST AI RMF" } },
    ],
  },
  {
    key: "implement",
    numeral: "IV",
    label: { en: "Implement", zh: "實作" },
    links: [
      { path: "/integrate", label: { en: "Integrate", zh: "整合" } },
      { path: "/docs/integrations", label: { en: "Integrations matrix", zh: "整合對照表" } },
      { path: "/conformance", label: { en: "Conformance", zh: "符規" } },
      { path: "/implementers", label: { en: "Implementer report", zh: "實作者報告" } },
    ],
  },
  {
    key: "evidence",
    numeral: "V",
    label: { en: "Evidence and audit", zh: "證據與稽核" },
    links: [
      { path: "/docs/evidence", label: { en: "Evidence guide", zh: "證據指南" } },
      { path: "/docs/auditor-kit", label: { en: "Auditor kit", zh: "稽核員工具包" } },
      { path: "/research", label: { en: "Measurements", zh: "量測" } },
    ],
  },
  {
    key: "taxonomies",
    numeral: "VI",
    label: { en: "Taxonomies", zh: "分類法" },
    links: [
      { path: "/atd", label: { en: "ATD techniques", zh: "ATD 技法" } },
      { path: "/threats", label: { en: "Threat feed", zh: "威脅情資" } },
    ],
  },
  {
    key: "governance",
    numeral: "VII",
    label: { en: "Community and governance", zh: "社群與治理" },
    links: [
      { path: "/community", label: { en: "Community", zh: "社群" } },
      { path: "/governance", label: { en: "Governance", zh: "治理" } },
      { path: "/charter", label: { en: "Charter", zh: "章程" } },
      { path: "/contribute", label: { en: "Contribute", zh: "參與貢獻" } },
      { path: "/citations", label: { en: "Citation", zh: "引用" } },
      { path: "/responsible-use", label: { en: "Responsible use", zh: "負責任使用" } },
    ],
  },
  {
    key: "help",
    numeral: "VIII",
    label: { en: "Help and legal", zh: "說明與法律" },
    links: [
      { path: "/faq", label: { en: "FAQ", zh: "常見問題" } },
      { path: "/contact", label: { en: "Contact", zh: "聯絡" } },
      { path: "/privacy", label: { en: "Privacy notice (draft)", zh: "隱私說明（草稿）" } },
      { path: "/terms", label: { en: "Terms of use (draft)", zh: "使用條款（草稿）" } },
    ],
  },
];

export function pick(text: Bilingual, locale: string): string {
  return locale === "zh" ? text.zh : text.en;
}
