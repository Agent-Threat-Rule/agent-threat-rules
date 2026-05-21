/**
 * Parse ADOPTERS.md from the repo root and return typed entries grouped by
 * tier. ADOPTERS.md is the single source of truth for the website's
 * /ecosystem page — never inline adopter data anywhere else, always
 * import this loader.
 *
 * The parser is deliberately permissive: malformed entries are skipped
 * with a console warning rather than crashing the build. This means a
 * casual contributor who fat-fingers a field still gets their PR merged
 * (after review) without breaking the static build.
 *
 * @module lib/adopters
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

/** Source location for the canonical adopters file (one level up from `website/`). */
const ADOPTERS_PATH = join(process.cwd(), "..", "ADOPTERS.md");

/** Adopter tier — matches the section headings in ADOPTERS.md. */
export type AdopterTier = "S" | "1" | "2" | "3" | "4";

/** Integration shape categories — matches the `Type:` field schema in ADOPTERS.md. */
export type IntegrationType =
  | "engine"
  | "rule-import"
  | "category-subset"
  | "adapter"
  | "reference"
  | "sidecar-proxy"
  | "other";

/** One adopter entry parsed from a `### Project Name` block. */
export interface Adopter {
  /** Project display name (the `### ...` heading text). */
  name: string;
  /** Owning organisation as declared by the adopter. May be "Independent". */
  org: string;
  /** Integration type from the fixed enum. Unknown values normalised to "other". */
  type: IntegrationType;
  /** One-sentence integration description. */
  integration: string;
  /** Evidence URL — merged PR, public docs, blog post, etc. */
  evidence: string;
  /** ISO date of public adoption (YYYY-MM-DD). */
  since: string;
  /** Adoption status. */
  status: "shipped" | "in-review" | "planning";
  /** Optional categories the project consumes. */
  categories?: string[];
  /** Which tier section this entry was found under. */
  tier: AdopterTier;
}

/** Result of parsing ADOPTERS.md — adopters grouped by tier, in declaration order. */
export interface AdoptersData {
  tierS: Adopter[];
  tier1: Adopter[];
  tier2: Adopter[];
  tier3: Adopter[];
  tier4: Adopter[];
  /** Total parsed entries across all tiers. */
  count: number;
}

/** Headings in ADOPTERS.md that introduce a tier section. */
const TIER_HEADINGS: Array<{ heading: string; tier: AdopterTier }> = [
  { heading: "Tier S", tier: "S" },
  { heading: "Tier 1", tier: "1" },
  { heading: "Tier 2", tier: "2" },
  { heading: "Tier 3", tier: "3" },
  { heading: "Tier 4", tier: "4" },
];

/**
 * Normalise an integration type string from ADOPTERS.md to the
 * `IntegrationType` enum. Anything unrecognised collapses to `"other"`
 * so the website renders without crashing.
 */
function normaliseType(raw: string): IntegrationType {
  const t = raw.trim().toLowerCase();
  if (
    t === "engine" ||
    t === "rule-import" ||
    t === "category-subset" ||
    t === "adapter" ||
    t === "reference" ||
    t === "sidecar-proxy"
  ) {
    return t;
  }
  return "other";
}

/**
 * Normalise a status string to the allowed set. Unrecognised values
 * collapse to `"shipped"` since that is the most common case and a
 * harmless default for display purposes.
 */
function normaliseStatus(raw: string): "shipped" | "in-review" | "planning" {
  const s = raw.trim().toLowerCase();
  if (s === "in-review" || s === "planning") return s;
  return "shipped";
}

/**
 * Extract the value following a bold field marker in a markdown bullet
 * list. Handles both:
 *   - **Org**: value
 *   - - **Org**: value
 *   - **Org**: value (with trailing detail)
 * Returns undefined when the field is absent.
 */
function extractField(block: string, fieldName: string): string | undefined {
  const re = new RegExp(`\\*\\*${fieldName}\\*\\*\\s*:\\s*([^\\n]+)`, "i");
  const m = block.match(re);
  return m ? m[1].trim() : undefined;
}

/**
 * Parse a single `### Heading` adopter block into an `Adopter`, or return
 * null if required fields are missing.
 */
function parseEntry(block: string, tier: AdopterTier): Adopter | null {
  const nameMatch = block.match(/^###\s+(.+?)\s*$/m);
  if (!nameMatch) return null;
  const name = nameMatch[1].trim();

  const org = extractField(block, "Org") ?? "Independent";
  const typeRaw = extractField(block, "Type") ?? "other";
  const integration = extractField(block, "Integration");
  const evidence = extractField(block, "Evidence");
  const since = extractField(block, "Since") ?? "";
  const statusRaw = extractField(block, "Status") ?? "shipped";
  const categoriesRaw = extractField(block, "Categories");

  if (!integration || !evidence) {
    // Required fields missing — skip rather than render a broken card.
    // The parser is permissive on purpose: see file header.
    if (typeof process !== "undefined" && process.env.NODE_ENV !== "production") {
      // eslint-disable-next-line no-console
      console.warn(`[adopters] skipping entry "${name}" — missing Integration or Evidence`);
    }
    return null;
  }

  // Evidence values may be wrapped in angle brackets `<url>`, the markdown
  // autolink form, or a `[label](url)` pair. Normalise to the URL.
  let evidenceUrl = evidence;
  const angleMatch = evidence.match(/^<(.+)>$/);
  if (angleMatch) evidenceUrl = angleMatch[1];
  const linkMatch = evidence.match(/^\[.*?\]\((.+?)\)/);
  if (linkMatch) evidenceUrl = linkMatch[1];

  const categories = categoriesRaw
    ? categoriesRaw
        .replace(/[`*]/g, "")
        .split(",")
        .map((c) => c.trim())
        .filter(Boolean)
    : undefined;

  return {
    name,
    org,
    type: normaliseType(typeRaw),
    integration,
    evidence: evidenceUrl,
    since,
    status: normaliseStatus(statusRaw),
    categories,
    tier,
  };
}

/**
 * Split a tier section (between `## Tier X — ...` and the next `## ` or
 * EOF) into individual `### Heading` blocks.
 */
function splitEntries(section: string): string[] {
  // Split the tier section on lines that begin a `### Heading`. The
  // pattern is line-anchored and uses `[\s\S]` instead of the `/s` flag
  // because the project targets ES2017 (which lacks dotAll support).
  const blocks: string[] = [];
  const lines = section.split("\n");
  let current: string[] = [];
  for (const line of lines) {
    if (/^###\s+/.test(line)) {
      if (current.length > 0) {
        blocks.push(current.join("\n"));
      }
      current = [line];
    } else if (current.length > 0) {
      current.push(line);
    }
  }
  if (current.length > 0) {
    blocks.push(current.join("\n"));
  }
  return blocks;
}

/**
 * Load and parse ADOPTERS.md. Called once per static-build by the
 * /ecosystem page. Returns empty arrays if the file is missing — the
 * page renders an empty-state message rather than failing the build.
 */
export function loadAdopters(): AdoptersData {
  let raw: string;
  try {
    raw = readFileSync(ADOPTERS_PATH, "utf-8");
  } catch {
    return { tierS: [], tier1: [], tier2: [], tier3: [], tier4: [], count: 0 };
  }

  const byTier: Record<AdopterTier, Adopter[]> = {
    S: [],
    "1": [],
    "2": [],
    "3": [],
    "4": [],
  };

  // ES2017 lacks the `/s` regex flag, so we extract each tier section
  // by walking line-by-line. The body of a tier starts at its `## Tier X`
  // heading and runs until the next top-level `## ` heading or EOF.
  const lines = raw.split("\n");
  let currentTier: AdopterTier | null = null;
  let currentSection: string[] = [];
  const sections: Array<{ tier: AdopterTier; body: string }> = [];
  for (const line of lines) {
    const topLevel = /^## (.+?)$/.exec(line);
    if (topLevel) {
      // Flush the previous tier (if any) before starting a new section.
      if (currentTier !== null) {
        sections.push({ tier: currentTier, body: currentSection.join("\n") });
      }
      const heading = topLevel[1];
      const match = TIER_HEADINGS.find((t) => heading.startsWith(t.heading));
      currentTier = match ? match.tier : null;
      currentSection = [];
      continue;
    }
    if (currentTier !== null) currentSection.push(line);
  }
  if (currentTier !== null) {
    sections.push({ tier: currentTier, body: currentSection.join("\n") });
  }

  for (const { tier, body } of sections) {
    const blocks = splitEntries(body);
    for (const block of blocks) {
      const entry = parseEntry(block, tier);
      if (entry) byTier[tier].push(entry);
    }
  }

  const count =
    byTier.S.length +
    byTier["1"].length +
    byTier["2"].length +
    byTier["3"].length +
    byTier["4"].length;

  return {
    tierS: byTier.S,
    tier1: byTier["1"],
    tier2: byTier["2"],
    tier3: byTier["3"],
    tier4: byTier["4"],
    count,
  };
}

/**
 * Display label for an adopter tier. EN and ZH variants.
 */
export function tierLabel(tier: AdopterTier, locale: "en" | "zh"): string {
  const labels: Record<AdopterTier, { en: string; zh: string }> = {
    S: {
      en: "Standards bodies & frameworks",
      zh: "標準同儕與框架",
    },
    "1": {
      en: "Production deployments",
      zh: "生產部署",
    },
    "2": {
      en: "Open-source tooling & SDK integrations",
      zh: "開源工具與 SDK 整合",
    },
    "3": {
      en: "Documentation references & awesome-lists",
      zh: "文件引用與 awesome-list",
    },
    "4": {
      en: "Commercial implementations",
      zh: "商業實作",
    },
  };
  return labels[tier][locale];
}

/**
 * One-line description of what each tier means, for the section sub-head.
 */
export function tierDescription(tier: AdopterTier, locale: "en" | "zh"): string {
  const descriptions: Record<AdopterTier, { en: string; zh: string }> = {
    S: {
      en: "Adopters whose adoption is itself a public-good interoperability artefact — taxonomies, profiles, schemas published by neutral bodies.",
      zh: "其本身就是公共財互操作性產出的採用者:由中立機構發佈的分類、規範對應、schema。",
    },
    "1": {
      en: "Adopters who ship ATR in a publicly-available customer-facing product.",
      zh: "在公開、面向客戶的產品中部署 ATR 的採用者。",
    },
    "2": {
      en: "Open-source developer tools, frameworks, and SDKs that integrate ATR.",
      zh: "整合 ATR 的開源開發者工具、框架、SDK。",
    },
    "3": {
      en: "Adopters who reference ATR in public catalogues, awesome-lists, or documentation indices.",
      zh: "在公開目錄、awesome-list、文件索引中引用 ATR 的採用者。",
    },
    "4": {
      en: "Vendors offering commercial support, hosted engines, or enterprise SLAs around ATR.",
      zh: "提供商業支援、託管引擎、或圍繞 ATR 提供企業 SLA 的供應商。",
    },
  };
  return descriptions[tier][locale];
}
