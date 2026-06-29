/**
 * Mapping Coverage Audit — read-only sweep of every rules/**\/*.yaml, reporting
 * how many rules carry each framework mapping across two tiers:
 *   - threat frameworks under `references:` (OWASP / MITRE ATLAS / CVE / ...)
 *   - regulatory frameworks under `compliance:` (EU AI Act / NIST AI RMF / ISO 42001 / ...)
 *
 * Also reports per-category compliance gaps, the distinct framework identifiers
 * in use (so typos / drift surface), and stale crosswalk docs whose hardcoded
 * rule count no longer matches the live corpus.
 *
 * NEVER mutates rules. Safe to run anytime; built for periodic maintenance and CI.
 * Every number comes straight from disk — the single source of truth.
 *
 * Usage:
 *   npx tsx scripts/audit-mappings.ts          human-readable report (default)
 *   npx tsx scripts/audit-mappings.ts --json   machine-readable JSON (for CI / stats)
 *   npx tsx scripts/audit-mappings.ts --gaps    also list rule IDs missing priority frameworks
 *
 *   npm run audit:mappings
 */

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";
import { loadAll } from "js-yaml";

const RULES_DIR = join(import.meta.dirname, "..", "rules");
const DOCS_DIR = join(import.meta.dirname, "..", "docs");

// Compliance frameworks whose per-category gaps we track explicitly.
const PRIORITY_COMPLIANCE = ["eu_ai_act", "nist_ai_rmf", "iso_42001"] as const;

// Crosswalk docs that hardcode a rule count in their header — flag when stale.
const CROSSWALK_DOCS = [
  "SAFE-MCP-MAPPING.md",
  "FIVE-EYES-MAPPING.md",
  "OWASP-AST10-MAPPING.md",
  "NSA-MCP-MAPPING.md",
  "ETSI-TS-104223-MAPPING.md",
  "FINOS-AI-GOVERNANCE-MAPPING.md",
  "MCP-38-MAPPING.md",
  "MITRE-ATLAS-MAPPING.md",
  "OWASP-AGENTIC-MAPPING.md",
  "OWASP-AGENTIC-MATURITY-MAPPING.md",
  "OWASP-AISVS-MAPPING.md",
  "OWASP-AIVSS-MAPPING.md",
] as const;

interface RuleMapping {
  readonly id: string;
  readonly category: string;
  readonly references: readonly string[];
  readonly compliance: readonly string[];
}

interface FrameworkStat {
  readonly key: string;
  readonly count: number;
  readonly pct: number;
}

type Counter = Map<string, number>;

function bump(map: Counter, key: string, by = 1): void {
  map.set(key, (map.get(key) ?? 0) + by);
}

function findYamlFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...findYamlFiles(full));
    } else if (entry.endsWith(".yaml") || entry.endsWith(".yml")) {
      out.push(full);
    }
  }
  return out;
}

function keysOf(block: unknown): string[] {
  return block && typeof block === "object" && !Array.isArray(block)
    ? Object.keys(block as Record<string, unknown>)
    : [];
}

function complianceIdentifier(item: unknown): string {
  if (item && typeof item === "object") {
    const o = item as Record<string, unknown>;
    const v = o.article ?? o.subcategory ?? o.clause ?? o.section ?? o.control ?? o.id;
    if (v !== undefined) return String(v);
  }
  return String(item);
}

function referenceIdentifier(item: unknown): string {
  if (item && typeof item === "object") {
    const o = item as Record<string, unknown>;
    const v = o.id ?? o.technique ?? o.name;
    if (v !== undefined) return String(v).split(" - ")[0].trim();
  }
  return String(item).split(" - ")[0].trim();
}

interface ParseResult {
  readonly rules: RuleMapping[];
  readonly refValues: Map<string, Counter>;
  readonly compValues: Map<string, Counter>;
  readonly parseErrors: string[];
}

function parseAllRules(files: readonly string[]): ParseResult {
  const rules: RuleMapping[] = [];
  const refValues = new Map<string, Counter>();
  const compValues = new Map<string, Counter>();
  const parseErrors: string[] = [];

  const collect = (store: Map<string, Counter>, key: string, value: string): void => {
    if (!store.has(key)) store.set(key, new Map());
    bump(store.get(key)!, value);
  };

  for (const file of files) {
    let docs: unknown[];
    try {
      docs = (loadAll(readFileSync(file, "utf-8")) ?? []) as unknown[];
    } catch (err) {
      parseErrors.push(`${file}: ${(err as Error).message}`);
      continue;
    }
    for (const doc of docs) {
      if (!doc || typeof doc !== "object") continue;
      const rule = doc as Record<string, unknown>;
      const id = rule.id;
      if (typeof id !== "string" || !id.startsWith("ATR-")) continue;

      const category = file.slice(RULES_DIR.length + 1).split("/")[0] || "(root)";
      const refKeys = keysOf(rule.references);
      const compKeys = keysOf(rule.compliance);

      for (const k of refKeys) {
        const arr = (rule.references as Record<string, unknown>)[k];
        if (Array.isArray(arr)) arr.forEach((i) => collect(refValues, k, referenceIdentifier(i)));
      }
      for (const k of compKeys) {
        const arr = (rule.compliance as Record<string, unknown>)[k];
        if (Array.isArray(arr)) arr.forEach((i) => collect(compValues, k, complianceIdentifier(i)));
      }

      rules.push({ id, category, references: refKeys, compliance: compKeys });
    }
  }
  return { rules, refValues, compValues, parseErrors };
}

function tallyFrameworks(rules: readonly RuleMapping[], tier: "references" | "compliance"): FrameworkStat[] {
  const counts: Counter = new Map();
  for (const r of rules) for (const k of r[tier]) bump(counts, k);
  const total = rules.length || 1;
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count, pct: (100 * count) / total }))
    .sort((a, b) => b.count - a.count);
}

interface CategoryGap {
  readonly category: string;
  readonly total: number;
  readonly covered: Record<string, number>;
}

function tallyByCategory(rules: readonly RuleMapping[]): CategoryGap[] {
  const totals: Counter = new Map();
  const covered = new Map<string, Counter>();
  for (const r of rules) {
    bump(totals, r.category);
    if (!covered.has(r.category)) covered.set(r.category, new Map());
    for (const fw of PRIORITY_COMPLIANCE) {
      if (r.compliance.includes(fw)) bump(covered.get(r.category)!, fw);
    }
  }
  return [...totals.entries()]
    .map(([category, total]) => ({
      category,
      total,
      covered: Object.fromEntries(PRIORITY_COMPLIANCE.map((fw) => [fw, covered.get(category)?.get(fw) ?? 0])),
    }))
    .sort((a, b) => b.total - a.total);
}

function staleDocs(liveTotal: number): { doc: string; stated: number }[] {
  const stale: { doc: string; stated: number }[] = [];
  for (const name of CROSSWALK_DOCS) {
    const path = join(DOCS_DIR, name);
    if (!existsSync(path)) continue;
    const header = readFileSync(path, "utf-8").slice(0, 1500);
    const match = header.match(/(\d{2,4})\s*rules/i);
    if (match) {
      const stated = Number(match[1]);
      if (stated !== liveTotal) stale.push({ doc: name, stated });
    }
  }
  return stale;
}

function pct(n: number): string {
  return `${n.toFixed(1)}%`;
}

function renderReport(data: ReturnType<typeof buildAudit>): void {
  const { total, refStats, compStats, categories, noCompliance, missing, stale, parseErrors, refValues, compValues } = data;
  const line = "─".repeat(64);

  console.log(`\nATR Mapping Coverage Audit`);
  console.log(line);
  console.log(`Rules audited: ${total}    Parse errors: ${parseErrors.length}\n`);

  console.log(`THREAT frameworks  (references:)`);
  for (const s of refStats) console.log(`  ${s.key.padEnd(20)} ${String(s.count).padStart(4)}  ${pct(s.pct).padStart(7)}`);

  console.log(`\nREGULATORY frameworks  (compliance:)`);
  for (const s of compStats) console.log(`  ${s.key.padEnd(20)} ${String(s.count).padStart(4)}  ${pct(s.pct).padStart(7)}`);

  console.log(`\nPriority compliance coverage by category`);
  const head = ["category".padEnd(22), ...PRIORITY_COMPLIANCE.map((f) => f.padStart(13))].join(" ");
  console.log(`  ${head}`);
  for (const c of categories) {
    const cells = PRIORITY_COMPLIANCE.map((fw) => {
      const n = c.covered[fw];
      return `${n}/${c.total} (${Math.round((100 * n) / c.total)}%)`.padStart(13);
    });
    console.log(`  ${c.category.padEnd(22)} ${cells.join(" ")}`);
  }

  console.log(`\nGaps`);
  console.log(`  Rules with NO compliance block: ${noCompliance.length} (${pct((100 * noCompliance.length) / total)})`);
  for (const fw of PRIORITY_COMPLIANCE) {
    const n = missing[fw].length;
    console.log(`  Rules missing ${fw}: ${n} (${pct((100 * n) / total)})`);
  }

  console.log(`\nDistinct identifiers in use (drift / typo check)`);
  for (const fw of PRIORITY_COMPLIANCE) {
    const vals = [...(compValues.get(fw)?.entries() ?? [])].sort((a, b) => b[1] - a[1]);
    console.log(`  ${fw}: ${vals.map(([v, n]) => `${v}(${n})`).join("  ") || "(none)"}`);
  }
  const atlas = refValues.get("mitre_atlas");
  if (atlas) console.log(`  mitre_atlas: ${atlas.size} distinct techniques`);

  if (stale.length) {
    console.log(`\nStale crosswalk docs (header rule-count != live ${total})`);
    for (const s of stale) console.log(`  ${s.doc}: header says ${s.stated} rules`);
  }

  if (data.listGaps) {
    console.log(`\nRule IDs missing eu_ai_act (${missing.eu_ai_act.length})`);
    console.log(`  ${missing.eu_ai_act.join(", ")}`);
  }

  if (parseErrors.length) {
    console.log(`\nParse errors`);
    for (const e of parseErrors.slice(0, 20)) console.log(`  ${e}`);
  }
  console.log("");
}

function buildAudit(listGaps: boolean) {
  const files = findYamlFiles(RULES_DIR);
  const { rules, refValues, compValues, parseErrors } = parseAllRules(files);
  const total = rules.length;

  const missing = Object.fromEntries(
    PRIORITY_COMPLIANCE.map((fw) => [fw, rules.filter((r) => !r.compliance.includes(fw)).map((r) => r.id)]),
  ) as Record<(typeof PRIORITY_COMPLIANCE)[number], string[]>;

  return {
    total,
    refStats: tallyFrameworks(rules, "references"),
    compStats: tallyFrameworks(rules, "compliance"),
    categories: tallyByCategory(rules),
    noCompliance: rules.filter((r) => r.compliance.length === 0).map((r) => r.id),
    missing,
    stale: staleDocs(total),
    parseErrors,
    refValues,
    compValues,
    listGaps,
  };
}

function toJson(data: ReturnType<typeof buildAudit>): unknown {
  return {
    rulesAudited: data.total,
    threatFrameworks: data.refStats,
    regulatoryFrameworks: data.compStats,
    priorityByCategory: data.categories,
    rulesWithoutCompliance: data.noCompliance.length,
    missingCounts: Object.fromEntries(PRIORITY_COMPLIANCE.map((fw) => [fw, data.missing[fw].length])),
    staleCrosswalkDocs: data.stale,
    parseErrors: data.parseErrors.length,
  };
}

// Coverage-floor gate: fail if any listed framework is below 100% rule coverage.
// Spec is a comma list of `tier:framework` (tier = references | compliance),
// e.g. --require-full=references:mitre_atlas,compliance:eu_ai_act. Keeps the
// website's "100% / every rule" claims honest by enforcing them in CI.
function requireFull(data: ReturnType<typeof buildAudit>, spec: string): number {
  let failures = 0;
  console.log(`\nCoverage-floor check (--require-full), corpus = ${data.total} rules`);
  for (const raw of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const [tier, fw] = raw.includes(":") ? raw.split(":") : ["compliance", raw];
    const stats = tier === "references" ? data.refStats : data.compStats;
    const stat = stats.find((s) => s.key === fw);
    const ok = stat !== undefined && stat.count === data.total;
    if (!ok) failures++;
    console.log(`  ${ok ? "PASS" : "FAIL"} ${tier}:${fw} — ${stat ? `${stat.count}/${data.total}` : "absent"}`);
  }
  console.log(failures === 0 ? "  all required frameworks at 100%\n" : `  ${failures} framework(s) below 100%\n`);
  return failures;
}

function main(): void {
  const args = new Set(process.argv.slice(2));
  const data = buildAudit(args.has("--gaps"));
  if (args.has("--json")) {
    console.log(JSON.stringify(toJson(data), null, 2));
  } else {
    renderReport(data);
  }
  const reqArg = process.argv.find((a) => a.startsWith("--require-full="));
  if (reqArg && requireFull(data, reqArg.slice("--require-full=".length)) > 0) {
    process.exitCode = 1;
  }
  if (data.parseErrors.length > 0) process.exitCode = 1;
}

main();
