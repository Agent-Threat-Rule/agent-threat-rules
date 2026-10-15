#!/usr/bin/env tsx
/**
 * generate-saf-mcp-mapping.ts
 *
 * Renders docs/SAFE-MCP-MAPPING.md from the hand-reviewed pairs in
 * docs/saf-mcp-mapping.json. The JSON is the source of truth; the Markdown is
 * generated and must not be edited by hand.
 *
 * Every pair links one ATR rule to one active technique in the SAF Framework
 * Model v2 (secure-agentic-framework/saf-mcp, research/framework-model.yml).
 * Relationships follow the SAF detection registry semantics (direct / partial /
 * adjacent). The document is an inventory of candidate mappings, not a
 * coverage or effectiveness claim, so it carries no percentage.
 *
 * Usage:
 *   npx tsx scripts/generate-saf-mcp-mapping.ts          write the Markdown
 *   npx tsx scripts/generate-saf-mcp-mapping.ts --check  exit 1 if it is stale
 */

import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { laneAllows } from "../src/quality/rule-contract.js";

const DEFAULT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DATA_PATH = "docs/saf-mcp-mapping.json";
const OUTPUT_PATH = "docs/SAFE-MCP-MAPPING.md";

export const RELATIONSHIPS = ["direct", "partial", "adjacent"] as const;
export const MODALITIES = [
  "content", "static", "runtime", "gateway", "endpoint", "identity",
  "network", "memory", "multimodal", "model-lifecycle", "on-chain",
] as const;

export interface SafTactic {
  readonly id: string;
  readonly name: string;
}

export interface SafTechnique {
  readonly id: string;
  readonly name: string;
  readonly tactics: readonly string[];
}

export interface SafMapping {
  readonly technique_id: string;
  readonly rule_id: string;
  readonly rule_path: string;
  readonly relationship: (typeof RELATIONSHIPS)[number];
  readonly modalities: readonly string[];
  readonly evidence: string;
}

export interface SafMappingFile {
  readonly framework: {
    readonly name: string;
    readonly repository: string;
    readonly path: string;
    readonly commit: string;
    readonly commit_date: string;
  };
  readonly atr_version_reviewed: string;
  readonly reviewed_on: string;
  readonly method: string;
  readonly tactics: readonly SafTactic[];
  readonly techniques: readonly SafTechnique[];
  readonly mappings: readonly SafMapping[];
}

/**
 * Techniques that research/framework-model.yml marks lifecycle_status: deprecated
 * at the pinned commit. The techniques list in the JSON is hand-copied, so this
 * is what stops a deprecated id from being listed (and counted in the total).
 * Update it whenever framework.commit moves.
 */
export const DEPRECATED_AT_PIN = [
  "SAF-T1104", "SAF-T1109", "SAF-T1205", "SAF-T1301",
  "SAF-T1306", "SAF-T1309", "SAF-T1702", "SAF-T1912",
] as const;

/** sync-stats.ts and audit-mappings.ts rewrite or flag the first "<N> rules" in this doc. */
const RULE_COUNT_PATTERN = /\d{2,4}\s*rules/i;

/**
 * What a rule file declares, or null when the file is missing. `runs` is false
 * when the engine evaluates the rule in no lane at all (status draft or
 * deprecated is skipped in src/engine.ts; maturity deprecated fails laneAllows),
 * so a pair backed by it would name a detection that never fires.
 */
export interface DeclaredRule {
  readonly id: string | null;
  readonly runs: boolean;
}
export type RuleLookup = (rulePath: string) => DeclaredRule | null;

export function ruleFromDisk(root: string): RuleLookup {
  return (rulePath) => {
    const full = join(root, rulePath);
    if (!existsSync(full)) return null;
    const doc = yaml.load(readFileSync(full, "utf8")) as { id?: unknown; status?: unknown; maturity?: unknown } | null;
    const id = typeof doc?.id === "string" ? doc.id : null;
    const runs = doc?.status !== "draft" && doc?.status !== "deprecated" && laneAllows(doc?.maturity, "hunt");
    return { id, runs };
  };
}

function duplicates(values: readonly string[]): string[] {
  return values.filter((v, i) => values.indexOf(v) !== i);
}

/** Returns every problem in the mapping file; an empty list means it is valid. */
export function validateMapping(data: SafMappingFile, ruleAt: RuleLookup): string[] {
  const techniqueIds = new Set(data.techniques.map((t) => t.id));
  const tacticIds = new Set(data.tactics.map((t) => t.id));
  const seen = new Set<string>();
  const problems: string[] = [];

  for (const id of duplicates(data.tactics.map((t) => t.id))) problems.push(`${id}: duplicate tactic`);
  for (const id of duplicates(data.techniques.map((t) => t.id))) problems.push(`${id}: duplicate technique`);
  if (RULE_COUNT_PATTERN.test(data.method)) problems.push("method: contains a rule count that sync-stats would rewrite");
  for (const technique of data.techniques) {
    if ((DEPRECATED_AT_PIN as readonly string[]).includes(technique.id)) {
      problems.push(`${technique.id}: deprecated in the pinned framework model`);
    }
    if (technique.tactics.length === 0) problems.push(`${technique.id}: no tactic`);
    for (const tactic of technique.tactics) {
      if (!tacticIds.has(tactic)) problems.push(`${technique.id}: unknown tactic ${tactic}`);
    }
  }
  for (const m of data.mappings) {
    const key = `${m.technique_id} ${m.rule_id}`;
    if (seen.has(key)) problems.push(`${key}: duplicate pair`);
    seen.add(key);
    if (!techniqueIds.has(m.technique_id)) problems.push(`${key}: technique is not an active SAF technique`);
    if (!RELATIONSHIPS.includes(m.relationship)) problems.push(`${key}: unknown relationship ${m.relationship}`);
    if (m.modalities.length === 0) problems.push(`${key}: no modality`);
    for (const modality of duplicates(m.modalities)) problems.push(`${key}: duplicate modality ${modality}`);
    for (const modality of m.modalities) {
      if (!(MODALITIES as readonly string[]).includes(modality)) problems.push(`${key}: unknown modality ${modality}`);
    }
    if (m.evidence.trim() === "") problems.push(`${key}: empty evidence`);
    if (RULE_COUNT_PATTERN.test(m.evidence)) problems.push(`${key}: evidence contains a rule count that sync-stats would rewrite`);
    const rule = ruleAt(m.rule_path);
    if (rule === null) problems.push(`${key}: rule file ${m.rule_path} not found`);
    else if (rule.id !== m.rule_id) problems.push(`${key}: ${m.rule_path} declares ${rule.id}`);
    else if (!rule.runs) problems.push(`${key}: ${m.rule_id} is draft or deprecated, so the engine never runs it`);
  }
  return problems;
}

/** Escapes a table cell. `<` is escaped so GitHub does not strip "<IMPORTANT>", "<url>" etc. as HTML tags. */
function escapeCell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/</g, "&lt;").replace(/\s*\n\s*/g, " ").trim();
}

function shortCommit(sha: string): string {
  return sha.slice(0, 7);
}

/** Renders the Markdown document. Pure: same input, same output. */
export function renderMarkdown(data: SafMappingFile): string {
  const byTechnique = new Map<string, SafMapping[]>();
  for (const m of data.mappings) {
    byTechnique.set(m.technique_id, [...(byTechnique.get(m.technique_id) ?? []), m]);
  }
  const mapped = data.techniques.filter((t) => byTechnique.has(t.id));
  const unmapped = data.techniques.filter((t) => !byTechnique.has(t.id));
  const adjacentOnly = mapped.filter((t) => (byTechnique.get(t.id) ?? []).every((m) => m.relationship === "adjacent"));
  const tacticName = new Map(data.tactics.map((t) => [t.id, t.name]));
  const fw = data.framework;

  const lines: string[] = [
    "# ATR → SAF-MCP Technique Mapping",
    "",
    `<!-- Generated from ${DATA_PATH} by scripts/generate-saf-mcp-mapping.ts. Do not edit by hand. -->`,
    "",
    `Framework: ${fw.name} — [${fw.repository.replace("https://github.com/", "")}](${fw.repository}), \`${fw.path}\` at \`${shortCommit(fw.commit)}\` (${fw.commit_date})`,
    `ATR release reviewed: v${data.atr_version_reviewed} (reviewed ${data.reviewed_on})`,
    "",
    "## How to read this",
    "",
    `- ${data.method}`,
    "- `partial`: the rule represents a bounded subset of the technique. `adjacent`: the rule provides supporting context but does not by itself represent the technique. These follow the SAF detection registry definitions.",
    "- Modalities name the observation surfaces the rule actually inspects, using the SAF registry vocabulary.",
    "- This is an inventory of candidate mappings, not a coverage or effectiveness claim, and none of the pairs has been validated by SAF. SAF decides whether an external mapping is validated in its own registry.",
    "- Deprecated SAF techniques are not mapped.",
    "- Per-rule `references.safe_mcp` tags inside rule files are author-declared and are not reconciled with this table; where they differ, this table is the reviewed result.",
    "",
    "## Summary",
    "",
    `- Active techniques in the framework model: ${data.techniques.length}`,
    `- Techniques with at least one reviewed ATR rule (partial or adjacent): ${mapped.length}`,
    `- Of those, techniques whose only reviewed rules are adjacent (supporting context, not detection of the technique itself): ${adjacentOnly.length}`,
    `- Techniques with none: ${unmapped.length} (listed at the end)`,
    `- Reviewed pairs: ${data.mappings.length}`,
    "",
    "## Mappings",
    "",
  ];

  for (const technique of mapped) {
    const tactics = technique.tactics.map((id) => `${id} ${tacticName.get(id) ?? ""}`.trim()).join(", ");
    lines.push(`### ${technique.id} — ${technique.name}`, "", `Tactic: ${tactics}`, "");
    lines.push("| ATR rule | Relationship | Modalities | Evidence |", "|---|---|---|---|");
    for (const m of byTechnique.get(technique.id) ?? []) {
      const link = `[${m.rule_id}](../${m.rule_path})`;
      lines.push(`| ${link} | ${m.relationship} | ${m.modalities.join(", ")} | ${escapeCell(m.evidence)} |`);
    }
    lines.push("");
  }

  lines.push("## Techniques with no reviewed ATR rule", "");
  for (const technique of unmapped) lines.push(`- ${technique.id} — ${technique.name}`);
  lines.push("");
  return lines.join("\n");
}

function main(argv: readonly string[], root = DEFAULT_ROOT): number {
  const data = JSON.parse(readFileSync(join(root, DATA_PATH), "utf8")) as SafMappingFile;
  const problems = validateMapping(data, ruleFromDisk(root));
  if (problems.length > 0) {
    console.error(`${DATA_PATH} has ${problems.length} problem(s):\n  ${problems.join("\n  ")}`);
    return 1;
  }
  const rendered = renderMarkdown(data);
  const outPath = join(root, OUTPUT_PATH);
  if (argv.includes("--check")) {
    const current = existsSync(outPath) ? readFileSync(outPath, "utf8") : "";
    if (current !== rendered) {
      console.error(`${OUTPUT_PATH} is stale. Run: npx tsx scripts/generate-saf-mcp-mapping.ts`);
      return 1;
    }
    console.log(`${OUTPUT_PATH} is up to date.`);
    return 0;
  }
  writeFileSync(outPath, rendered);
  console.log(`Wrote ${OUTPUT_PATH} (${data.mappings.length} pairs).`);
  return 0;
}

const isMain =
  process.argv[1] !== undefined &&
  realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url));
if (isMain) {
  process.exitCode = main(process.argv.slice(2));
}
