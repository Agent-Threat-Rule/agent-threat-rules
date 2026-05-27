#!/usr/bin/env node
/**
 * check-rules-safety.ts — Auto-merge safety gate for ATR rule additions
 *
 * Per quality-gate policy (see docs/QUALITY-GATE.md), every new rule must
 * clear ALL of the following before it can auto-merge to main:
 *
 *   1. Metadata: test_cases.true_positives AND true_negatives both
 *      non-empty; author present and not "MiroFish Predicted".
 *   2. Own-TP-must-match: the rule's regex / conditions MUST actually
 *      match every entry in test_cases.true_positives. A rule that
 *      doesn't catch its own declared TPs is broken.
 *   3. Benign skill corpus: 0 FP across data/skill-benchmark/benign/*.md
 *      (currently 432 known-clean SKILL.md samples).
 *   4. Research-mention corpus: 0 FP across data/research-mentions/
 *      corpus.jsonl (curated samples of text that MENTIONS attacks
 *      without being attacks — papers, blogs, READMEs, course material).
 *   5. Cross-rule conflict: the new rule MUST NOT match ANY existing
 *      rule's test_cases.true_negatives. A rule that fires on another
 *      rule's known-benign set is a precision regression for that rule.
 *   6. Per-PR cap: ≤ MAX_NEW_PER_PR rule files (default 10).
 *
 * Exit 0 = safe to auto-merge
 * Exit 1 = any check failed → PR stays in human-review queue
 *
 * Usage (in tc-pr-back workflow):
 *   npx tsx scripts/check-rules-safety.ts --base origin/main
 *
 * Single-proposal mode (for /red-team and /cve-collector flows):
 *   npx tsx scripts/check-rules-safety.ts --file proposals/path.proposal.yaml
 */

import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { load as yamlLoad } from "js-yaml";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";

const MAX_NEW_PER_PR = Number(process.env.MAX_NEW_PER_PR ?? 10);
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BENIGN_DIR = join(REPO_ROOT, "data/skill-benchmark/benign");
const RESEARCH_MENTIONS_FILE = join(
  REPO_ROOT,
  "data/research-mentions/corpus.jsonl",
);
const BENIGN_EXTENDED_DIR = join(REPO_ROOT, "data/benign-corpus-extended");
const RULES_DIR = join(REPO_ROOT, "rules");

interface Failure {
  file: string;
  reason: string;
}

function parseArgs(): { base: string; file: string | null } {
  const argv = process.argv.slice(2);
  const baseIdx = argv.indexOf("--base");
  const base =
    baseIdx >= 0 ? (argv[baseIdx + 1] ?? "origin/main") : "origin/main";
  const fileIdx = argv.indexOf("--file");
  const file = fileIdx >= 0 ? (argv[fileIdx + 1] ?? null) : null;
  return { base, file };
}

/** Diff against base to find newly added rule files. */
function getNewRuleFiles(base: string): string[] {
  try {
    const out = execFileSync(
      "git",
      [
        "diff",
        "--name-only",
        "--diff-filter=A",
        `${base}...HEAD`,
        "--",
        "rules/",
      ],
      { cwd: REPO_ROOT, encoding: "utf-8" },
    ).trim();
    return out
      .split("\n")
      .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))
      .filter(Boolean);
  } catch (err) {
    console.error(
      `[safety-gate] git diff failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return [];
  }
}

/** Walk a directory recursively for .yaml/.yml files. */
function walkYamlFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const f = join(dir, entry);
    let s;
    try {
      s = statSync(f);
    } catch {
      continue;
    }
    if (s.isDirectory()) out.push(...walkYamlFiles(f));
    else if (s.isFile() && (entry.endsWith(".yaml") || entry.endsWith(".yml")))
      out.push(f);
  }
  return out;
}

interface JsonlSample {
  text: string;
  category?: string;
  source_type?: string;
}

function loadResearchMentions(): JsonlSample[] {
  if (!existsSync(RESEARCH_MENTIONS_FILE)) return [];
  const raw = readFileSync(RESEARCH_MENTIONS_FILE, "utf-8");
  const out: JsonlSample[] = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      out.push(JSON.parse(t) as JsonlSample);
    } catch {
      continue;
    }
  }
  return out;
}

interface ExtendedBenignSample {
  text: string;
  source: string;
  source_id: string;
}

/**
 * Load the extended benign corpus (arxiv abstracts, npm / pypi package
 * descriptions). One JSONL file per source under
 * data/benign-corpus-extended/.
 */
function loadExtendedBenign(): ExtendedBenignSample[] {
  if (!existsSync(BENIGN_EXTENDED_DIR)) return [];
  const out: ExtendedBenignSample[] = [];
  for (const entry of readdirSync(BENIGN_EXTENDED_DIR)) {
    if (!entry.endsWith(".jsonl")) continue;
    const f = join(BENIGN_EXTENDED_DIR, entry);
    let raw: string;
    try {
      raw = readFileSync(f, "utf-8");
    } catch {
      continue;
    }
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        out.push(JSON.parse(t) as ExtendedBenignSample);
      } catch {
        continue;
      }
    }
  }
  return out;
}

interface RuleTNSample {
  ownerRuleId: string;
  ownerFile: string;
  text: string;
}

/**
 * Collect every existing rule's true_negatives, tagged with the rule
 * that authored them. Used for cross-rule conflict detection.
 */
function loadAllExistingTrueNegatives(
  excludeFiles: Set<string>,
): RuleTNSample[] {
  const out: RuleTNSample[] = [];
  for (const f of walkYamlFiles(RULES_DIR)) {
    const rel = f.startsWith(REPO_ROOT + "/")
      ? f.slice(REPO_ROOT.length + 1)
      : f;
    if (excludeFiles.has(rel)) continue;
    let doc: unknown;
    try {
      doc = yamlLoad(readFileSync(f, "utf-8"));
    } catch {
      continue;
    }
    const d = doc as {
      id?: string;
      test_cases?: { true_negatives?: Array<string | { input?: string }> };
    };
    const id = d.id ?? rel;
    const tns = d.test_cases?.true_negatives ?? [];
    for (const tn of tns) {
      const text = typeof tn === "string" ? tn : (tn?.input ?? "");
      if (typeof text === "string" && text.length > 0)
        out.push({ ownerRuleId: id, ownerFile: rel, text });
    }
  }
  return out;
}

function loadDoc(file: string): Record<string, unknown> | null {
  const abs = join(REPO_ROOT, file);
  if (!existsSync(abs)) return null;
  try {
    return yamlLoad(readFileSync(abs, "utf-8")) as Record<string, unknown>;
  } catch (err) {
    console.error(
      `[safety-gate] Cannot parse ${file}: ${err instanceof Error ? err.message : String(err)}`,
    );
    return null;
  }
}

/** Check 1+2: structure + author. */
function checkMetadata(
  file: string,
  doc: Record<string, unknown>,
): Failure | null {
  const author = typeof doc.author === "string" ? doc.author : "";
  if (!author) return { file, reason: "missing author field" };
  if (/MiroFish\s+Predicted/i.test(author)) {
    return {
      file,
      reason: `blocked author "${author}" (MiroFish Predicted rules require human review)`,
    };
  }
  const testCases = doc.test_cases as Record<string, unknown> | undefined;
  if (!testCases) return { file, reason: "missing test_cases block" };
  const tp = Array.isArray(testCases.true_positives)
    ? testCases.true_positives
    : [];
  const tn = Array.isArray(testCases.true_negatives)
    ? testCases.true_negatives
    : [];
  if (tp.length === 0)
    return { file, reason: "missing test_cases.true_positives (need ≥1)" };
  if (tn.length === 0)
    return { file, reason: "missing test_cases.true_negatives (need ≥1)" };
  return null;
}

/** Build a single AgentEvent from arbitrary text content. */
function asTextEvent(content: string): AgentEvent {
  return {
    type: "mcp_exchange",
    timestamp: new Date().toISOString(),
    content,
    fields: {
      tool_name: "corpus-sample",
      tool_input: content,
      tool_response: content,
      user_input: content,
    },
  };
}

/**
 * Run an ATR engine over a sample and return the set of rule IDs that
 * matched (across both event evaluation and skill scanning, to mirror
 * the production engine's two paths).
 */
function matchAllRuleIds(engine: ATREngine, content: string): Set<string> {
  const matched = new Set<string>();
  for (const m of engine.evaluate(asTextEvent(content))) matched.add(m.rule.id);
  for (const m of engine.scanSkill(content)) matched.add(m.rule.id);
  return matched;
}

/**
 * Check 3: scan the benign-skill corpus. For each sample, collect all
 * matching rule IDs; if any new rule ID appears, that rule FP'd.
 */
async function checkBenignCorpusFP(
  engine: ATREngine,
  newRuleIds: Set<string>,
): Promise<Map<string, string[]>> {
  const fps = new Map<string, string[]>();
  if (!existsSync(BENIGN_DIR)) {
    console.error(
      `[safety-gate] benign corpus not found at ${BENIGN_DIR} — skipping FP check`,
    );
    return fps;
  }
  const samples = readdirSync(BENIGN_DIR).filter((f) => f.endsWith(".md"));
  for (const sample of samples) {
    const content = readFileSync(join(BENIGN_DIR, sample), "utf-8");
    for (const id of matchAllRuleIds(engine, content)) {
      if (newRuleIds.has(id)) {
        if (!fps.has(id)) fps.set(id, []);
        fps.get(id)!.push(sample);
      }
    }
  }
  return fps;
}

/**
 * Check 3b: scan the extended benign corpus. Larger and more diverse
 * than the original 432-skill set — arxiv abstracts (cs.AI / cs.CR /
 * cs.LG / cs.CL), plus npm and pypi package descriptions + READMEs.
 * Same FP semantics: a new rule must produce 0 matches across the
 * extended corpus.
 */
async function checkExtendedBenignFP(
  engine: ATREngine,
  newRuleIds: Set<string>,
): Promise<Map<string, string[]>> {
  const fps = new Map<string, string[]>();
  const samples = loadExtendedBenign();
  if (samples.length === 0) {
    console.error(
      `[safety-gate] extended-benign corpus empty (${BENIGN_EXTENDED_DIR}) — skipping extended-FP check`,
    );
    return fps;
  }
  for (const s of samples) {
    const label = `${s.source}:${s.source_id.slice(0, 40)}`;
    for (const id of matchAllRuleIds(engine, s.text)) {
      if (newRuleIds.has(id)) {
        if (!fps.has(id)) fps.set(id, []);
        fps.get(id)!.push(label);
      }
    }
  }
  return fps;
}

/**
 * Check 4: scan the research-mention corpus. Same shape as Check 3,
 * but each sample is a curated piece of text that MENTIONS attacks
 * without being them — academic abstracts, security blogs, READMEs,
 * course descriptions. A FP here means a rule cannot tell "this is
 * an attack" from "this is a sentence about the attack."
 */
async function checkResearchMentionFP(
  engine: ATREngine,
  newRuleIds: Set<string>,
): Promise<Map<string, string[]>> {
  const fps = new Map<string, string[]>();
  const samples = loadResearchMentions();
  if (samples.length === 0) {
    console.error(
      `[safety-gate] research-mention corpus empty (${RESEARCH_MENTIONS_FILE}) — skipping mention-FP check`,
    );
    return fps;
  }
  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    const label = `mention#${i}:${s.category ?? "uncategorised"}:${s.source_type ?? "unknown"}`;
    for (const id of matchAllRuleIds(engine, s.text)) {
      if (newRuleIds.has(id)) {
        if (!fps.has(id)) fps.set(id, []);
        fps.get(id)!.push(label);
      }
    }
  }
  return fps;
}

/**
 * Check 5: cross-rule conflict. For each new rule, verify it does not
 * match any OTHER (existing) rule's true_negatives. If rule X starts
 * firing on rule Y's known-benign set, Y just regressed in precision
 * and we need a human to look at the overlap.
 *
 * Returns a map of newRuleId → list of "ownerRuleId:sample-snippet"
 * conflicts.
 */
async function checkCrossRuleConflict(
  engine: ATREngine,
  newRuleIds: Set<string>,
  newFiles: Set<string>,
): Promise<Map<string, string[]>> {
  const fps = new Map<string, string[]>();
  const tnSamples = loadAllExistingTrueNegatives(newFiles);
  if (tnSamples.length === 0) {
    return fps;
  }
  for (const tn of tnSamples) {
    for (const id of matchAllRuleIds(engine, tn.text)) {
      if (newRuleIds.has(id) && id !== tn.ownerRuleId) {
        if (!fps.has(id)) fps.set(id, []);
        const snippet = tn.text.slice(0, 60).replace(/\s+/g, " ");
        fps
          .get(id)!
          .push(`conflicts with ${tn.ownerRuleId}'s TN: "${snippet}..."`);
      }
    }
  }
  return fps;
}

/**
 * Check 2 (sanity): rule's own true_positives MUST actually match its
 * own regex. A rule that doesn't catch its own declared TPs is broken
 * by construction.
 *
 * NOTE: engine.evaluate() skips rules with status='draft' or 'deprecated',
 * so new draft rules would never match their own TPs via the normal path.
 * To work around this, we temporarily promote each draft/test rule to
 * 'active' in the in-memory engine object before testing, then restore it.
 * This only affects the in-memory engine used for validation — it never
 * modifies the rule files on disk.
 */
async function checkOwnTruePositivesMatch(
  engine: ATREngine,
  newRuleEntries: Array<{ id: string; file: string; tps: string[] }>,
): Promise<Map<string, string[]>> {
  // NOTE: caller is responsible for promoting draft/test rules to 'active'
  // before calling this function — engine.evaluate() skips draft rules.
  const fps = new Map<string, string[]>();
  for (const r of newRuleEntries) {
    const misses: string[] = [];
    for (const tp of r.tps) {
      const matchedIds = matchAllRuleIds(engine, tp);
      if (!matchedIds.has(r.id)) {
        misses.push(tp.slice(0, 60).replace(/\s+/g, " "));
      }
    }
    if (misses.length > 0) {
      fps.set(
        r.id,
        misses.map((m) => `own TP not matched: "${m}..."`),
      );
    }
  }
  return fps;
}

function extractTruePositives(doc: Record<string, unknown>): string[] {
  const tc = doc.test_cases as
    | { true_positives?: Array<string | { input?: string }> }
    | undefined;
  const tps = tc?.true_positives ?? [];
  return tps
    .map((t) => (typeof t === "string" ? t : (t?.input ?? "")))
    .filter((s): s is string => typeof s === "string" && s.length > 0);
}

async function main(): Promise<void> {
  const { base, file: singleFile } = parseArgs();
  const newFiles = singleFile ? [singleFile] : getNewRuleFiles(base);

  if (singleFile) {
    console.log(`[safety-gate] single-file mode: ${singleFile}`);
  } else {
    console.log(`[safety-gate] base=${base}`);
  }
  console.log(`[safety-gate] ${newFiles.length} new rule file(s) detected`);

  if (newFiles.length === 0) {
    console.log(
      "[safety-gate] No new rule files — nothing to check, treating as safe.",
    );
    process.exit(0);
  }

  if (!singleFile && newFiles.length > MAX_NEW_PER_PR) {
    console.log(
      `[safety-gate] FAIL — ${newFiles.length} new rules exceeds MAX_NEW_PER_PR=${MAX_NEW_PER_PR}. Human review required.`,
    );
    process.exit(1);
  }

  const failures: Failure[] = [];
  const newRuleIds = new Set<string>();
  const fileToId = new Map<string, string>();
  const ruleEntries: Array<{ id: string; file: string; tps: string[] }> = [];

  for (const file of newFiles) {
    const doc = loadDoc(file);
    if (!doc) {
      failures.push({ file, reason: "could not parse rule file" });
      continue;
    }
    const metaFail = checkMetadata(file, doc);
    if (metaFail) {
      failures.push(metaFail);
      continue;
    }
    const id = typeof doc.id === "string" ? doc.id : "";
    if (!id) {
      failures.push({ file, reason: "missing id field" });
      continue;
    }
    // Surface duplicate-ID collisions as an explicit failure rather than
    // letting fileToId.set silently overwrite — otherwise downstream
    // failure attribution lands on the wrong file and the collision is
    // invisible to the reviewer.
    const prior = fileToId.get(id);
    if (prior) {
      failures.push({
        file,
        reason: `duplicate id ${id} — already declared by ${prior}`,
      });
      continue;
    }
    newRuleIds.add(id);
    fileToId.set(id, file);
    ruleEntries.push({ id, file, tps: extractTruePositives(doc) });
  }

  if (newRuleIds.size > 0) {
    const engine = new ATREngine({ rulesDir: RULES_DIR });
    await engine.loadRules();

    // Temporarily promote all NEW draft/test rules to 'active' for FP checks
    // (benign corpus, extended benign, research mentions, cross-rule conflict).
    // engine.evaluate() skips draft rules, so without this promotion the FP
    // checks would trivially pass for draft rules — a false green.
    // We restore original statuses before returning.
    const statusBackup = new Map<string, string>();
    for (const id of newRuleIds) {
      const rule = engine.getRuleById(id) as Record<string, unknown> | undefined;
      if (rule && (rule['status'] === 'draft' || rule['status'] === 'test')) {
        statusBackup.set(id, rule['status'] as string);
        rule['status'] = 'active';
      }
    }
    const restoreStatuses = () => {
      for (const [id, status] of statusBackup) {
        const rule = engine.getRuleById(id) as Record<string, unknown> | undefined;
        if (rule) rule['status'] = status;
      }
    };

    // Check 2 — own TPs must actually match.
    const tpMisses = await checkOwnTruePositivesMatch(engine, ruleEntries);
    for (const [id, reasons] of tpMisses) {
      for (const r of reasons.slice(0, 3))
        failures.push({ file: fileToId.get(id) ?? id, reason: r });
      if (reasons.length > 3)
        failures.push({
          file: fileToId.get(id) ?? id,
          reason: `(+${reasons.length - 3} more TP-not-matched failures suppressed)`,
        });
    }

    // Check 3 — benign skill corpus FP (432 SKILL.md samples).
    const benignFps = await checkBenignCorpusFP(engine, newRuleIds);
    for (const [id, samples] of benignFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `benign-corpus FP on ${samples.length} sample(s): ${samples.slice(0, 3).join(", ")}${samples.length > 3 ? ", ..." : ""}`,
      });
    }

    // Check 3b — extended benign corpus FP (arxiv + npm + pypi).
    const extendedFps = await checkExtendedBenignFP(engine, newRuleIds);
    for (const [id, samples] of extendedFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `extended-benign FP on ${samples.length} sample(s): ${samples.slice(0, 3).join(", ")}${samples.length > 3 ? ", ..." : ""}`,
      });
    }

    // Check 4 — research-mention corpus FP.
    const mentionFps = await checkResearchMentionFP(engine, newRuleIds);
    for (const [id, samples] of mentionFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `research-mention FP on ${samples.length} sample(s): ${samples.slice(0, 2).join(" | ")}${samples.length > 2 ? ", ..." : ""}`,
      });
    }

    // Check 5 — cross-rule conflict against existing TNs.
    const conflictFps = await checkCrossRuleConflict(
      engine,
      newRuleIds,
      new Set(newFiles),
    );
    for (const [id, conflicts] of conflictFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `cross-rule conflict: ${conflicts.slice(0, 2).join(" | ")}${conflicts.length > 2 ? `, +${conflicts.length - 2} more` : ""}`,
      });
    }

    // Restore original statuses now that all FP checks are complete
    restoreStatuses();
  }

  if (failures.length === 0) {
    console.log(
      `[safety-gate] PASS — ${newFiles.length} rule(s) safe to auto-merge`,
    );
    newFiles.forEach((f) => console.log(`  ✓ ${f}`));
    process.exit(0);
  }

  console.log(
    `[safety-gate] FAIL — ${failures.length} rule(s) need human review:`,
  );
  failures.forEach((f) => console.log(`  ✗ ${f.file} — ${f.reason}`));
  process.exit(1);
}

void main();
