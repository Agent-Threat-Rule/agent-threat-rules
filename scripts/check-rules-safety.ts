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
 *
 * NEW-RULE DISCOVERY IS NOT DIFF-ONLY (this was a false green).
 *   `git diff --diff-filter=A base...HEAD` only sees committed files. Rules are
 *   routinely written into rules/ and gated BEFORE any commit —
 *   scripts/fn-mine-llm.ts writes each authored rule to disk and then calls this
 *   script, and the gate answered "0 new rule file(s) detected — nothing to
 *   check, treating as safe" and exited 0. Every rule authored that way skipped
 *   all six checks while the caller recorded a PASS. Discovery therefore unions
 *   the diff with `git ls-files --others --exclude-standard -- rules/`, so a
 *   rule that exists on disk is measured whether or not git has heard of it.
 */

import { execFileSync } from "node:child_process";
import {
  readFileSync,
  readdirSync,
  existsSync,
  statSync,
  mkdtempSync,
  copyFileSync,
  writeFileSync,
  rmSync,
} from "node:fs";
import { join, resolve, dirname, basename } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { load as yamlLoad } from "js-yaml";
import { ATREngine } from "../src/engine.js";
import { matchedRuleIds } from "./lib/corpus-event.js";
import { lintRuleDoc } from "./lint-rule-patterns.js";

const MAX_NEW_PER_PR = Number(process.env.MAX_NEW_PER_PR ?? 10);
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BENIGN_DIR = join(REPO_ROOT, "data/skill-benchmark/benign");
const RESEARCH_MENTIONS_FILE = join(
  REPO_ROOT,
  "data/research-mentions/corpus.jsonl",
);
const BENIGN_EXTENDED_DIR = join(REPO_ROOT, "data/benign-corpus-extended");
// Benign SOURCE CODE corpus. The other benign corpora are prose (skill
// markdown, arxiv abstracts, package descriptions), so a rule whose pattern is
// a benign code line — e.g. `import random`, `from bs4 import BeautifulSoup` —
// passes them all yet false-positives on real code. This corpus is normal
// source code (common imports + normal usage of the allowlisted agent
// libraries) that detection rules must NEVER match.
const BENIGN_CODE_DIR = join(REPO_ROOT, "data/benign-code");
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

/** Runs a git command and returns stdout. Injected so discovery is testable. */
export type GitRunner = (args: readonly string[]) => string;

function execGit(repoRoot: string): GitRunner {
  return (args) =>
    execFileSync("git", [...args], {
      cwd: repoRoot,
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
}

const isRuleFile = (f: string): boolean =>
  f.endsWith(".yaml") || f.endsWith(".yml");

/**
 * Rule files added relative to base AND rule files that exist on disk but are
 * not in git at all. The untracked half is not a convenience: without it this
 * gate reports "nothing to check, treating as safe" for every rule authored
 * into the working tree and gated before commit, which is how the fn-mine
 * flywheel calls it. See the header note.
 *
 * Untracked discovery is deliberately NOT attempted in --file mode; that mode
 * gates one explicitly named path.
 */
export function getNewRuleFiles(
  base: string,
  repoRoot: string = REPO_ROOT,
  run: GitRunner = execGit(repoRoot),
): string[] {
  const added = tryGit(
    run,
    ["diff", "--name-only", "--diff-filter=A", `${base}...HEAD`, "--", "rules/"],
    "git diff",
  );
  return [
    ...new Set([...added, ...getUntrackedRuleFiles(repoRoot, run)]),
  ].sort();
}

/** Rule files on disk that git does not track and .gitignore does not exclude. */
export function getUntrackedRuleFiles(
  repoRoot: string = REPO_ROOT,
  run: GitRunner = execGit(repoRoot),
): string[] {
  return tryGit(
    run,
    ["ls-files", "--others", "--exclude-standard", "--", "rules/"],
    "git ls-files --others",
  );
}

/**
 * Run one git command, returning the rule files it named. A git failure is
 * reported and treated as "this source found nothing" — never as a reason to
 * abandon the other source, because losing a discovery source silently is the
 * exact failure this gate is being hardened against.
 */
function tryGit(
  run: GitRunner,
  args: readonly string[],
  label: string,
): string[] {
  try {
    return run(args).trim().split("\n").filter(Boolean).filter(isRuleFile);
  } catch (err) {
    console.error(
      `[safety-gate] ${label} failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return [];
  }
}

/**
 * Diff against base to find modified (already-existing) rule files. Stays
 * diff-only on purpose: the modified-rule check is differential (base vs head),
 * and an untracked file has no base version to compare against — it is new, and
 * getNewRuleFiles already covers it.
 */
export function getModifiedRuleFiles(
  base: string,
  repoRoot: string = REPO_ROOT,
  run: GitRunner = execGit(repoRoot),
): string[] {
  return tryGit(
    run,
    ["diff", "--name-only", "--diff-filter=M", `${base}...HEAD`, "--", "rules/"],
    "git diff (modified)",
  );
}

/** Read a file's contents at a git ref. Null when it is absent there. */
function readFileAtRef(ref: string, file: string): string | null {
  try {
    return execFileSync("git", ["show", `${ref}:${file}`], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch {
    return null;
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

/**
 * Run an ATR engine over a sample and return the set of rule IDs that matched.
 *
 * Delegates to the canonical shape set in scripts/lib/corpus-event.ts. This gate
 * used to hand-roll a single mcp_exchange event with four fields, which left
 * `tool_args` (and every other field the production hook actually populates)
 * unresolvable — conditions keyed on it could not fire, so rules built on them
 * were scored FP-clean without ever being read. A rule must not earn its
 * detection credit on a wider presentation than the one it pays its false
 * positives on.
 */
function matchAllRuleIds(engine: ATREngine, content: string): ReadonlySet<string> {
  return matchedRuleIds(engine, content);
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
    const label = `${s.source ?? "?"}:${(s.source_id ?? "?").slice(0, 40)}`;
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
 * Load the benign-code corpus from data/benign-code/*.jsonl. Same
 * {source, source_id, text} shape as the extended benign corpus, but each
 * `text` is real source code (imports + normal library usage).
 */
function loadBenignCode(): ExtendedBenignSample[] {
  if (!existsSync(BENIGN_CODE_DIR)) return [];
  const out: ExtendedBenignSample[] = [];
  for (const entry of readdirSync(BENIGN_CODE_DIR)) {
    if (!entry.endsWith(".jsonl")) continue;
    let raw: string;
    try {
      raw = readFileSync(join(BENIGN_CODE_DIR, entry), "utf-8");
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

/**
 * Check 3c: scan the benign-CODE corpus. This is the hard gate that the
 * import-FP class (e.g. a rule whose pattern is `import random`) failed —
 * the prose corpora never contained source code. A new rule matching ANY
 * benign-code sample is a false positive and the rule is rejected, routing
 * the proposal back to human review instead of letting it reach main.
 */
async function checkBenignCodeFP(
  engine: ATREngine,
  newRuleIds: Set<string>,
): Promise<Map<string, string[]>> {
  const fps = new Map<string, string[]>();
  const samples = loadBenignCode();
  if (samples.length === 0) {
    console.error(
      `[safety-gate] benign-code corpus empty (${BENIGN_CODE_DIR}) — skipping benign-code FP check`,
    );
    return fps;
  }
  for (const s of samples) {
    const label = `${s.source ?? "?"}:${(s.source_id ?? "?").slice(0, 40)}`;
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

/** Every benign sample the gate knows about, flattened to labelled text. */
function collectBenignCorpus(): Array<{ label: string; text: string }> {
  const out: Array<{ label: string; text: string }> = [];
  if (existsSync(BENIGN_DIR)) {
    for (const f of readdirSync(BENIGN_DIR).filter((x) => x.endsWith(".md"))) {
      out.push({ label: f, text: readFileSync(join(BENIGN_DIR, f), "utf-8") });
    }
  }
  for (const s of loadExtendedBenign())
    out.push({ label: `${s.source}/${s.source_id}`, text: s.text });
  for (const s of loadBenignCode())
    out.push({ label: `benign-code/${s.source_id}`, text: s.text });
  for (const s of loadResearchMentions())
    out.push({ label: "research-mention", text: s.text });
  return out;
}

/**
 * Build an engine holding exactly the supplied rule sources. Draft/test
 * statuses are activated so an inert rule still gets measured — the same
 * treatment the new-rule path gives them.
 */
async function buildScopedEngine(
  name: string,
  content: string,
): Promise<{ engine: ATREngine; dir: string }> {
  const dir = mkdtempSync(join(tmpdir(), "atr-safety-modified-"));
  writeFileSync(join(dir, name), content, "utf-8");
  const engine = new ATREngine({ rulesDir: dir });
  await engine.loadRules();
  for (const rule of engine.getRules() as unknown as Array<
    Record<string, unknown>
  >) {
    if (rule["status"] === "draft" || rule["status"] === "test") {
      rule["status"] = "active";
    }
  }
  return { engine, dir };
}

/**
 * Check 6 — a modified rule may not introduce NEW benign false positives.
 *
 * Deliberately differential rather than absolute. A rule that already
 * false-positives is pre-existing debt, and failing whichever PR happens to
 * touch it next would only teach contributors to route around the gate. What
 * must never land is a change that makes a rule match benign samples it did
 * not match before.
 *
 * Each rule is evaluated twice over the same corpus — once as it exists at
 * base, once as modified — and only the difference is reported. That also
 * means a PR which strictly narrows a pattern passes with no work, which is
 * the outcome we want to encourage.
 */
async function checkModifiedRulesNoNewFP(
  base: string,
  files: string[],
): Promise<Failure[]> {
  const failures: Failure[] = [];
  const corpus = collectBenignCorpus();
  if (corpus.length === 0) {
    console.error(
      "[safety-gate] benign corpora empty — skipping modified-rule FP check",
    );
    return failures;
  }

  for (const file of files) {
    const baseContent = readFileAtRef(base, file);
    const headPath = join(REPO_ROOT, file);
    if (!baseContent || !existsSync(headPath)) continue;
    const headContent = readFileSync(headPath, "utf-8");
    if (baseContent === headContent) continue;

    const name = basename(file);
    let baseBuilt: { engine: ATREngine; dir: string } | null = null;
    let headBuilt: { engine: ATREngine; dir: string } | null = null;
    try {
      baseBuilt = await buildScopedEngine(name, baseContent);
      headBuilt = await buildScopedEngine(name, headContent);
    } catch (err) {
      // A rule that no longer loads is a real problem, but it is the schema
      // validator's to report, not this gate's.
      console.error(
        `[safety-gate] could not build scoped engines for ${file}: ${err instanceof Error ? err.message : String(err)}`,
      );
      if (baseBuilt) rmSync(baseBuilt.dir, { recursive: true, force: true });
      if (headBuilt) rmSync(headBuilt.dir, { recursive: true, force: true });
      continue;
    }

    const introduced: string[] = [];
    for (const { label, text } of corpus) {
      const before = matchAllRuleIds(baseBuilt.engine, text);
      const after = matchAllRuleIds(headBuilt.engine, text);
      for (const id of after) {
        if (!before.has(id)) introduced.push(`${id} now matches ${label}`);
      }
    }

    rmSync(baseBuilt.dir, { recursive: true, force: true });
    rmSync(headBuilt.dir, { recursive: true, force: true });

    if (introduced.length > 0) {
      for (const detail of introduced.slice(0, 3)) {
        failures.push({
          file,
          reason: `modification introduces a new benign false positive: ${detail}`,
        });
      }
      if (introduced.length > 3) {
        failures.push({
          file,
          reason: `(+${introduced.length - 3} more newly introduced benign FPs suppressed)`,
        });
      }
    }
  }
  return failures;
}

async function main(): Promise<void> {
  const { base, file: singleFile } = parseArgs();
  const newFiles = singleFile ? [singleFile] : getNewRuleFiles(base);

  if (singleFile) {
    console.log(`[safety-gate] single-file mode: ${singleFile}`);
  } else {
    console.log(`[safety-gate] base=${base}`);
  }
  const modifiedFiles = singleFile ? [] : getModifiedRuleFiles(base);
  // Say where they came from. "0 new rule file(s)" was the sound this gate made
  // while skipping a whole batch of uncommitted rules, so the split between
  // committed and on-disk-only is worth a line of CI log.
  const untracked = singleFile ? [] : getUntrackedRuleFiles();
  console.log(
    `[safety-gate] ${newFiles.length} new rule file(s) detected` +
      (untracked.length > 0
        ? ` (${untracked.length} uncommitted, discovered on disk)`
        : ""),
  );
  if (modifiedFiles.length > 0) {
    console.log(
      `[safety-gate] ${modifiedFiles.length} modified rule file(s) detected`,
    );
  }

  // Modified rules are checked differentially — a change may not introduce
  // benign FPs the rule did not already have. Runs even when no rule is added,
  // which is the case this gate previously ignored entirely.
  const modifiedFailures =
    modifiedFiles.length > 0
      ? await checkModifiedRulesNoNewFP(base, modifiedFiles)
      : [];

  if (newFiles.length === 0) {
    if (modifiedFailures.length === 0) {
      console.log(
        modifiedFiles.length > 0
          ? `[safety-gate] PASS — ${modifiedFiles.length} modified rule(s) introduce no new benign FPs`
          : "[safety-gate] No new or modified rule files — nothing to check, treating as safe.",
      );
      process.exit(0);
    }
    console.log(
      `[safety-gate] FAIL — ${modifiedFailures.length} finding(s) need human review:`,
    );
    modifiedFailures.forEach((f) => console.log(`  ✗ ${f.file} — ${f.reason}`));
    process.exit(1);
  }

  if (!singleFile && newFiles.length > MAX_NEW_PER_PR) {
    console.log(
      `[safety-gate] FAIL — ${newFiles.length} new rules exceeds MAX_NEW_PER_PR=${MAX_NEW_PER_PR}. Human review required.`,
    );
    process.exit(1);
  }

  const failures: Failure[] = [...modifiedFailures];
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

    // Check 6 — loose-regex lint. The bare-keyword-without-word-boundary class
    // (e.g. "nc" matching inside "async", "host" inside prose) is the highest-
    // confidence FP cause (00120, 00149) and almost never legitimate, so route
    // it to human review. Other loose patterns ([^...]*, .*, wide {0,N}) are
    // advisory only (frequently legitimate).
    for (const lf of lintRuleDoc(doc)) {
      if (lf.code === "bareword") {
        failures.push({ file, reason: `loose-regex lint: ${lf.detail}` });
      } else {
        console.log(`  [loose-regex advisory] ${file} — ${lf.code}: ${lf.detail}`);
      }
    }
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

    // Perf: the corpus-FP checks (Checks 3/3b/3c/4) only ask whether a NEW
    // rule matches a benign sample. Running the full ~690-rule engine over
    // thousands of samples spends ~99% of its time evaluating rules whose
    // result is discarded. Per-event preprocessing (base64/unicode folding,
    // skill parsing) is content-driven, not rule-set-driven, so a scoped
    // engine holding ONLY the new rules yields the identical new-rule match
    // set at ~100x less work. Verified empirically: scoped+promoted
    // reproduces the full-engine FP set exactly (same rules, same counts).
    // The full engine is still used for own-TP (Check 2) and cross-rule
    // conflict (Check 5, which must see every existing rule's true_negatives).
    const scopedDir = mkdtempSync(join(tmpdir(), "atr-safety-newrules-"));
    for (const f of newFiles) {
      copyFileSync(join(REPO_ROOT, f), join(scopedDir, basename(f)));
    }
    const scopedEngine = new ATREngine({ rulesDir: scopedDir });
    await scopedEngine.loadRules();
    for (const id of newRuleIds) {
      const rule = scopedEngine.getRuleById(id) as
        | Record<string, unknown>
        | undefined;
      if (rule && (rule['status'] === 'draft' || rule['status'] === 'test')) {
        rule['status'] = 'active';
      }
    }

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
    const benignFps = await checkBenignCorpusFP(scopedEngine, newRuleIds);
    for (const [id, samples] of benignFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `benign-corpus FP on ${samples.length} sample(s): ${samples.slice(0, 3).join(", ")}${samples.length > 3 ? ", ..." : ""}`,
      });
    }

    // Check 3b — extended benign corpus FP (arxiv + npm + pypi).
    const extendedFps = await checkExtendedBenignFP(scopedEngine, newRuleIds);
    for (const [id, samples] of extendedFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `extended-benign FP on ${samples.length} sample(s): ${samples.slice(0, 3).join(", ")}${samples.length > 3 ? ", ..." : ""}`,
      });
    }

    // Check 3c — benign-CODE corpus FP (imports + normal library usage).
    // Hard gate against the import-FP class that slipped through before.
    const codeFps = await checkBenignCodeFP(scopedEngine, newRuleIds);
    for (const [id, samples] of codeFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `benign-CODE FP on ${samples.length} sample(s): ${samples.slice(0, 3).join(", ")}${samples.length > 3 ? ", ..." : ""}`,
      });
    }

    // Check 4 — research-mention corpus FP.
    const mentionFps = await checkResearchMentionFP(scopedEngine, newRuleIds);
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
    rmSync(scopedDir, { recursive: true, force: true });
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

// Only run when invoked directly, so unit tests can import the discovery
// helpers without main()'s process.exit() tearing the test runner down.
const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) void main();
