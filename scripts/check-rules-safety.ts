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
 *      (known-clean SKILL.md samples; the corpus grows, so the count is
 *      counted at run time and printed, never written down here).
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
 * Exit 2 = the gate could not run as asked (bad usage / bad environment).
 *          Never reported as safe: a gate that did not run is not a pass.
 *
 * Usage (in tc-pr-back workflow):
 *   npx tsx scripts/check-rules-safety.ts --base origin/main
 *
 * Explicit-target mode (for /red-team, /cve-collector and CONTRIBUTING's
 * "check my rule before I open the PR" flow). Positional paths and --file
 * mean the same thing, and either may be repeated:
 *   npx tsx scripts/check-rules-safety.ts rules/x/ATR-2026-00001-foo.yaml
 *   npx tsx scripts/check-rules-safety.ts --file proposals/path.proposal.yaml
 *
 * A NAMED TARGET IS NEVER "NOTHING TO CHECK" (this was a false green).
 *   Positional arguments were parsed by nobody: argv was scanned for --base and
 *   --file and everything else was dropped. CONTRIBUTING.md Path 2 step 4 and
 *   .github/workflows/issue-to-proposal.yml both teach the positional form, so
 *   every contributor who followed the docs got "0 new rule file(s) detected /
 *   nothing to check, treating as safe" and exit 0 in under a second, for a
 *   rule that was never read. The "nothing to check → safe" answer is now only
 *   reachable from diff mode with no target named by anyone.
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
import type { Dirent } from "node:fs";
import {
  join,
  resolve,
  dirname,
  basename,
  isAbsolute,
  relative,
} from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { load as yamlLoad } from "js-yaml";
import { ATREngine } from "../src/engine.js";
import { matchedRuleIds } from "./lib/corpus-event.js";
import { lintRuleDoc } from "./lint-rule-patterns.js";

/**
 * Validated in main(). Read as a raw string on purpose: `Number("ten")` is NaN,
 * and `count > NaN` is false, so a typo'd override used to disable the per-PR
 * cap silently — an unbounded batch would have sailed through reporting PASS.
 */
const MAX_NEW_PER_PR_RAW = process.env.MAX_NEW_PER_PR ?? "10";
/** Usage / environment failure. Distinct from exit 1, "a check found something". */
const EXIT_USAGE = 2;
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

export const USAGE = [
  "Usage:",
  "  check-rules-safety.ts <rule.yaml> [<rule.yaml> ...]   explicit targets",
  "  check-rules-safety.ts --file <path> [--file <path>]   same, flag form",
  "  check-rules-safety.ts [--base <git-ref>]              diff mode (CI)",
  "",
  "Exit: 0 = safe, 1 = a check failed, 2 = usage or environment error.",
].join("\n");

export interface ParsedArgs {
  readonly base: string;
  /** Targets the caller named, positionally or with --file. Verbatim, unresolved. */
  readonly files: readonly string[];
  readonly errors: readonly string[];
}

/**
 * Parse argv. Positional paths are accepted and mean exactly what --file means;
 * anything unrecognised is an error rather than a silent drop, because a
 * dropped argument here reads as "the caller asked for nothing" and the gate's
 * answer to that used to be "safe".
 */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const files: string[] = [];
  const errors: string[] = [];
  let base = "origin/main";
  let sawBase = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--base") {
      const value = argv[i + 1];
      i++;
      if (value === undefined || value.startsWith("-")) {
        errors.push("--base needs a git ref, e.g. --base origin/main");
      } else if (sawBase) {
        errors.push(`--base given twice ("${base}" then "${value}")`);
      } else {
        base = value;
        sawBase = true;
      }
      continue;
    }
    if (arg === "--file") {
      const value = argv[i + 1];
      i++;
      if (value === undefined || value.startsWith("-")) {
        errors.push("--file needs a path, e.g. --file rules/<cat>/<rule>.yaml");
      } else {
        files.push(value);
      }
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      errors.push("help requested");
      continue;
    }
    if (arg.startsWith("-")) {
      errors.push(`unknown option "${arg}"`);
      continue;
    }
    files.push(arg);
  }
  return { base, files, errors };
}

export interface ResolvedTargets {
  /** Repo-relative paths, de-duplicated, in the order the caller named them. */
  readonly files: readonly string[];
  readonly errors: readonly string[];
}

const isReadableFile = (p: string): boolean => {
  try {
    return existsSync(p) && statSync(p).isFile();
  } catch {
    return false;
  }
};

/**
 * Turn caller-named paths into repo-relative rule paths. A path that cannot be
 * resolved is an ERROR, never an empty work list — "the caller named something
 * specific" and "there is nothing to check" must not be able to produce the
 * same outcome. Relative paths resolve against the working directory first and
 * the repo root second, so both `check-rules-safety.ts rules/x/y.yaml` from the
 * repo root and a path relative to a subdirectory work.
 */
export function resolveTargets(
  raw: readonly string[],
  repoRoot: string = REPO_ROOT,
  cwd: string = process.cwd(),
): ResolvedTargets {
  const files: string[] = [];
  const errors: string[] = [];
  for (const p of raw) {
    const candidates = isAbsolute(p)
      ? [p]
      : [...new Set([resolve(cwd, p), resolve(repoRoot, p)])];
    const hit = candidates.find(isReadableFile);
    if (!hit) {
      errors.push(`no such file: ${p}`);
      continue;
    }
    const rel = relative(repoRoot, hit);
    if (rel.startsWith("..") || isAbsolute(rel)) {
      // Downstream (loadDoc, the scoped-engine copy) joins against REPO_ROOT,
      // so a path outside the repo would silently resolve to something else.
      errors.push(`outside the repository, cannot be checked: ${p}`);
      continue;
    }
    if (!isRuleFile(rel)) {
      errors.push(`not a YAML rule file: ${p}`);
      continue;
    }
    if (!files.includes(rel)) files.push(rel);
  }
  return { files, errors };
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
  onError: DiscoveryErrorSink = () => {},
): string[] {
  const added = tryGit(
    run,
    ["diff", "--name-only", "--diff-filter=A", `${base}...HEAD`, "--", "rules/"],
    "git diff",
    onError,
  );
  return [
    ...new Set([...added, ...getUntrackedRuleFiles(repoRoot, run, onError)]),
  ].sort();
}

/** Rule files on disk that git does not track and .gitignore does not exclude. */
export function getUntrackedRuleFiles(
  repoRoot: string = REPO_ROOT,
  run: GitRunner = execGit(repoRoot),
  onError: DiscoveryErrorSink = () => {},
): string[] {
  return tryGit(
    run,
    ["ls-files", "--others", "--exclude-standard", "--", "rules/"],
    "git ls-files --others",
    onError,
  );
}

/** Told about a discovery source that could not answer. See tryGit. */
export type DiscoveryErrorSink = (message: string) => void;

/**
 * Run one git command, returning the rule files it named. A git failure never
 * aborts the other source — a shallow clone can lose the diff and still have a
 * truthful untracked listing — but it is reported to the sink, and main() will
 * not let the run finish green on a partial discovery. An unanswered source
 * means the gate cannot prove that nothing needs checking, and "cannot prove"
 * is not "safe".
 */
function tryGit(
  run: GitRunner,
  args: readonly string[],
  label: string,
  onError: DiscoveryErrorSink = () => {},
): string[] {
  try {
    return run(args).trim().split("\n").filter(Boolean).filter(isRuleFile);
  } catch (err) {
    const message = `${label} failed: ${err instanceof Error ? err.message : String(err)}`;
    console.error(`[safety-gate] ${message}`);
    onError(message);
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
  onError: DiscoveryErrorSink = () => {},
): string[] {
  return tryGit(
    run,
    ["diff", "--name-only", "--diff-filter=M", `${base}...HEAD`, "--", "rules/"],
    "git diff (modified)",
    onError,
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

/** One benign sample, already labelled for the failure message. */
export interface LabelledSample {
  readonly label: string;
  readonly text: string;
}

/** A loaded corpus plus everything that went wrong while loading it. */
interface LoadedCorpus {
  readonly samples: readonly LabelledSample[];
  readonly errors: readonly string[];
}

interface JsonlRecord {
  text?: string;
  source?: string;
  source_id?: string;
  category?: string;
  source_type?: string;
}

/**
 * Read JSONL samples from a file or a directory of .jsonl files.
 *
 * Unreadable files and unparseable lines are COUNTED AND REPORTED, not skipped
 * in silence. A corpus that quietly shrinks is a gate that quietly weakens: the
 * rule still gets its "0 FP" verdict, just over fewer samples than anyone
 * thinks. Errors are returned to the caller, which turns them into findings.
 */
function loadJsonl(
  path: string,
  toLabel: (record: JsonlRecord, index: number, file: string) => string,
): LoadedCorpus {
  if (!existsSync(path)) return { samples: [], errors: [] };
  let files: string[];
  try {
    files = statSync(path).isDirectory()
      ? readdirSync(path)
          .filter((e) => e.endsWith(".jsonl"))
          .map((e) => join(path, e))
      : [path];
  } catch (err) {
    return { samples: [], errors: [`cannot list ${path}: ${asMessage(err)}`] };
  }

  const samples: LabelledSample[] = [];
  const errors: string[] = [];
  for (const file of files) {
    let raw: string;
    try {
      raw = readFileSync(file, "utf-8");
    } catch (err) {
      errors.push(`cannot read ${file}: ${asMessage(err)}`);
      continue;
    }
    const lines = raw.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i]!.trim();
      if (!t) continue;
      let record: JsonlRecord;
      try {
        record = JSON.parse(t) as JsonlRecord;
      } catch (err) {
        errors.push(`malformed JSON at ${file}:${i + 1}: ${asMessage(err)}`);
        continue;
      }
      const text = typeof record.text === "string" ? record.text : "";
      if (text.length === 0) {
        errors.push(`empty or missing "text" at ${file}:${i + 1}`);
        continue;
      }
      samples.push({ label: toLabel(record, samples.length, file), text });
    }
  }
  return { samples, errors };
}

const asMessage = (err: unknown): string =>
  err instanceof Error ? err.message : String(err);

/**
 * Benign SKILL.md files. Counted at run time — the corpus grows.
 *
 * This walks subdirectories. It used to read only the top level, which quietly
 * excluded every sample filed under one: 35 files in `benign/ninja-legit/` were
 * in the corpus on disk but were never charged against any rule, so the gate
 * enforced 432 samples while the repository documented 467. A benign sample that
 * the gate does not read is a benign sample that cannot catch a false positive.
 */
function loadBenignSkills(): LoadedCorpus {
  if (!existsSync(BENIGN_DIR)) return { samples: [], errors: [] };
  const samples: LabelledSample[] = [];
  const errors: string[] = [];

  const walk = (dir: string, prefix: string): void => {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      errors.push(`cannot list ${dir}: ${asMessage(err)}`);
      return;
    }
    // Sorted so the sample order does not depend on filesystem enumeration.
    for (const entry of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
      const full = join(dir, entry.name);
      const label = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        walk(full, label);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith(".md")) continue;
      try {
        samples.push({ label, text: readFileSync(full, "utf-8") });
      } catch (err) {
        errors.push(`cannot read ${full}: ${asMessage(err)}`);
      }
    }
  };

  walk(BENIGN_DIR, "");
  return { samples, errors };
}

/**
 * Every benign corpus the gate charges a rule against, loaded exactly once.
 *
 *  - skills:   known-clean SKILL.md samples (data/skill-benchmark/benign).
 *  - extended: arxiv abstracts, npm / pypi package descriptions and READMEs —
 *              larger and more varied prose than the skill corpus.
 *  - code:     real source code. The prose corpora contain none, so a rule whose
 *              pattern is a benign code line (`import random`) passes all of
 *              them and false-positives on the first repository it meets.
 *  - mentions: text that MENTIONS attacks without being one — papers, security
 *              blogs, READMEs, course material. A FP here means the rule cannot
 *              tell an attack from a sentence about the attack.
 */
interface BenignCorpora {
  readonly skills: LoadedCorpus;
  readonly extended: LoadedCorpus;
  readonly code: LoadedCorpus;
  readonly mentions: LoadedCorpus;
}

function loadBenignCorpora(): BenignCorpora {
  const sourceLabel = (r: JsonlRecord): string =>
    `${r.source ?? "?"}:${(r.source_id ?? "?").slice(0, 40)}`;
  return {
    skills: loadBenignSkills(),
    extended: loadJsonl(BENIGN_EXTENDED_DIR, sourceLabel),
    code: loadJsonl(BENIGN_CODE_DIR, sourceLabel),
    mentions: loadJsonl(
      RESEARCH_MENTIONS_FILE,
      (r, i) =>
        `mention#${i}:${r.category ?? "uncategorised"}:${r.source_type ?? "unknown"}`,
    ),
  };
}

/** Every benign sample, flattened, for the differential modified-rule check. */
function flattenCorpora(c: BenignCorpora): readonly LabelledSample[] {
  return [
    ...c.skills.samples,
    ...c.extended.samples,
    ...c.code.samples,
    ...c.mentions.samples,
  ];
}

/**
 * Fail-closed census. An absent or empty corpus used to print "skipping ..."
 * and return no false positives, which the gate then reported as a PASS — the
 * rule was cleared by a check that never ran. Missing corpora and load errors
 * are findings now, and a rule waits for a human instead.
 */
function censusFailures(c: BenignCorpora): Failure[] {
  const out: Failure[] = [];
  const corpora: Array<[string, string, LoadedCorpus]> = [
    ["benign-skills", BENIGN_DIR, c.skills],
    ["benign-extended", BENIGN_EXTENDED_DIR, c.extended],
    ["benign-code", BENIGN_CODE_DIR, c.code],
    ["research-mentions", RESEARCH_MENTIONS_FILE, c.mentions],
  ];
  for (const [name, where, corpus] of corpora) {
    if (corpus.samples.length === 0) {
      out.push({
        file: where,
        reason: `${name} corpus is missing or empty — the gate cannot clear a rule on a corpus it could not read`,
      });
    }
    for (const err of corpus.errors.slice(0, 3)) {
      out.push({ file: where, reason: `${name} corpus load error: ${err}` });
    }
    if (corpus.errors.length > 3) {
      out.push({
        file: where,
        reason: `${name} corpus: +${corpus.errors.length - 3} more load error(s) suppressed`,
      });
    }
  }
  return out;
}

export interface RuleTNSample {
  ownerRuleId: string;
  ownerFile: string;
  text: string;
}

/**
 * Collect every rule's true_negatives, tagged with the rule that authored
 * them. This includes new rules so peers added by the same PR are checked in
 * both directions; self-conflicts are excluded by owner id at evaluation time.
 */
function loadAllTrueNegatives(errors: string[] = []): RuleTNSample[] {
  const out: RuleTNSample[] = [];
  for (const f of walkYamlFiles(RULES_DIR)) {
    const rel = f.startsWith(REPO_ROOT + "/")
      ? f.slice(REPO_ROOT.length + 1)
      : f;
    let doc: unknown;
    try {
      doc = yamlLoad(readFileSync(f, "utf-8"));
    } catch (err) {
      // Not skipped in silence: an unreadable rule contributes no
      // true-negatives, so the cross-rule check would clear a new rule of a
      // conflict it was never tested for.
      errors.push(`cannot load ${rel} for cross-rule check: ${asMessage(err)}`);
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
 * Checks 3 / 3b / 3c / 4: scan one benign corpus. For each sample, collect the
 * matching rule IDs; any new rule ID that appears is a false positive.
 *
 * One implementation for all four corpora on purpose. Each used to carry its
 * own copy, and each copy carried its own "corpus empty — skipping" branch that
 * returned zero false positives and let the run report PASS. Emptiness is now
 * decided once, by censusFailures(), before any rule is measured.
 */
async function checkCorpusFP(
  engine: ATREngine,
  newRuleIds: ReadonlySet<string>,
  samples: readonly LabelledSample[],
): Promise<Map<string, string[]>> {
  const fps = new Map<string, string[]>();
  for (const s of samples) {
    for (const id of matchAllRuleIds(engine, s.text)) {
      if (newRuleIds.has(id)) {
        if (!fps.has(id)) fps.set(id, []);
        fps.get(id)!.push(s.label);
      }
    }
  }
  return fps;
}

/**
 * Evaluate the directed cross-rule matrix. Only new rules can be offenders,
 * while every other rule (including a peer added by the same PR) can own the
 * true-negative sample. A rule's own TN is intentionally left to its own-rule
 * validation rather than reported as a cross-rule conflict.
 *
 * Returns a map of newRuleId → list of "ownerRuleId:sample-snippet"
 * conflicts.
 */
export function findCrossRuleConflicts(
  newRuleIds: ReadonlySet<string>,
  tnSamples: readonly RuleTNSample[],
  matches: (text: string) => ReadonlySet<string>,
): Map<string, string[]> {
  const fps = new Map<string, string[]>();
  for (const tn of tnSamples) {
    for (const id of matches(tn.text)) {
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

/** Check 5: run the directed matrix against the repository's TN corpus. */
async function checkCrossRuleConflict(
  engine: ATREngine,
  newRuleIds: Set<string>,
  loadErrors: string[] = [],
): Promise<Map<string, string[]>> {
  return findCrossRuleConflicts(
    newRuleIds,
    loadAllTrueNegatives(loadErrors),
    (text) => matchAllRuleIds(engine, text),
  );
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
 *
 * The engine is chosen per rule by the caller: the full rulebase for a rule
 * that lives under rules/, the scoped engine for a target that does not (a
 * proposal file). Asking the full engine about a rule it never loaded would
 * report every declared TP as unmatched — a finding about the harness, not the
 * rule. Suppression is decided from a rule's own tags, so the scoped engine
 * returns the same verdict for the rule as the full one.
 */
async function checkOwnTruePositivesMatch(
  engineFor: (ruleId: string) => ATREngine,
  newRuleEntries: Array<{ id: string; file: string; tps: string[] }>,
): Promise<Map<string, string[]>> {
  // NOTE: caller is responsible for promoting draft/test rules to 'active'
  // before calling this function — engine.evaluate() skips draft rules.
  const fps = new Map<string, string[]>();
  for (const r of newRuleEntries) {
    const misses: string[] = [];
    for (const tp of r.tps) {
      const matchedIds = matchAllRuleIds(engineFor(r.id), tp);
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
  corpus: readonly LabelledSample[],
): Promise<Failure[]> {
  const failures: Failure[] = [];

  for (const file of files) {
    const baseContent = readFileAtRef(base, file);
    const headPath = join(REPO_ROOT, file);
    // Neither half of the comparison may be missing. Skipping here would clear
    // a modified rule without comparing anything.
    if (baseContent === null) {
      failures.push({
        file,
        reason: `cannot read the base version at ${base} — the modified-rule FP comparison cannot run`,
      });
      continue;
    }
    if (!existsSync(headPath)) {
      failures.push({
        file,
        reason: "reported as modified but not present on disk",
      });
      continue;
    }
    const headContent = readFileSync(headPath, "utf-8");
    if (baseContent === headContent) continue;

    const name = basename(file);
    let baseBuilt: { engine: ATREngine; dir: string } | null = null;
    let headBuilt: { engine: ATREngine; dir: string } | null = null;
    try {
      baseBuilt = await buildScopedEngine(name, baseContent);
      headBuilt = await buildScopedEngine(name, headContent);
    } catch (err) {
      // The schema validator reports WHY the rule no longer loads. This gate
      // still has to report that it could not measure the change: a rule the
      // engine cannot load matches nothing, which reads as "introduces no new
      // false positives" and would otherwise pass.
      failures.push({
        file,
        reason: `could not build scoped engines to compare against ${base}: ${asMessage(err)}`,
      });
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

/** Print usage / environment problems and leave. Never exits 0. */
function exitUsage(problems: readonly string[]): never {
  console.error(
    `[safety-gate] cannot run as asked — ${problems.length} problem(s):`,
  );
  problems.forEach((p) => console.error(`  ✗ ${p}`));
  console.error("");
  console.error(USAGE);
  process.exit(EXIT_USAGE);
}

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2));
  const base = parsed.base;

  const maxNewPerPr = Number(MAX_NEW_PER_PR_RAW);
  const setupProblems = [...parsed.errors];
  if (!Number.isInteger(maxNewPerPr) || maxNewPerPr <= 0) {
    setupProblems.push(
      `MAX_NEW_PER_PR must be a positive integer, got "${MAX_NEW_PER_PR_RAW}"`,
    );
  }

  // A named target that cannot be resolved is a usage error, not an empty work
  // list. This is the whole point: "you asked me to check X" and "there is
  // nothing to check" must never produce the same answer.
  const targets = resolveTargets(parsed.files);
  setupProblems.push(...targets.errors);
  if (setupProblems.length > 0) exitUsage(setupProblems);

  const explicit = targets.files.length > 0;

  // Discovery errors are collected rather than shrugged off: if a source could
  // not answer, "0 new rule files" is an unproven claim, and this gate does not
  // get to report unproven claims as safe.
  const discoveryErrors: string[] = [];
  const noteDiscoveryError: DiscoveryErrorSink = (m) => {
    discoveryErrors.push(m);
  };

  const newFiles = explicit
    ? [...targets.files]
    : getNewRuleFiles(base, REPO_ROOT, execGit(REPO_ROOT), noteDiscoveryError);

  if (explicit) {
    console.log(
      `[safety-gate] explicit-target mode: ${newFiles.length} file(s) named by the caller`,
    );
    newFiles.forEach((f) => console.log(`  • ${f}`));
  } else {
    console.log(`[safety-gate] base=${base}`);
  }
  const modifiedFiles = explicit
    ? []
    : getModifiedRuleFiles(base, REPO_ROOT, execGit(REPO_ROOT), noteDiscoveryError);
  // Say where they came from. "0 new rule file(s)" was the sound this gate made
  // while skipping a whole batch of uncommitted rules, so the split between
  // committed and on-disk-only is worth a line of CI log.
  const untracked = explicit
    ? []
    : getUntrackedRuleFiles(REPO_ROOT, execGit(REPO_ROOT), noteDiscoveryError);
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

  if (discoveryErrors.length > 0) {
    console.log(
      "[safety-gate] FAIL — rule discovery was incomplete, so nothing can be cleared:",
    );
    [...new Set(discoveryErrors)].forEach((m) => console.log(`  ✗ ${m}`));
    process.exit(1);
  }

  // Corpora are loaded once, counted, and printed. The counts are measured at
  // run time on purpose — they grow, and a number written into a comment or a
  // doc goes stale without anyone noticing.
  const corpora = loadBenignCorpora();
  console.log(
    `[safety-gate] benign corpora: ${corpora.skills.samples.length} skill file(s), ` +
      `${corpora.extended.samples.length} extended sample(s), ` +
      `${corpora.code.samples.length} code sample(s), ` +
      `${corpora.mentions.samples.length} research-mention sample(s)`,
  );
  const corpusFailures =
    newFiles.length > 0 || modifiedFiles.length > 0 ? censusFailures(corpora) : [];
  const benignCorpus = flattenCorpora(corpora);

  // Modified rules are checked differentially — a change may not introduce
  // benign FPs the rule did not already have. Runs even when no rule is added,
  // which is the case this gate previously ignored entirely.
  const modifiedFailures = [
    ...corpusFailures,
    ...(modifiedFiles.length > 0 && corpusFailures.length === 0
      ? await checkModifiedRulesNoNewFP(base, modifiedFiles, benignCorpus)
      : []),
  ];

  if (newFiles.length === 0) {
    if (explicit) {
      // Unreachable via resolveTargets, kept because the cost of being wrong
      // here is a false green.
      exitUsage([
        "targets were named but none survived resolution — refusing to report safe",
      ]);
    }
    if (modifiedFailures.length === 0) {
      console.log(
        modifiedFiles.length > 0
          ? `[safety-gate] PASS — ${modifiedFiles.length} modified rule(s) introduce no new benign FPs`
          : "[safety-gate] No new or modified rule files, and no target was named — nothing to check, treating as safe.",
      );
      process.exit(0);
    }
    console.log(
      `[safety-gate] FAIL — ${modifiedFailures.length} finding(s) need human review:`,
    );
    modifiedFailures.forEach((f) => console.log(`  ✗ ${f.file} — ${f.reason}`));
    process.exit(1);
  }

  if (!explicit && newFiles.length > maxNewPerPr) {
    console.log(
      `[safety-gate] FAIL — ${newFiles.length} new rules exceeds MAX_NEW_PER_PR=${maxNewPerPr}. Human review required.`,
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
    const loadedInScope = new Set<string>();
    for (const id of newRuleIds) {
      const rule = scopedEngine.getRuleById(id) as
        | Record<string, unknown>
        | undefined;
      if (!rule) continue;
      loadedInScope.add(id);
      if (rule['status'] === 'draft' || rule['status'] === 'test') {
        rule['status'] = 'active';
      }
    }

    // A rule the engine did not load matches nothing, and "matched nothing"
    // is exactly what a clean FP scan looks like. Every corpus check below
    // would pass vacuously, so refuse instead of clearing it.
    for (const id of newRuleIds) {
      if (!loadedInScope.has(id)) {
        failures.push({
          file: fileToId.get(id) ?? id,
          reason: `rule id ${id} did not load into the engine (schema rejected, or the file's id does not match) — its FP checks would be vacuous`,
        });
      }
    }

    // Check 2 — own TPs must actually match. Measured on the engine that
    // actually holds the rule: rules/ files come from the full rulebase, a
    // target outside rules/ (a proposal) from the scoped engine.
    const engineFor = (id: string): ATREngine =>
      engine.getRuleById(id) ? engine : scopedEngine;
    const tpMisses = await checkOwnTruePositivesMatch(
      engineFor,
      ruleEntries.filter((r) => loadedInScope.has(r.id)),
    );
    for (const [id, reasons] of tpMisses) {
      for (const r of reasons.slice(0, 3))
        failures.push({ file: fileToId.get(id) ?? id, reason: r });
      if (reasons.length > 3)
        failures.push({
          file: fileToId.get(id) ?? id,
          reason: `(+${reasons.length - 3} more TP-not-matched failures suppressed)`,
        });
    }

    // Check 3 — benign skill corpus FP (count printed above, counted on disk).
    const benignFps = await checkCorpusFP(
      scopedEngine,
      newRuleIds,
      corpora.skills.samples,
    );
    for (const [id, samples] of benignFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `benign-corpus FP on ${samples.length} sample(s): ${samples.slice(0, 3).join(", ")}${samples.length > 3 ? ", ..." : ""}`,
      });
    }

    // Check 3b — extended benign corpus FP (arxiv + npm + pypi).
    const extendedFps = await checkCorpusFP(
      scopedEngine,
      newRuleIds,
      corpora.extended.samples,
    );
    for (const [id, samples] of extendedFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `extended-benign FP on ${samples.length} sample(s): ${samples.slice(0, 3).join(", ")}${samples.length > 3 ? ", ..." : ""}`,
      });
    }

    // Check 3c — benign-CODE corpus FP (imports + normal library usage).
    // Hard gate against the import-FP class that slipped through before.
    const codeFps = await checkCorpusFP(
      scopedEngine,
      newRuleIds,
      corpora.code.samples,
    );
    for (const [id, samples] of codeFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `benign-CODE FP on ${samples.length} sample(s): ${samples.slice(0, 3).join(", ")}${samples.length > 3 ? ", ..." : ""}`,
      });
    }

    // Check 4 — research-mention corpus FP.
    const mentionFps = await checkCorpusFP(
      scopedEngine,
      newRuleIds,
      corpora.mentions.samples,
    );
    for (const [id, samples] of mentionFps) {
      failures.push({
        file: fileToId.get(id) ?? id,
        reason: `research-mention FP on ${samples.length} sample(s): ${samples.slice(0, 2).join(" | ")}${samples.length > 2 ? ", ..." : ""}`,
      });
    }

    // Check 5 — directed cross-rule conflict against existing and peer TNs.
    // A rule file that cannot be read contributes no true-negatives, so the
    // conflict it might have caused would never be looked for: report it.
    const tnLoadErrors: string[] = [];
    const conflictFps = await checkCrossRuleConflict(
      engine,
      newRuleIds,
      tnLoadErrors,
    );
    for (const err of tnLoadErrors.slice(0, 3)) {
      failures.push({ file: RULES_DIR, reason: err });
    }
    if (tnLoadErrors.length > 3) {
      failures.push({
        file: RULES_DIR,
        reason: `(+${tnLoadErrors.length - 3} more cross-rule corpus load error(s) suppressed)`,
      });
    }
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
      explicit
        ? `[safety-gate] PASS — ${newFiles.length} named rule(s) cleared every check`
        : `[safety-gate] PASS — ${newFiles.length} rule(s) safe to auto-merge`,
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
