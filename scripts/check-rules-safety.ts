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
 * A MODIFIED rule gets two differential checks instead, base against head:
 *   modified-rule FP  no benign false positive the rule did not already have.
 *   own-TP check      no true positive the rule matched at base, on a path it
 *                     matched it on, that it no longer matches, with every
 *                     case replayed as the base rule would receive it; every
 *                     true positive the change adds must match. Run the way
 *                     `atr test` runs a case. Before it, an edit that left a
 *                     rule unable to fire passed: a rule that matches nothing
 *                     introduces no false positive.
 * A renamed rule file is a modified one, compared with the file it was at base;
 * a changed file whose rule id differs, or that was not a rule at base, is a
 * new rule (routeChangedRuleFiles).
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
import { loadRulesFromDirectory } from "../src/loader.js";
import { normalizeMaturity } from "../src/quality/rule-contract.js";
import type { AgentEvent } from "../src/types.js";
import { conditionFields, matchedRuleIds, type RuleLike } from "./lib/corpus-event.js";
import {
  NO_HITS,
  caseHits,
  caseSnippet,
  declaredTruePositives,
  eventFor,
  matches,
  methodOf,
  testCaseEngine,
  type CaseHits,
} from "./lib/own-true-positives.js";
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

export interface Failure {
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
    // T: a rule file replaced by a symlink (or the reverse) is a modification;
    // git lists it under neither A, M nor R.
    ["diff", "--name-only", "--diff-filter=MT", `${base}...HEAD`, "--", "rules/"],
    "git diff (modified)",
    onError,
  );
}

/** A rule file as it was at base and as it is now: one path, or a rename. */
export interface ChangedRuleFile {
  readonly basePath: string;
  readonly headPath: string;
}

/**
 * Rule files git reports as renamed between base and HEAD, each with the path
 * it had at base. `git diff` pairs a moved file with its old path when the two
 * are similar enough, and then lists it under neither --diff-filter=A nor M: a
 * rule moved to another directory, and broken in the same commit, cleared this
 * gate with "nothing to check, treating as safe". A pair whose base path is not
 * a rule file is new to the rulebase, and main() checks it as a new rule.
 */
export function getRenamedRuleFiles(
  base: string,
  repoRoot: string = REPO_ROOT,
  run: GitRunner = execGit(repoRoot),
  onError: DiscoveryErrorSink = () => {},
): ChangedRuleFile[] {
  let out: string;
  try {
    out = run([
      "diff",
      "--name-status",
      "-z",
      "--find-renames",
      "--diff-filter=R",
      `${base}...HEAD`,
      "--",
      "rules/",
    ]);
  } catch (err) {
    const message = `git diff (renamed) failed: ${err instanceof Error ? err.message : String(err)}`;
    console.error(`[safety-gate] ${message}`);
    onError(message);
    return [];
  }
  // -z: status, base path, head path, NUL-terminated and never quoted.
  const fields = out.split("\0");
  if (fields[fields.length - 1] === "") fields.pop();
  const pairs: ChangedRuleFile[] = [];
  for (let i = 0; i < fields.length; i += 3) {
    const [status, basePath, headPath] = fields.slice(i, i + 3);
    if (!status?.startsWith("R") || !basePath || !headPath) {
      onError(`git diff (renamed) printed output this gate cannot read: ${JSON.stringify(fields.slice(i))}`);
      break;
    }
    if (isRuleFile(headPath)) pairs.push({ basePath, headPath });
  }
  return pairs;
}

/** The rule id a rule source declares, or null when it has none it can be read from. */
function ruleIdIn(content: string | null): string | null {
  if (content === null) return null;
  try {
    const doc = yamlLoad(content) as { id?: unknown } | null;
    return doc !== null && typeof doc === "object" && typeof doc.id === "string" ? doc.id : null;
  } catch {
    return null;
  }
}

/**
 * Split changed rule files into the ones to check as modified and the ones to
 * check as new. ATR ids are permanent, so a pair whose rule id differs between
 * base and head, or whose base path is not a rule file, is a rule the rulebase
 * has not had: git pairs a deleted rule with a similar added one as a rename,
 * and an id edited in place replaces one rule with another. Either gets every
 * new-rule check, including the per-PR cap, not a comparison with the rule it
 * replaced. An id that cannot be read on either side leaves the pair modified,
 * where the modified-rule checks report why.
 */
export function routeChangedRuleFiles(
  pairs: readonly ChangedRuleFile[],
  idAtBase: (path: string) => string | null,
  idAtHead: (path: string) => string | null,
): { readonly modified: readonly ChangedRuleFile[]; readonly added: readonly string[] } {
  const modified: ChangedRuleFile[] = [];
  const added: string[] = [];
  for (const pair of pairs) {
    if (!isRuleFile(pair.basePath)) {
      added.push(pair.headPath);
      continue;
    }
    const before = idAtBase(pair.basePath);
    const after = idAtHead(pair.headPath);
    if (before !== null && after !== null && before !== after) added.push(pair.headPath);
    else modified.push(pair);
  }
  return { modified, added };
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
  files: readonly ChangedRuleFile[],
  corpus: readonly LabelledSample[],
): Promise<Failure[]> {
  const failures: Failure[] = [];

  for (const { basePath, headPath: file } of files) {
    const baseContent = readFileAtRef(base, basePath);
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

/** Keys a test case uses to describe itself rather than to carry payload. */
const TEST_CASE_META_KEYS: ReadonlySet<string> = new Set([
  "expected",
  "description",
  "reason",
  "attack_type",
  "note",
  "matched_condition",
  "label",
]);

/**
 * What makes a true positive the same one in both versions: its payload, with
 * meta keys dropped, keys sorted and runs of whitespace collapsed. Editing a
 * description, or switching a YAML block from `|-` to `|`, is not a new case.
 */
function testCaseIdentity(tc: Record<string, unknown>): string {
  const canonical = (v: unknown): unknown => {
    if (typeof v === "string") return v.replace(/\s+/g, " ").trim();
    if (Array.isArray(v)) return v.map(canonical);
    if (v !== null && typeof v === "object") {
      const o = v as Record<string, unknown>;
      return Object.fromEntries(Object.keys(o).sort().map((k) => [k, canonical(o[k])]));
    }
    return v;
  };
  const payload = Object.fromEntries(
    Object.entries(tc).filter(([k]) => !TEST_CASE_META_KEYS.has(k)),
  );
  return JSON.stringify(canonical(payload));
}

/**
 * A rule the engine evaluates in no lane: status draft or deprecated, or
 * maturity deprecated (normalizeMaturity trims, as the lane gate does).
 */
const isInert = (rule: Record<string, unknown>): boolean =>
  rule["status"] === "draft" ||
  rule["status"] === "deprecated" ||
  normalizeMaturity(rule["maturity"]) === "deprecated";

const scanTargetOf = (rule: Record<string, unknown>): unknown =>
  (rule["tags"] as { scan_target?: unknown } | undefined)?.scan_target;

const sourceOf = (rule: Record<string, unknown>): unknown =>
  (rule["agent_source"] as { type?: unknown } | undefined)?.type;

/** A rule source as a YAML mapping, or null when it is not one. */
function parseRule(content: string): Record<string, unknown> | null {
  try {
    const doc = yamlLoad(content);
    return doc !== null && typeof doc === "object" && !Array.isArray(doc)
      ? (doc as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/**
 * An engine holding one version of a rule the way `atr test` holds it
 * (testCaseEngine in scripts/lib/own-true-positives.ts), read from its file by
 * the rule loader, so a rule the loader refuses is not in it.
 */
async function buildTestCaseEngine(
  name: string,
  content: string,
): Promise<{ engine: ATREngine; dir: string }> {
  const dir = mkdtempSync(join(tmpdir(), "atr-safety-testcase-"));
  try {
    writeFileSync(join(dir, name), content, "utf-8");
    const loaded = loadRulesFromDirectory(dir) as unknown as Array<Record<string, unknown>>;
    return { engine: testCaseEngine(loaded), dir };
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    throw err;
  }
}

/**
 * The paths a case matched on at base and no longer matches on. scanSkill()
 * counts for a scan_target skill or both rule. Any other rule matches on the
 * SKILL.md path only incidentally, through the skill compound gate, and losing
 * that while it still matches at runtime is not a loss; a case it matched only
 * that way and now matches nowhere is.
 */
function lostPaths(before: CaseHits, after: CaseHits, skillNative: boolean): string[] {
  const lost: string[] = [];
  if (before.evaluate && !after.evaluate) lost.push("evaluate()");
  if (before.skill && !after.skill && (skillNative || !matches(after))) lost.push("scanSkill()");
  return lost;
}

/**
 * The event a case is replayed to both versions as: what the base rule
 * received, with event.fields cut down to what production carries for it.
 * buildEventFromTestCase() fills every field alias (user_input, tool_args,
 * agent_message, ...) so that any rule can resolve its field in `atr test`.
 * Replayed whole, that event would let a changed condition read a field no
 * producer fills for this event; src/hook-handler.ts fills tool_name, tool_args
 * and content. Kept: the fields the base rule's conditions read, plus tool_name
 * and content, which every producer sets. Any other field a changed condition
 * reads then resolves the way src/engine.ts resolveField() resolves it for this
 * event type in production.
 */
function replayEvent(tc: Record<string, unknown>, baseRule: Record<string, unknown>): AgentEvent | null {
  const event = eventFor(tc, baseRule);
  if (event === null) return null;
  const keep = new Set([...conditionFields(baseRule as unknown as RuleLike), "tool_name", "content"]);
  const fields = Object.fromEntries(Object.entries(event.fields ?? {}).filter(([k]) => keep.has(k)));
  return { ...event, fields };
}

/**
 * The own-TP check for modified rules: a change may not stop a rule matching
 * its own true positives.
 *
 * Check 2 asks this of new rules only, and npm run gate:generalization asks it
 * of pattern rules only, with the regex applied to a case's text whatever field
 * or event the rule reads. A modified semantic rule got neither, so setting its
 * fallback_method from pattern to none, which leaves the synchronous engine
 * unable to fire it, passed. So did re-routing any rule (agent_source.type, or
 * the field a condition reads) away from the events its true positives arrive
 * as.
 *
 * Each true positive is run the way `atr test` runs it, on an engine holding
 * one version of the rule (buildTestCaseEngine). Differential, like the
 * modified-rule FP check, over the true positives the modified rule declares,
 * each replayed to both versions as the event the base rule would receive
 * (replayEvent), whatever the case looks like now:
 *
 *   the base rule matches it   the modified rule must still match it on each
 *                              path the base rule did (evaluate(), and
 *                              scanSkill() for a skill or both rule).
 *   it does not, and the case  debt this change did not create: reported,
 *   was declared at base       not charged.
 *   it does not, and the case  must match the modified rule, on the event
 *   is new                     buildEventFromTestCase() builds for it.
 *
 * Replaying every case under the base rule's routing, not only the ones whose
 * text is unchanged, is what keeps a re-routed rule from passing by editing
 * each case's keys.
 *
 * The modified rule must still match at least one of the cases the base rule
 * matched, kept or dropped, so replacing them all while changing the detection
 * does not get around the check; dropping some, as a precision fix does, is
 * reported. When there is no base measurement to compare with (the base rule
 * did not load or is behavioral), or the change puts a rule back in a lane
 * (it was draft or deprecated), every case must match, as for a new rule. A
 * rule that stays in a lane must keep a true positive when it had one; a rule
 * this change takes out of every lane may drop them. method: behavioral cannot
 * be run here (`atr test` skips it too): a rule behavioral in both versions is
 * skipped, and one made behavioral by this change matches nothing.
 */
export async function ownTruePositiveRegressions(
  file: string,
  baseContent: string,
  headContent: string,
): Promise<Failure[]> {
  const head = parseRule(headContent);
  if (head === null) {
    return [{ file, reason: "the modified rule does not parse, so its true positives cannot be checked" }];
  }
  const headTps = declaredTruePositives(head);
  if (headTps === null) {
    return [{ file, reason: "test_cases.true_positives is not a list, so its true positives cannot be checked" }];
  }
  const base = parseRule(baseContent);
  const baseTps = (base === null ? [] : declaredTruePositives(base)) ?? [];

  if (headTps.length === 0) {
    if (isInert(head)) return [];
    if (baseTps.length > 0 || (base !== null && isInert(base))) {
      return [
        {
          file,
          reason:
            baseTps.length > 0
              ? `the change removes every true positive (base declared ${baseTps.length}) from a rule ` +
                `that stays in a lane; keep at least one, or this check cannot tell whether the rule still fires`
              : "the change puts a draft or deprecated rule back in a lane without a true positive; " +
                "add one, so this check can tell whether the rule fires",
        },
      ];
    }
    return [];
  }

  const headBehavioral = methodOf(head) === "behavioral";
  if (headBehavioral && (base === null || methodOf(base) === "behavioral")) {
    console.log(
      `  [own-TP advisory] ${file} — method: behavioral cannot be run on the synchronous path; ` +
        `its true positives were not checked`,
    );
    return [];
  }

  const headId = typeof head["id"] === "string" ? head["id"] : "";
  const baseId = base !== null && typeof base["id"] === "string" ? base["id"] : "";
  const name = basename(file);
  let headBuilt: { engine: ATREngine; dir: string } | null = null;
  let baseBuilt: { engine: ATREngine; dir: string } | null = null;
  try {
    headBuilt = await buildTestCaseEngine(name, headContent);
    if (base !== null) baseBuilt = await buildTestCaseEngine(name, baseContent);
    if (headId === "" || !headBuilt.engine.getRuleById(headId)) {
      return [
        {
          file,
          reason:
            "the modified rule did not load into the engine (schema rejected, or the file's id " +
            "does not match) — its true positives cannot be checked",
        },
      ];
    }
    const baseRule = base;
    const baseEngine =
      baseRule !== null && baseBuilt !== null && baseBuilt.engine.getRuleById(baseId) &&
      methodOf(baseRule) !== "behavioral"
        ? baseBuilt.engine
        : null;
    const revived = baseRule !== null && isInert(baseRule) && !isInert(head);
    // Nothing to compare with: every case must match, as for a new rule.
    const comparable = baseEngine !== null && !revived;
    const skillNative = baseRule !== null && ["skill", "both"].includes(String(scanTargetOf(baseRule)));
    const headEngine = headBehavioral ? null : headBuilt.engine;
    const atBase = (tc: Record<string, unknown>, event: AgentEvent | null): CaseHits =>
      baseEngine === null ? NO_HITS : caseHits(baseEngine, baseId, tc, event);
    const atHead = (tc: Record<string, unknown>, event: AgentEvent | null): CaseHits =>
      headEngine === null ? NO_HITS : caseHits(headEngine, headId, tc, event);

    const rerouted =
      baseRule !== null && sourceOf(baseRule) !== sourceOf(head)
        ? ` (agent_source.type ${String(sourceOf(baseRule))} -> ${String(sourceOf(head))}; ` +
          `the case is replayed as the base rule received it)`
        : "";
    const declaredAtBase = new Map(baseTps.map((tc) => [testCaseIdentity(tc), tc]));
    const unmatchedReason = comparable
      ? "true positive added by this change is not matched"
      : revived
        ? "true positive of a rule this change puts back in a lane is not matched"
        : "true positive is not matched, and the rule at base could not be run to compare";
    const failures: Failure[] = [];
    let debt = 0;
    for (const tc of headTps) {
      if (comparable && baseRule !== null) {
        const event = replayEvent(tc, baseRule);
        const before = atBase(tc, event);
        const after = atHead(tc, event);
        const lost = lostPaths(before, after, skillNative);
        if (lost.length > 0) {
          failures.push({
            file,
            reason:
              `own true positive matched at base on ${lost.join(" and ")}, not after this ` +
              `change${rerouted}: "${caseSnippet(tc)}..."`,
          });
          continue;
        }
        if (matches(before)) continue;
        if (declaredAtBase.has(testCaseIdentity(tc))) {
          if (!matches(after)) debt++;
          continue;
        }
      }
      if (!matches(atHead(tc, eventFor(tc, head)))) {
        failures.push({ file, reason: `${unmatchedReason}: "${caseSnippet(tc)}..."` });
      }
    }

    // Every case the base rule matched, kept or dropped. The modified rule must
    // still match one of them, or a change that rewrites the detection and all
    // of its cases at once would leave nothing to compare.
    const matchedAtBase =
      comparable && baseRule !== null
        ? baseTps.filter((tc) => matches(atBase(tc, replayEvent(tc, baseRule))))
        : [];
    const stillMatched = (tc: Record<string, unknown>): boolean =>
      baseRule !== null && matches(atHead(tc, replayEvent(tc, baseRule)));
    if (failures.length === 0 && matchedAtBase.length > 0 && !matchedAtBase.some(stillMatched)) {
      failures.push({
        file,
        reason:
          `the rule matched ${matchedAtBase.length} of its true positives at base and matches ` +
          `none of them after this change`,
      });
    }
    if (debt > 0) {
      console.log(
        `  [own-TP advisory] ${file} — ${debt} declared true positive(s) the rule did not ` +
          `match at base either (not charged to this change)`,
      );
    }
    const kept = new Set(headTps.map(testCaseIdentity));
    const dropped = matchedAtBase.filter((tc) => !kept.has(testCaseIdentity(tc)));
    if (dropped.length > 0) {
      const lostWithThem = dropped.filter((tc) => !stillMatched(tc)).length;
      console.log(
        `  [own-TP advisory] ${file} — ${dropped.length} true positive(s) the base rule matched ` +
          `are no longer declared` +
          (lostWithThem > 0 ? `; the modified rule no longer matches ${lostWithThem} of them` : ""),
      );
    }
    return failures;
  } catch (err) {
    return [
      {
        file,
        reason: `could not build scoped engines to compare own true positives against base: ${asMessage(err)}`,
      },
    ];
  } finally {
    if (headBuilt) rmSync(headBuilt.dir, { recursive: true, force: true });
    if (baseBuilt) rmSync(baseBuilt.dir, { recursive: true, force: true });
  }
}

/** The own-TP check over every modified rule file; see ownTruePositiveRegressions(). */
async function checkModifiedRulesKeepOwnTPs(
  base: string,
  files: readonly ChangedRuleFile[],
): Promise<Failure[]> {
  const failures: Failure[] = [];
  for (const { basePath, headPath: file } of files) {
    const baseContent = readFileAtRef(base, basePath);
    const headPath = join(REPO_ROOT, file);
    // An unreadable base or a missing head is the modified-rule FP check's to
    // report (or the gate has already failed on the corpus census).
    if (baseContent === null || !existsSync(headPath)) continue;
    const headContent = readFileSync(headPath, "utf-8");
    if (baseContent === headContent) continue;
    failures.push(...(await ownTruePositiveRegressions(file, baseContent, headContent)));
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

  // Modified and renamed rule files are compared with the file they were at
  // base, unless the rule id changed or the base file was not a rule: then the
  // rulebase has a new rule (routeChangedRuleFiles).
  const changed: readonly ChangedRuleFile[] = explicit
    ? []
    : [
        ...getModifiedRuleFiles(base, REPO_ROOT, execGit(REPO_ROOT), noteDiscoveryError).map(
          (f): ChangedRuleFile => ({ basePath: f, headPath: f }),
        ),
        ...getRenamedRuleFiles(base, REPO_ROOT, execGit(REPO_ROOT), noteDiscoveryError),
      ];
  const routed = routeChangedRuleFiles(
    changed,
    (p) => ruleIdIn(readFileAtRef(base, p)),
    (p) => {
      const abs = join(REPO_ROOT, p);
      return ruleIdIn(existsSync(abs) ? readFileSync(abs, "utf-8") : null);
    },
  );
  const newFiles = explicit
    ? [...targets.files]
    : [
        ...new Set([
          ...getNewRuleFiles(base, REPO_ROOT, execGit(REPO_ROOT), noteDiscoveryError),
          ...routed.added,
        ]),
      ].sort();

  if (explicit) {
    console.log(
      `[safety-gate] explicit-target mode: ${newFiles.length} file(s) named by the caller`,
    );
    newFiles.forEach((f) => console.log(`  • ${f}`));
  } else {
    console.log(`[safety-gate] base=${base}`);
  }
  const modifiedFiles = routed.modified;
  const renamedCount = modifiedFiles.filter((f) => f.basePath !== f.headPath).length;
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
      `[safety-gate] ${modifiedFiles.length} modified rule file(s) detected` +
        (renamedCount > 0 ? ` (${renamedCount} renamed)` : ""),
    );
  }
  if (routed.added.length > 0) {
    console.log(
      `[safety-gate] ${routed.added.length} changed rule file(s) checked as new rules ` +
        `(rule id changed, or not a rule file at base): ${routed.added.join(", ")}`,
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
  // benign FPs the rule did not already have, nor stop it matching its own true
  // positives (the own-TP check). Runs even when no rule is added, which is the
  // case this gate previously ignored entirely.
  const modifiedFailures = [
    ...corpusFailures,
    ...(modifiedFiles.length > 0 && corpusFailures.length === 0
      ? await checkModifiedRulesNoNewFP(base, modifiedFiles, benignCorpus)
      : []),
    ...(modifiedFiles.length > 0
      ? await checkModifiedRulesKeepOwnTPs(base, modifiedFiles)
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
          ? `[safety-gate] PASS — ${modifiedFiles.length} modified rule(s) introduce no new benign FPs and still match their own true positives`
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
