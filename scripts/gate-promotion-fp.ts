#!/usr/bin/env node
/**
 * gate-promotion-fp.ts — block a maturity promotion that would put an
 * FP-producing rule into the enforce (auto-block) lane, and/or hand back the
 * FP-clean subset so an upstream promoter can promote only what is safe.
 *
 * WHY: maturity:stable is the enforce lane (see engine.ts — "enforce = only
 * maturity=stable rules, auto-block, lowest FP"). A promoter that keys on time
 * (">=60 days in test + 0 FP *reports*") can promote a rule that has never been
 * scanned against a benign corpus. This gate re-runs the rules a PR promotes to
 * stable/production against the local benign corpora and FAILS if any of them
 * false-positive — so a bad promotion turns the PR red instead of shipping.
 *
 * The same scan is also useful BEFORE a promotion PR exists: run it as a filter,
 * take the clean ids, and open a PR that only promotes those. That is what
 * --emit-clean / --emit-dirty / --filter-mode are for.
 *
 * Modes:
 *   gate-promotion-fp.ts --base origin/main   # auto-detect rules this branch
 *                                             # sets to stable/production, gate them
 *   gate-promotion-fp.ts --ids <file>         # gate an explicit ATR-id list.
 *                                             # Every id MUST resolve to a rule
 *                                             # file on disk (tracked or not);
 *                                             # an id that does not is exit 3.
 *
 * Output flags (compose with either mode):
 *   --emit-clean <path>   write the FP-clean ids, one per line
 *   --emit-dirty <path>   write the FP-producing ids, one per line (worst first)
 *   --filter-mode         report FP-dirty rules but still exit 0
 *
 * Exit codes:
 *   0  gate passed (no promoted rule false-positives), nothing to gate, OR
 *      --filter-mode was requested (the caller consumes the emitted lists
 *      instead of the exit code)
 *   1  gate failed: at least one promoted rule FPs on the benign corpus
 *      (default/gate semantics — unchanged), or an unexpected runtime error
 *   2  usage error: the flags given cannot produce a meaningful run
 *   3  --ids named rule ids that no file on disk carries. The requested scan
 *      cannot be performed, so no verdict is reported (see below).
 *
 * DEFAULT BEHAVIOUR IS FROZEN: with no output flags this script behaves exactly
 * as before (CI's maturity-fp-gate workflow depends on it). --emit-clean alone
 * keeps gate semantics — it only adds a side output. Only the explicit opt-in
 * --filter-mode relaxes the exit code, and it refuses to run unless it is
 * paired with an emit target, so it can never be used to silently mute the gate.
 *
 * THREE WAYS THIS GATE USED TO PASS WITHOUT MEASURING ANYTHING (all fixed here):
 *
 *   1. The candidate list came from `git ls-files rules/` — tracked files only.
 *      Rules are routinely written to rules/ and gated BEFORE being committed
 *      (scripts/fn-mine-llm.ts authors straight into the tree, then gates), and
 *      for those `--ids` resolved zero targets, printed "nothing to gate" and
 *      exited 0. A zero-measurement PASS on precisely the rules that had never
 *      been measured. Candidates now include untracked-but-not-ignored files.
 *
 *   2. An id in the --ids file that matched no rule on disk was a WARN and
 *      nothing more. A promoter feeding a stale or typo'd id list therefore got
 *      exit 0 and an empty clean list, which reads as "scanned, all fine". That
 *      is now exit 3, with the unresolved ids named, and no list is written —
 *      an unread verdict must not leave a consumable artifact behind.
 *
 *   3. THE EVENT SHAPE COULD NOT RESOLVE THE FIELD THE RULE DETECTS ON. The scan
 *      built one `mcp_exchange` event carrying only tool_name / tool_input /
 *      tool_response / user_input. `field: tool_args` resolves to undefined on
 *      that event (src/engine.ts resolveField wants fields.tool_args, or an event
 *      typed tool_call), so all 40 rules that detect on tool_args — three of them
 *      maturity:stable, i.e. already in the auto-blocking enforce lane — were
 *      scored against a field no sample ever filled, and every one came back
 *      CLEAN. Same for agent_output, agent_message and tool_description. The
 *      shape set now lives in scripts/lib/corpus-event.ts, mirrors what
 *      src/hook-handler.ts actually emits (including the JSON encoding of
 *      tool_args), and is meant to be shared with the true-positive side so a
 *      rule can never earn its detection credit on a wider shape than the one it
 *      pays its false positives on. Fields a text corpus genuinely cannot fill
 *      (tool_name, trace, behavioral) are now reported as NOT MEASURED instead of
 *      being folded silently into the clean list.
 */
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  readdirSync,
  existsSync,
  statSync,
  mkdtempSync,
  copyFileSync,
} from "node:fs";
import { join, resolve, dirname, basename } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import {
  corpusShapes,
  shapeNames,
  fieldCoverage,
  skillPathCoverage,
  unmeasurableReason,
  type FieldCoverage,
  type SkillPathGap,
} from "./lib/corpus-event.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ENFORCE_MATURITIES = new Set(["stable", "production"]);

export const EXIT_OK = 0;
export const EXIT_FAIL = 1;
export const EXIT_USAGE = 2;
export const EXIT_MISSING_IDS = 3;

/** Thrown when the given flag combination cannot produce a meaningful run. */
export class GateUsageError extends Error {}

export interface GateOptions {
  readonly idsFile: string | null;
  readonly base: string;
  readonly emitClean: string | null;
  readonly emitDirty: string | null;
  readonly filterMode: boolean;
}

/**
 * Filesystem surface the gate reads. Injected so tests can run the whole gate
 * against a fixture corpus. Deliberately NOT reachable from the CLI or the
 * environment: a security gate must not be re-pointable by configuration.
 */
export interface GateDeps {
  readonly repoRoot: string;
  readonly rulesDir: string;
  readonly corpora: readonly string[];
  /** Repo-relative paths of every rule file the gate can scan. */
  readonly listRuleFiles: () => readonly string[];
}

export function defaultDeps(): GateDeps {
  return {
    repoRoot: REPO_ROOT,
    rulesDir: join(REPO_ROOT, "rules"),
    corpora: [
      join(REPO_ROOT, "data/skill-benchmark/benign"),
      join(REPO_ROOT, "data/benign-corpus-extended"),
      join(REPO_ROOT, "data/benign-code"),
    ],
    listRuleFiles: () => gitRuleFiles(REPO_ROOT),
  };
}

// ---------------------------------------------------------------------------
// CLI parsing (pure)
// ---------------------------------------------------------------------------

/** Legacy lookup for --ids / --base: absent or value-less both read as null. */
function legacyValue(argv: readonly string[], name: string): string | null {
  const i = argv.indexOf(name);
  return i >= 0 ? (argv[i + 1] ?? null) : null;
}

/** Strict lookup for the output flags: a flag without a value is an error. */
function pathValue(argv: readonly string[], name: string): string | null {
  const i = argv.indexOf(name);
  if (i < 0) return null;
  const value = argv[i + 1];
  if (value === undefined || value.startsWith("--") || value.trim() === "") {
    throw new GateUsageError(`${name} requires a <path> value`);
  }
  return value;
}

export function parseCliOptions(argv: readonly string[]): GateOptions {
  const emitClean = pathValue(argv, "--emit-clean");
  const emitDirty = pathValue(argv, "--emit-dirty");
  const filterMode = argv.includes("--filter-mode");
  if (emitClean !== null && emitClean === emitDirty) {
    throw new GateUsageError("--emit-clean and --emit-dirty must be different paths");
  }
  if (filterMode && emitClean === null && emitDirty === null) {
    throw new GateUsageError(
      "--filter-mode suppresses the failure exit code, so it must be paired with " +
        "--emit-clean <path> and/or --emit-dirty <path>. Without an emitted list the " +
        "run produces no machine-readable output and would only hide FP-dirty rules.",
    );
  }
  return {
    idsFile: legacyValue(argv, "--ids"),
    base: legacyValue(argv, "--base") ?? "origin/main",
    emitClean,
    emitDirty,
    filterMode,
  };
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/** Rule files a diff sets to an enforce-lane maturity. */
export function parsePromotedFiles(diff: string): readonly string[] {
  const files = new Set<string>();
  let current: string | null = null;
  for (const line of diff.split("\n")) {
    const header = /^\+\+\+ b\/(rules\/.*\.ya?ml)$/.exec(line);
    if (header) {
      current = header[1] ?? null;
      continue;
    }
    const maturity = /^\+\s*maturity:\s*["']?(\w+)["']?\s*$/.exec(line);
    if (maturity && current && ENFORCE_MATURITIES.has(maturity[1] ?? "")) files.add(current);
  }
  return [...files];
}

export interface FpPartition {
  readonly clean: readonly string[];
  readonly dirty: readonly (readonly [string, number])[];
}

/** Split scanned ids into FP-clean and FP-producing, deterministically ordered. */
export function partitionByFp(counts: ReadonlyMap<string, number>): FpPartition {
  const entries = [...counts.entries()];
  const clean = entries
    .filter(([, n]) => n === 0)
    .map(([id]) => id)
    .sort((a, b) => a.localeCompare(b));
  const dirty = entries
    .filter(([, n]) => n > 0)
    .map(([id, n]) => [id, n] as const)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return { clean, dirty };
}

/**
 * Gate semantics (default): any FP-dirty rule fails the run.
 * Filter semantics (--filter-mode): the caller wants the lists, not a verdict,
 * so a dirty finding is data — exiting non-zero would abort a `set -e` promoter.
 */
export function resolveExitCode(dirtyCount: number, filterMode: boolean): number {
  if (dirtyCount === 0) return EXIT_OK;
  return filterMode ? EXIT_OK : EXIT_FAIL;
}

/** One id per line; an empty list yields an empty file, never a blank line. */
export function formatIdList(ids: readonly string[]): string {
  return ids.length === 0 ? "" : `${ids.join("\n")}\n`;
}

// ---------------------------------------------------------------------------
// Filesystem / git
// ---------------------------------------------------------------------------

/** Runs a git command in the repo and returns stdout. Injected so the file
 *  discovery contract can be tested without spawning git. */
export type GitRunner = (args: readonly string[]) => string;

function execGit(repoRoot: string): GitRunner {
  return (args) =>
    execFileSync("git", [...args], {
      cwd: repoRoot,
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
}

/**
 * Every rule file the gate may scan: tracked, PLUS untracked-but-not-ignored.
 *
 * The untracked half is the whole point. `git ls-files rules/` alone made the
 * gate blind to rules that exist on disk but have never been committed — which
 * is the normal state of a freshly authored rule, and the exact moment its FP
 * behaviour most needs measuring. With them invisible, `--ids` resolved zero
 * targets and the gate printed "nothing to gate" and exited 0.
 *
 * Files that git still tracks but that are gone from the working tree are
 * dropped: the gate measures what is on disk, and a deleted rule cannot be
 * scanned. If such an id was explicitly requested it surfaces as a missing id
 * (exit 3) rather than as a crash or a silent skip.
 */
export function gitRuleFiles(repoRoot: string, run: GitRunner = execGit(repoRoot)): readonly string[] {
  const isRule = (f: string): boolean => f.endsWith(".yaml") || f.endsWith(".yml");
  const tracked = run(["ls-files", "--", "rules/"]).split("\n").filter(isRule);
  const untracked = run(["ls-files", "--others", "--exclude-standard", "--", "rules/"])
    .split("\n")
    .filter(isRule);
  return [...new Set([...tracked, ...untracked])]
    .filter((f) => existsSync(join(repoRoot, f)))
    .sort();
}

function promotedFilesFromDiff(base: string, repoRoot: string): readonly string[] {
  const diff = execFileSync("git", ["diff", `${base}...HEAD`, "--unified=0", "--", "rules/"], {
    cwd: repoRoot,
    encoding: "utf-8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return parsePromotedFiles(diff);
}

function ruleIdOf(repoRoot: string, file: string): string | null {
  for (const line of readFileSync(join(repoRoot, file), "utf-8").split("\n")) {
    const m = /^id:\s*(\S+)/.exec(line);
    if (m) return m[1] ?? null;
  }
  return null;
}

function writeIdList(path: string, ids: readonly string[]): void {
  const target = resolve(path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, formatIdList(ids), "utf-8");
}

/** Always write the requested lists — even empty ones — so `set -e` callers can read unconditionally. */
function emitLists(options: GateOptions, partition: FpPartition): void {
  if (options.emitClean !== null) {
    writeIdList(options.emitClean, partition.clean);
    console.log(`[fp-gate] wrote ${partition.clean.length} clean id(s) -> ${options.emitClean}`);
  }
  if (options.emitDirty !== null) {
    const ids = partition.dirty.map(([id]) => id);
    writeIdList(options.emitDirty, ids);
    console.log(`[fp-gate] wrote ${ids.length} dirty id(s) -> ${options.emitDirty}`);
  }
}

/**
 * Every rule id a benign sample matches, across the whole canonical shape set.
 *
 * Counted PER SAMPLE, not per shape: a document that trips a rule on two shapes
 * is one false positive, not two. That keeps the number comparable with what the
 * gate reported before the shape set was widened.
 */
function matchedRuleIds(engine: ATREngine, text: string): ReadonlySet<string> {
  const matched = new Set<string>();
  for (const shape of corpusShapes(text)) {
    for (const m of engine.evaluate(shape.event)) matched.add(m.rule.id);
  }
  for (const m of engine.scanSkill(text)) matched.add(m.rule.id);
  return matched;
}

/**
 * Every corpus file under a path, INCLUDING subdirectories.
 *
 * This walk used to be one level deep. `data/skill-benchmark/benign` holds 466
 * committed samples, 35 of which live in `ninja-legit/` — so the gate loaded 431
 * and reported the other 35 as clean by never opening them. That is the same
 * disease as a narrow event shape: not a wrong answer, an unasked question. A
 * sample that is committed to a benign corpus is a sample the gate has to read,
 * and a subdirectory must never be able to hide one.
 */
function collectCorpusFiles(dir: string): readonly string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...collectCorpusFiles(full));
    else if (e.endsWith(".jsonl") || e.endsWith(".md")) out.push(full);
  }
  return out;
}

function loadCorpusTexts(pathStr: string): readonly string[] {
  const texts: string[] = [];
  if (!existsSync(pathStr)) return texts;
  const files: string[] = [];
  if (statSync(pathStr).isDirectory()) files.push(...collectCorpusFiles(pathStr));
  else files.push(pathStr);
  for (const f of files) {
    let raw: string;
    try {
      raw = readFileSync(f, "utf-8");
    } catch {
      continue;
    }
    if (f.endsWith(".md")) {
      texts.push(raw);
      continue;
    }
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        const obj = JSON.parse(t) as { text?: string };
        if (typeof obj.text === "string" && obj.text.length > 0) texts.push(obj.text);
      } catch {
        continue;
      }
    }
  }
  return texts;
}

/** Copy just the target rule files into a temp dir so the engine loads only them. */
function scopedRulesDir(repoRoot: string, files: readonly string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "atr-gate-"));
  for (const f of files) copyFileSync(join(repoRoot, f), join(dir, basename(f)));
  return dir;
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

interface Targets {
  readonly files: readonly string[];
  readonly ids: ReadonlySet<string>;
  /** Ids requested via --ids that no rule file on disk carries. */
  readonly missing: readonly string[];
}

function targetsFromIdsFile(idsFile: string, deps: GateDeps): Targets {
  const requested = new Set(
    readFileSync(idsFile, "utf-8")
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const files: string[] = [];
  const found = new Set<string>();
  for (const f of deps.listRuleFiles()) {
    const id = ruleIdOf(deps.repoRoot, f);
    if (id !== null && requested.has(id)) {
      files.push(f);
      found.add(id);
    }
  }
  const missing = [...requested].filter((id) => !found.has(id)).sort();
  return { files, ids: found, missing };
}

function resolveTargets(options: GateOptions, deps: GateDeps): Targets {
  if (options.idsFile !== null) return targetsFromIdsFile(options.idsFile, deps);
  const files = promotedFilesFromDiff(options.base, deps.repoRoot);
  const ids = files
    .map((f) => ruleIdOf(deps.repoRoot, f))
    .filter((x): x is string => x !== null);
  return { files, ids: new Set(ids), missing: [] };
}

interface ScanResult {
  readonly counts: ReadonlyMap<string, number>;
  readonly sampleCount: number;
  /** Target rules with conditions this corpus cannot measure. */
  readonly coverage: readonly FieldCoverage[];
  /** Target rules the `skill` half of matchedRuleIds cannot ever match. */
  readonly skillCoverage: readonly SkillPathGap[];
}

async function scanFpCounts(targets: Targets, deps: GateDeps): Promise<ScanResult> {
  const engine = new ATREngine({ rulesDir: scopedRulesDir(deps.repoRoot, targets.files) });
  await engine.loadRules();

  const samples: string[] = [];
  for (const c of deps.corpora) samples.push(...loadCorpusTexts(c));

  const counts = new Map<string, number>();
  for (const id of targets.ids) counts.set(id, 0);
  for (const text of samples) {
    for (const id of matchedRuleIds(engine, text)) {
      if (targets.ids.has(id)) counts.set(id, (counts.get(id) ?? 0) + 1);
    }
  }
  const coverage = fieldCoverage(engine.getRules()).filter((c) => targets.ids.has(c.ruleId));
  const skillCoverage = skillPathCoverage(engine.getRules()).filter((c) => targets.ids.has(c.ruleId));
  return { counts, sampleCount: samples.length, coverage, skillCoverage };
}

/**
 * "Clean" must never be allowed to mean "never looked at it".
 *
 * A condition on a field this corpus cannot fill (tool_name has no benign corpus;
 * trace/behavioral rules need a span DAG or a metric window) contributes nothing
 * to the FP count. Silence from such a rule is an absence of evidence, so it is
 * named here rather than folded into the clean list without comment. The exit
 * code is deliberately NOT changed: these rules are unmeasurABLE with a text
 * corpus, so failing them would block promotion with no available remedy. Making
 * it loud is the honest half of the fix.
 */
function reportCoverage(coverage: readonly FieldCoverage[]): void {
  if (coverage.length === 0) return;
  console.log(
    `\n[fp-gate] NOT MEASURED — ${coverage.length} rule(s) declare conditions this benign ` +
      `corpus cannot exercise. Their silence below is not evidence of precision:`,
  );
  for (const c of coverage) {
    const tag = c.zeroMeasurement ? "ZERO-MEASUREMENT" : "partially measured";
    console.log(`  ${c.ruleId} — ${tag}`);
    for (const f of c.unmeasured) console.log(`      ${f}: ${unmeasurableReason(f)}`);
  }
}

/**
 * "shapes = ..., skill" must not be allowed to imply the skill path measured
 * anything.
 *
 * engine.scanSkill() applies a compound gate to every rule that is not
 * `scan_target: skill|both`, and that gate is arithmetically unreachable for a
 * `condition: any` rule — evaluateArrayConditions breaks on the first match, so
 * matchedConditions.length is capped at 1 while the gate demands at least 2. On
 * main that is 645 of 780 rules, 102 of them maturity:stable. Their silence on
 * the skill half of matchedRuleIds() is not evidence about the skill path.
 *
 * The exit code deliberately does NOT change, for the same reason reportCoverage
 * does not change it: an `scan_target: mcp` rule not running on a SKILL.md is
 * the intended behaviour, so failing on it would block every promotion with
 * nothing to fix. Saying it out loud is the whole remedy.
 */
function reportSkillPathCoverage(gaps: readonly SkillPathGap[]): void {
  if (gaps.length === 0) return;
  const enforce = gaps.filter((g) => g.claimsEnforceLane);
  console.log(
    `\n[fp-gate] NOT MEASURED ON THE SKILL PATH — ${gaps.length} rule(s) cannot produce a ` +
      `match through engine.scanSkill() for any input` +
      (enforce.length > 0 ? `, ${enforce.length} of them in the enforce lane` : "") +
      `. They were measured on the evaluate() shapes only:`,
  );
  for (const g of gaps) {
    console.log(
      `  ${g.ruleId} — ${g.blocker} (max ${g.maxAttainableConditions} of ${g.requiredConditions} ` +
        `required matched conditions)`,
    );
    console.log(`      ${g.reason}`);
  }
}

function report(
  partition: FpPartition,
  sampleCount: number,
  filterMode: boolean,
  coverage: readonly FieldCoverage[] = [],
  skillCoverage: readonly SkillPathGap[] = [],
): void {
  console.log(`[fp-gate] corpus = ${sampleCount} benign samples`);
  console.log(
    `[fp-gate] shapes = ${shapeNames().join(", ")}, skill ` +
      `(a rule's true positives MUST be measured on this same set)`,
  );
  console.log(`[fp-gate] clean = ${partition.clean.length} · dirty = ${partition.dirty.length}`);
  reportCoverage(coverage);
  reportSkillPathCoverage(skillCoverage);
  if (partition.dirty.length === 0) {
    console.log(`[fp-gate] PASS — all promoted rules are FP-clean on the benign corpus.`);
    return;
  }
  if (filterMode) {
    console.log(`\n[fp-gate] FILTERED — these rules false-positive on benign content and were`);
    console.log(`excluded from the clean list (they must not enter the enforce lane):`);
    for (const [id, n] of partition.dirty) console.log(`  ${id} — ${n} FP`);
    return;
  }
  console.error(`\n[fp-gate] FAIL — these promoted rules false-positive on benign content and`);
  console.error(`must not enter the enforce (auto-block) lane:`);
  for (const [id, n] of partition.dirty) console.error(`  ${id} — ${n} FP`);
}

/**
 * An id the caller asked us to scan that no rule file carries is not a warning.
 * The requested measurement did not happen, so there is no verdict to report —
 * and reporting exit 0 with an empty clean list is indistinguishable from
 * "scanned it, it was fine". Fail loudly, name the ids, and write nothing:
 * leaving a consumable list behind would let a caller that ignores the exit
 * code act on a scan that never ran.
 */
function reportMissingIds(missing: readonly string[], idsFile: string): number {
  console.error(
    `[fp-gate] FAIL — ${missing.length} requested id(s) match no rule file on disk. ` +
      `Nothing was measured for them:`,
  );
  for (const id of missing) console.error(`  ${id}`);
  console.error(
    `\nThe id list (${idsFile}) is stale, misspelled, or names rules that were removed.\n` +
      `No clean/dirty list was written — an unmeasured rule must not be promoted.`,
  );
  return EXIT_MISSING_IDS;
}

export async function runGate(options: GateOptions, deps: GateDeps = defaultDeps()): Promise<number> {
  const targets = resolveTargets(options, deps);
  if (targets.missing.length > 0 && options.idsFile !== null) {
    return reportMissingIds(targets.missing, options.idsFile);
  }

  if (targets.files.length === 0) {
    const scope = options.idsFile !== null ? `in ${options.idsFile}` : `vs ${options.base}`;
    console.log(`[fp-gate] no rules promoted to enforce lane ${scope} — nothing to gate.`);
    emitLists(options, { clean: [], dirty: [] });
    return EXIT_OK;
  }

  console.log(
    `[fp-gate] gating ${targets.files.length} promoted rule(s) against the benign corpus`,
  );
  const { counts, sampleCount, coverage, skillCoverage } = await scanFpCounts(targets, deps);
  const partition = partitionByFp(counts);
  report(partition, sampleCount, options.filterMode, coverage, skillCoverage);
  emitLists(options, partition);
  return resolveExitCode(partition.dirty.length, options.filterMode);
}

export async function main(
  argv: readonly string[],
  deps: GateDeps = defaultDeps(),
): Promise<number> {
  let options: GateOptions;
  try {
    options = parseCliOptions(argv);
  } catch (e: unknown) {
    if (e instanceof GateUsageError) {
      console.error(`[fp-gate] usage error: ${e.message}`);
      return EXIT_USAGE;
    }
    throw e;
  }
  return runGate(options, deps);
}

// Only run when invoked directly (so unit tests can import the pure helpers).
const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((e: unknown) => {
      console.error(e instanceof Error ? e.stack : String(e));
      process.exitCode = EXIT_FAIL;
    });
}
