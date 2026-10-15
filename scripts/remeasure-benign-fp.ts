#!/usr/bin/env node
/**
 * remeasure-benign-fp.ts — extend the committed benign-corpus false-positive
 * evidence (data/benign-fp-measurement.json) to a grown corpus, measuring only
 * what the growth can have changed.
 *
 * WHY
 *
 * scripts/gate-action-eligibility.ts binds that evidence to a digest of the
 * benign corpus, so any change to the corpus needs the evidence re-measured. A
 * full measurement (scripts/gate-promotion-fp.ts --emit-measurement over every
 * rule) takes three to four hours on CI: the daily re-verify job hit its 240
 * minute limit in 11 of its last 14 runs. The weekly benign harvest adds a few
 * hundred samples. A rule's false-positive count is a sum over samples — each
 * sample adds one if the rule fires on it, and nothing a rule does depends on
 * any other sample or on any other rule — so a rule whose detection has not
 * changed needs only the NEW samples measured, and its count is the committed
 * count plus theirs.
 *
 * THE CONTRACT
 *
 * The file written is identical to what a full
 *   gate-promotion-fp.ts --ids <every rule> --filter-mode --emit-measurement <path>
 * run would write on the same tree, except `generated_at` and `commit`.
 * tests/remeasure-benign-fp.test.ts checks that against the real full
 * measurement. Anything that would break the sum refuses instead (exit 4) and
 * writes nothing; a full measurement is then the only honest answer.
 *
 * HOW
 *
 *  1. The base is --base-ref (default HEAD): its committed evidence E, and the
 *     corpus as it was at that commit, materialized with `git archive`.
 *  2. Preconditions, each exit 4: E was measured on exactly that corpus (digest),
 *     on MEASUREMENT_CORPORA, with today's shape set, over as many samples as
 *     that corpus holds; and every base sample is still in the corpus (the base
 *     is a sub-multiset of the head). added = head minus base, as multisets.
 *  3. Rules are enumerated the way the measurement enumerates them (git's rule
 *     files, ruleIdOf) and split: UNCHANGED = E holds a usable record whose
 *     detection_fingerprint matches; everything else is measured in FULL. More
 *     than --max-full-rules of those is exit 4 rather than hours of running.
 *  4. Pass 1 runs the canonical counting path (runGate) over every rule on a
 *     temporary corpus holding exactly the added samples. Only its per-rule
 *     fields are used: it writes `corpus_digest` from its own module constant,
 *     not from the corpus it was handed, so that field is wrong by
 *     construction and is replaced.
 *  5. An attribution pass evaluates every rule on each added sample through
 *     src/corpus-event.ts matchedRuleIds and records which samples each rule
 *     fires on. Its per-rule totals must equal pass 1's; a disagreement is
 *     exit 5 and nothing is written.
 *  6. Pass 2 runs runGate for the FULL rules over the whole head corpus.
 *  7. The file is pass 1's document with the merged rules (unchanged: E count
 *     plus the delta; full: pass 2), the head sample count, and a corpus digest
 *     computed here over the head tree.
 *
 * WHAT IT TRUSTS
 *
 * E's per-rule counts. They are extended, not re-verified: a hand-edited
 * fp_count is carried forward, and catching that is the job of the scheduled
 * full re-measure in .github/workflows/action-eligibility.yml. In the harvest
 * workflow the base is main, whose evidence went through review.
 *
 * Usage:
 *   remeasure-benign-fp.ts --emit-measurement <path> [--base-ref <ref>]
 *                          [--report <path>] [--max-full-rules <n>]
 *
 * Exit codes:
 *   0  evidence (and report) written
 *   1  unexpected runtime error; nothing written
 *   2  usage error, including a --base-ref that does not resolve
 *   4  full measurement required: the base evidence cannot be extended; nothing written
 *   5  two independent counts of the same thing disagree; nothing written
 */
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import { detectionFingerprint, MEASUREMENT_CORPORA } from "../src/quality/action-eligibility.js";
import { matchedRuleIds } from "./lib/corpus-event.js";
import { loadCorpusTexts, type CorpusRecord } from "./lib/benign-corpus.js";
import { gitRuleFiles, ruleIdOf, runGate, scopedRulesDir } from "./gate-promotion-fp.js";
import {
  ATTRIBUTION_SCHEMA,
  EXCERPT_CHARS,
  sanitizeInline,
  type AttributedRule,
  type AttributionReport,
  type FullMeasurement,
} from "./lib/fp-attribution.js";
import {
  EVIDENCE_PATH,
  FullMeasurementRequired,
  Inconsistent,
  RemeasureUsageError,
  addedSamples,
  countTexts,
  currentShapes,
  digestOf,
  gitIn,
  isCount,
  isObj,
  loadBase,
  newRecordsByText,
  readCorpus,
  sameList,
  sameMultiset,
  type Base,
  type BaseEvidence,
} from "./lib/remeasure-base.js";
import { parseFlagPairs } from "./lib/strict-flags.js";

export { EVIDENCE_PATH, RemeasureUsageError };

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const DEFAULT_MAX_FULL_RULES = 200;

export const EXIT_OK = 0;
export const EXIT_FAIL = 1;
export const EXIT_USAGE = 2;
export const EXIT_FULL_MEASUREMENT_REQUIRED = 4;
export const EXIT_INCONSISTENT = 5;

/** writeMeasurement's format, in its key order. A change to it must fail here, loudly. */
const TOP_KEYS = ["_comment", "generated_at", "commit", "corpora", "corpus_digest", "shapes", "sample_count", "rules"];
const RULE_KEYS = ["fp_count", "maturity", "detection_fingerprint", "partial_measurement", "skill_path_unmeasured"];

export interface RemeasureOptions {
  readonly baseRef: string;
  readonly emitMeasurement: string;
  readonly report: string | null;
  readonly maxFullRules: number;
}

export type RuleMatcher = (engine: ATREngine, text: string) => ReadonlySet<string>;

/**
 * What the script reads. Injected so tests can point it at a fixture
 * repository; not reachable from the CLI or the environment.
 */
export interface RemeasureDeps {
  /** The head tree: rules, corpora and the git repository the base ref lives in. */
  readonly repoRoot: string;
  /** Repo-relative paths of every rule file the measurement may scan. */
  readonly listRuleFiles: () => readonly string[];
  /** The attribution pass's matcher. Injectable so the cross-check can be shown to bite. */
  readonly matchedRuleIds: RuleMatcher;
}

export function defaultRemeasureDeps(repoRoot: string = REPO_ROOT): RemeasureDeps {
  return { repoRoot, listRuleFiles: () => gitRuleFiles(repoRoot), matchedRuleIds };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const FLAGS: ReadonlySet<string> = new Set(["--base-ref", "--emit-measurement", "--report", "--max-full-rules"]);

export function parseRemeasureArgs(argv: readonly string[]): RemeasureOptions {
  const values = parseFlagPairs(argv, FLAGS, (m) => new RemeasureUsageError(m));
  const emitMeasurement = values.get("--emit-measurement");
  if (emitMeasurement === undefined) throw new RemeasureUsageError("--emit-measurement is required");
  const baseRef = values.get("--base-ref") ?? "HEAD";
  // The ref reaches git as an argument; one that starts with "-" would be read as an option.
  if (baseRef.startsWith("-") || /[\s\u0000-\u001f]/.test(baseRef)) {
    throw new RemeasureUsageError(`--base-ref must name a commit, not ${JSON.stringify(baseRef)}`);
  }
  const limit = values.get("--max-full-rules") ?? String(DEFAULT_MAX_FULL_RULES);
  if (!/^\d+$/.test(limit)) throw new RemeasureUsageError(`--max-full-rules must be a whole number, not ${limit}`);
  const report = values.get("--report") ?? null;
  if (report !== null && resolve(report) === resolve(emitMeasurement)) {
    throw new RemeasureUsageError("--report and --emit-measurement must be different paths");
  }
  return { baseRef, emitMeasurement, report, maxFullRules: Number(limit) };
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

const STARTED = Date.now();
/** Stamped with seconds since start, so a CI log shows where the time went. */
const log = (message: string): void =>
  console.log(`[remeasure +${Math.round((Date.now() - STARTED) / 1000)}s] ${message}`);

const sum = (xs: Iterable<number>): number => [...xs].reduce((a, b) => a + b, 0);

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

interface Rules {
  /** Every rule id, as the measurement's own --ids resolution finds them. */
  readonly ids: readonly string[];
  /** The engine runGate would build for all of them, for fingerprints and attribution. */
  readonly engine: ATREngine;
  readonly prints: ReadonlyMap<string, string>;
}

async function loadRules(deps: RemeasureDeps): Promise<Rules> {
  // Exactly the files runGate's --ids resolution scans when asked for every id: those with an id line.
  const withIds = deps.listRuleFiles().map((f): [string, string | null] => [f, ruleIdOf(deps.repoRoot, f)]);
  const files = withIds.filter(([, id]) => id !== null).map(([f]) => f);
  const ids = [...new Set(withIds.flatMap(([, id]) => (id === null ? [] : [id])))].sort((a, b) => a.localeCompare(b));
  if (ids.length === 0) throw new Error(`found no rule ids under ${deps.repoRoot}/rules; refusing to write evidence for no rules`);
  const dir = scopedRulesDir(deps.repoRoot, files);
  try {
    const engine = new ATREngine({ rulesDir: dir });
    await engine.loadRules();
    const prints = new Map(engine.getRules().map((r): [string, string] => [r.id, detectionFingerprint(r)]));
    const unloaded = ids.filter((id) => !prints.has(id));
    if (unloaded.length > 0) {
      log(`WARNING: the engine loaded no rule for ${unloaded.join(", ")}; a full measurement records them as 0 FP too`);
    }
    return { ids, engine, prints };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

interface Split {
  readonly unchanged: ReadonlySet<string>;
  readonly full: readonly FullMeasurement[];
}

function splitRules(rules: Rules, evidence: BaseEvidence): Split {
  const unchanged = new Set<string>();
  const full: FullMeasurement[] = [];
  for (const id of rules.ids) {
    const rec = evidence.rules.get(id);
    const print = rules.prints.get(id);
    if (rec === undefined) full.push({ id, reason: "absent-from-base-evidence" });
    else if (print === undefined) full.push({ id, reason: "not-loadable" });
    else if (!isCount(rec.fp_count) || typeof rec.detection_fingerprint !== "string") {
      full.push({ id, reason: "unusable-base-record" });
    } else if (rec.detection_fingerprint !== print) full.push({ id, reason: "detection-changed" });
    else unchanged.add(id);
  }
  return { unchanged, full };
}

// ---------------------------------------------------------------------------
// Measuring
// ---------------------------------------------------------------------------

/**
 * Write `texts` as a corpus the measurement loaders read back as exactly
 * `texts`. Non-empty texts go to one .jsonl (JSON keeps newlines, CRs and
 * lone surrogates intact); an empty text can only be an empty .md file, since
 * the .jsonl loader skips empty text. The round trip is checked, not assumed.
 */
export function writeAddedCorpus(dir: string, texts: readonly string[]): void {
  mkdirSync(dir, { recursive: true });
  const lines = texts.filter((t) => t.length > 0).map((t) => JSON.stringify({ text: t }));
  writeFileSync(join(dir, "added.jsonl"), lines.length === 0 ? "" : `${lines.join("\n")}\n`, "utf-8");
  texts
    .filter((t) => t.length === 0)
    .forEach((_, i) => writeFileSync(join(dir, `empty-${String(i).padStart(6, "0")}.md`), ""));
  const back = loadCorpusTexts(dir);
  if (!sameMultiset(back, texts)) {
    throw new Inconsistent(`the added samples do not read back from their corpus (${texts.length} written, ${back.length} read)`);
  }
}

interface RuleRecord {
  readonly fp_count: number;
  readonly maturity: string | null;
  readonly detection_fingerprint: string | null;
  readonly partial_measurement: boolean;
  readonly skill_path_unmeasured: boolean;
}

interface Emitted {
  readonly doc: Readonly<Record<string, unknown>>;
  readonly sampleCount: number;
  readonly rules: ReadonlyMap<string, RuleRecord>;
}

function asRuleRecord(id: string, v: unknown): RuleRecord {
  const ok =
    isObj(v) &&
    sameList(Object.keys(v), RULE_KEYS) &&
    isCount(v.fp_count) &&
    (v.maturity === null || typeof v.maturity === "string") &&
    (v.detection_fingerprint === null || typeof v.detection_fingerprint === "string") &&
    typeof v.partial_measurement === "boolean" &&
    typeof v.skill_path_unmeasured === "boolean";
  if (!ok) throw new Inconsistent(`gate-promotion-fp.ts wrote ${id} in a format this script does not know`);
  return v as unknown as RuleRecord;
}

/** Read what runGate emitted, refusing any drift from the format this script reproduces. */
function readEmitted(path: string, ids: readonly string[]): Emitted {
  const doc = JSON.parse(readFileSync(path, "utf-8")) as unknown;
  if (!isObj(doc) || !sameList(Object.keys(doc), TOP_KEYS) || !isObj(doc.rules) || !isCount(doc.sample_count)) {
    throw new Inconsistent("gate-promotion-fp.ts wrote a measurement in a format this script does not know; update it");
  }
  const corpora = Array.isArray(doc.corpora) ? doc.corpora : [];
  const shapes = Array.isArray(doc.shapes) ? doc.shapes : [];
  if (!sameList(corpora, MEASUREMENT_CORPORA) || !sameList(shapes, currentShapes())) {
    throw new Inconsistent("gate-promotion-fp.ts records corpora or shapes this script does not check against");
  }
  if (!sameList(Object.keys(doc.rules), [...ids].sort((a, b) => a.localeCompare(b)))) {
    throw new Inconsistent("gate-promotion-fp.ts measured a different set of rules than it was asked to");
  }
  const rules = new Map(Object.entries(doc.rules).map(([id, v]) => [id, asRuleRecord(id, v)]));
  return { doc, sampleCount: doc.sample_count, rules };
}

/** The canonical counting path: runGate in filter mode, exactly as a full measurement runs it. */
async function canonicalPass(
  label: string,
  ids: readonly string[],
  corpora: readonly string[],
  deps: RemeasureDeps,
  tmp: string,
): Promise<Emitted> {
  const idsFile = join(tmp, `${label}-ids.txt`);
  const out = join(tmp, `${label}-measurement.json`);
  writeFileSync(idsFile, `${ids.join("\n")}\n`, "utf-8");
  const code = await runGate(
    {
      idsFile,
      base: "origin/main",
      emitClean: null,
      emitDirty: join(tmp, `${label}-dirty.txt`),
      emitMeasurement: out,
      filterMode: true,
    },
    { repoRoot: deps.repoRoot, rulesDir: join(deps.repoRoot, "rules"), corpora, listRuleFiles: deps.listRuleFiles },
  );
  if (code !== 0) throw new Error(`the ${label} measurement (gate-promotion-fp.ts runGate) exited ${code}`);
  return readEmitted(out, ids);
}

/** rule id -> (added text -> how many added samples carry it), for every rule that fires on one. */
function attribute(
  engine: ATREngine,
  added: readonly string[],
  match: RuleMatcher,
): ReadonlyMap<string, ReadonlyMap<string, number>> {
  const byRule = new Map<string, Map<string, number>>();
  for (const [text, n] of countTexts(added)) {
    for (const id of match(engine, text)) {
      const hits = byRule.get(id) ?? new Map<string, number>();
      hits.set(text, n);
      byRule.set(id, hits);
    }
  }
  return byRule;
}

function crossCheck(
  rules: Rules,
  pass1: Emitted,
  attribution: ReadonlyMap<string, ReadonlyMap<string, number>>,
  addedCount: number,
): void {
  const problems: string[] = [];
  if (pass1.sampleCount !== addedCount) {
    problems.push(`pass 1 read ${pass1.sampleCount} added samples; ${addedCount} were written`);
  }
  const known = new Set(rules.ids);
  for (const id of rules.ids) {
    const canonical = pass1.rules.get(id);
    const attributed = sum(attribution.get(id)?.values() ?? []);
    if (canonical?.fp_count !== attributed) {
      problems.push(`${id}: pass 1 counted ${String(canonical?.fp_count)}, the attribution pass ${attributed}`);
    }
    if ((canonical?.detection_fingerprint ?? null) !== (rules.prints.get(id) ?? null)) {
      problems.push(`${id}: pass 1 recorded another detection fingerprint than the one the split used`);
    }
  }
  for (const id of attribution.keys()) {
    if (!known.has(id)) problems.push(`${id}: matched by the attribution pass but not a measured rule`);
  }
  if (problems.length > 0) {
    throw new Inconsistent(`the attribution pass disagrees with the canonical count:\n  ${problems.slice(0, 20).join("\n  ")}`);
  }
}

// ---------------------------------------------------------------------------
// Assembling
// ---------------------------------------------------------------------------

function mergeRules(
  ids: readonly string[],
  split: Split,
  evidence: BaseEvidence,
  pass1: Emitted,
  pass2: Emitted | null,
): Readonly<Record<string, RuleRecord>> {
  const sorted = [...ids].sort((a, b) => a.localeCompare(b));
  return Object.fromEntries(
    sorted.map((id): [string, RuleRecord] => {
      const delta = split.unchanged.has(id);
      const now = delta ? pass1.rules.get(id) : pass2?.rules.get(id);
      if (now === undefined) throw new Inconsistent(`${id} has no measurement`);
      const committed = delta ? (evidence.rules.get(id)?.fp_count as number) : 0;
      return [
        id,
        {
          fp_count: delta ? committed + now.fp_count : now.fp_count,
          maturity: now.maturity,
          detection_fingerprint: now.detection_fingerprint,
          partial_measurement: now.partial_measurement,
          skill_path_unmeasured: now.skill_path_unmeasured,
        },
      ];
    }),
  );
}

function buildReport(
  options: RemeasureOptions,
  base: Base,
  context: { readonly added: readonly string[]; readonly split: Split; readonly rules: Readonly<Record<string, RuleRecord>> },
  attribution: ReadonlyMap<string, ReadonlyMap<string, number>>,
  provenance: ReadonlyMap<string, readonly CorpusRecord[]>,
): AttributionReport {
  const attributed = Object.keys(context.rules)
    .filter((id) => attribution.has(id))
    .map((id): AttributedRule => {
      const hits = attribution.get(id) ?? new Map<string, number>();
      const before = base.evidence.rules.get(id)?.fp_count;
      return {
        id,
        measured: context.split.unchanged.has(id) ? "delta" : "full",
        fp_count_before: isCount(before) ? before : null,
        fp_count_after: context.rules[id]?.fp_count ?? 0,
        added_matches: sum(hits.values()),
        samples: [...hits].map(([text, occurrences]) => ({
          excerpt: sanitizeInline(text, EXCERPT_CHARS),
          occurrences,
          locations: (provenance.get(text) ?? []).map((r) => ({
            file: r.file,
            line: r.line,
            source: r.source,
            source_id: r.sourceId,
          })),
        })),
      };
    });
  return {
    schema: ATTRIBUTION_SCHEMA,
    base_ref: options.baseRef,
    base_commit: base.commit,
    base_sample_count: base.evidence.sampleCount,
    added_sample_count: context.added.length,
    head_sample_count: base.evidence.sampleCount + context.added.length,
    rules_total: Object.keys(context.rules).length,
    measured_on_added_only: context.split.unchanged.size,
    measured_in_full: context.split.full,
    rules: attributed,
  };
}

interface Result {
  readonly evidence: string;
  readonly report: AttributionReport;
}

async function remeasure(options: RemeasureOptions, deps: RemeasureDeps, tmp: string): Promise<Result> {
  const base = loadBase(gitIn(deps.repoRoot), options.baseRef, join(tmp, "base"));
  const headDigest = digestOf(deps.repoRoot);
  const head = readCorpus(deps.repoRoot, "head");
  const added = addedSamples(head, base.corpus);
  const rules = await loadRules(deps);
  const split = splitRules(rules, base.evidence);
  log(
    `base ${options.baseRef} (${base.commit.slice(0, 12)}): ${base.evidence.sampleCount} samples, ` +
      `${base.evidence.rules.size} rule records; head: ${head.texts.length} samples, ${added.length} added`,
  );
  log(`${rules.ids.length} rules: ${split.unchanged.size} on the added samples only, ${split.full.length} in full`);
  if (split.full.length > options.maxFullRules) {
    throw new FullMeasurementRequired(
      `${split.full.length} rules need a full measurement and --max-full-rules is ${options.maxFullRules}`,
    );
  }
  writeAddedCorpus(join(tmp, "added"), added);
  log(`pass 1/2: ${rules.ids.length} rules x ${added.length} added samples`);
  const pass1 = await canonicalPass("added", rules.ids, [join(tmp, "added")], deps, tmp);
  const attribution = attribute(rules.engine, added, deps.matchedRuleIds);
  crossCheck(rules, pass1, attribution, added.length);
  log(`attribution pass agrees with pass 1: ${attribution.size} rules fire on the added samples`);
  const full = split.full.map((f) => f.id);
  log(`pass 2/2: ${full.length} rules x ${head.texts.length} samples`);
  const corpora = MEASUREMENT_CORPORA.map((c) => join(deps.repoRoot, c));
  const pass2 = full.length === 0 ? null : await canonicalPass("full", full, corpora, deps, tmp);
  const sampleCount = base.evidence.sampleCount + added.length;
  if (pass2 !== null && pass2.sampleCount !== sampleCount) {
    throw new Inconsistent(`pass 2 read ${pass2.sampleCount} samples; base plus added is ${sampleCount}`);
  }
  if (digestOf(deps.repoRoot) !== headDigest) throw new Inconsistent("the corpus changed while it was being measured");
  const merged = mergeRules(rules.ids, split, base.evidence, pass1, pass2);
  const doc = { ...pass1.doc, corpus_digest: headDigest, sample_count: sampleCount, rules: merged };
  const report = buildReport(options, base, { added, split, rules: merged }, attribution, newRecordsByText(head, base.corpus));
  return { evidence: `${JSON.stringify(doc, null, 2)}\n`, report };
}

function writeAtomically(path: string, content: string): void {
  const target = resolve(path);
  mkdirSync(dirname(target), { recursive: true });
  const staging = `${target}.tmp-${process.pid}`;
  writeFileSync(staging, content, "utf-8");
  renameSync(staging, target);
}

function reportFailure(e: unknown): number {
  if (e instanceof RemeasureUsageError) {
    console.error(`[remeasure] usage error: ${e.message}`);
    return EXIT_USAGE;
  }
  if (e instanceof FullMeasurementRequired) {
    console.error(
      `[remeasure] FULL MEASUREMENT REQUIRED — ${e.message}.\n` +
        `The delta only extends evidence that describes its base exactly. Nothing was written.\n` +
        `Regenerate ${EVIDENCE_PATH} on main with a full measurement (scripts/gate-promotion-fp.ts\n` +
        `--ids <every rule id> --filter-mode --emit-dirty <path> --emit-measurement ${EVIDENCE_PATH}).\n` +
        `If only --max-full-rules was exceeded, running this script on an up-to-date main, with no new\n` +
        `samples and a higher --max-full-rules, re-measures just those rules.`,
    );
    return EXIT_FULL_MEASUREMENT_REQUIRED;
  }
  if (e instanceof Inconsistent) {
    console.error(`[remeasure] INCONSISTENT — ${e.message}\nNothing was written.`);
    return EXIT_INCONSISTENT;
  }
  console.error(`[remeasure] FAIL — ${e instanceof Error ? (e.stack ?? e.message) : String(e)}\nNothing was written.`);
  return EXIT_FAIL;
}

export async function runRemeasure(
  options: RemeasureOptions,
  deps: RemeasureDeps = defaultRemeasureDeps(),
): Promise<number> {
  const tmp = mkdtempSync(join(tmpdir(), "atr-remeasure-"));
  try {
    const { evidence, report } = await remeasure(options, deps, tmp);
    if (options.report !== null) writeAtomically(options.report, `${JSON.stringify(report, null, 2)}\n`);
    writeAtomically(options.emitMeasurement, evidence);
    log(
      `wrote ${options.emitMeasurement}: ${report.rules_total} rules over ${report.head_sample_count} samples; ` +
        `${report.rules.length} rules fire on the ${report.added_sample_count} added samples`,
    );
    return EXIT_OK;
  } catch (e) {
    return reportFailure(e);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

export async function main(argv: readonly string[], deps?: RemeasureDeps): Promise<number> {
  let options: RemeasureOptions;
  try {
    options = parseRemeasureArgs(argv);
  } catch (e) {
    return reportFailure(e);
  }
  return runRemeasure(options, deps);
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

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
