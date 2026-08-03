/**
 * rule-latency-profile.ts -- measuring what one rule costs, in a form that does
 * not depend on how fast the machine is.
 *
 * This module only MEASURES. Every threshold, comparison and verdict lives in
 * scripts/gate-rule-latency.ts, which consumes a Profile. The split is the
 * boundary the numbers care about: a Profile is raw milliseconds and is
 * meaningless on its own, because milliseconds on a GitHub runner vary by 2.7x
 * for identical work. Only the ratio between two costs in the SAME Profile is a
 * fact about the rules.
 *
 * PROFILING PROCEDURE, AND WHY EACH STEP IS THERE
 *   1. Load the rules the engine would actually evaluate (isEvaluable mirrors
 *      src/engine.ts evaluateRaw). Profiling a rule the engine skips would put a
 *      number in the baseline that describes nothing.
 *   2. Build the corpus events once, exactly as eval-harness.ts sampleToEvent
 *      does, so the profile describes the same work the eval harness reports.
 *   3. Give each rule an engine of its own holding only that rule.
 *   4. WARM IT (see WARMUP_MS / WARMUP_PASSES_MIN). Skipping this produces a
 *      bimodal measurement with 2-4x spread and nothing else in the design can
 *      recover from that.
 *   5. Size the timing window from a WARM pass, never the cold probe (see
 *      calibrate()).
 *   6. Time REPS windows of >= WINDOW_MS each and keep the MINIMUM.
 *   7. Do all of that PROFILE_PASSES times over the whole corpus and keep the
 *      per-rule minimum across passes (see PROFILE_PASSES).
 *
 * KNOWN GAP (deliberate, bounded, and now reported on every run)
 *   The engine filters rules by agent_source.type against the event type, so a
 *   rule whose source type the eval corpus never produces has its regexes
 *   skipped and profiles at roughly the cost of the dispatch loop alone. This is
 *   not theoretical: the same `(?:[a-z]+\s*){0,6}` regex that ranks 1st when
 *   declared llm_io ranks 670th of 671 when declared agent_trace, because the
 *   corpus carries no trace payload and the engine never runs it.
 *
 *   Those rules are therefore excluded from the profile's judgeable set and
 *   listed in `unprofilableRuleIds`, which the gate prints every run rather than
 *   letting the hole sit silently in a comment. Closing it means widening the
 *   eval corpus (src/eval/corpus.ts), not widening this gate.
 *
 * @module scripts/lib/rule-latency-profile
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../../src/engine.js";
import { loadRuleFile } from "../../src/loader.js";
import { laneAllows } from "../../src/quality/rule-contract.js";
import { EVAL_CORPUS } from "../../src/eval/corpus.js";
import { runEval } from "../../src/eval/eval-harness.js";
import type { AgentEvent, ATRRule } from "../../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The corpus this gate profiles against. */
export const RULES_DIR = join(REPO_ROOT, "rules");

/**
 * ATR source types the eval corpus can actually exercise.
 *
 * Derived from EVENT_TYPE_TO_SOURCE in src/engine.ts applied to the event types
 * present in src/eval/corpus.ts (llm_input, llm_output, tool_call,
 * tool_response, multi_agent_message). A rule declaring anything else has its
 * conditions skipped by the engine on every corpus sample, so its measured cost
 * describes the dispatch loop and nothing about its regexes.
 */
export const CORPUS_SOURCE_TYPES: ReadonlySet<string> = new Set([
  "llm_io",
  "tool_call",
  "mcp_exchange",
  "multi_agent_comm",
]);

// ---------------------------------------------------------------------------
// Measurement parameters
// ---------------------------------------------------------------------------

/**
 * Warm each rule for at least this many milliseconds before measuring.
 *
 * NOT optional. V8 interprets a RegExp until roughly a thousand executions, then
 * tiers it up to native code. One corpus pass is 341 executions, so an unwarmed
 * measurement lands on either side of that transition at random: a rule was
 * observed at 4.1x in one clean profile and 10.1x in the next, purely from this.
 */
const WARMUP_MS = 6;

/**
 * ...and for at least this many corpus passes, whatever the clock says.
 *
 * A time-only warmup has a failure mode that shows up exactly where it hurts.
 * The pass count is derived from a single unwarmed probe, so on a busy machine
 * the probe reads slow and the rule gets FEWER warmup passes -- while the
 * tier-up threshold, being a count of executions, has not moved. The expensive
 * rules get the fewest passes of all, because they are what makes the probe slow.
 *
 * Observed directly: ATR-2026-00245 measured 7.3x, 7.7x and 7.7x across three
 * quiet profiles and 16.1x on a contended one, a 2.1x drift on a rule that had
 * not changed at all. With this floor in place the same rule read 7.7x quiet and
 * 9.0x under a machine 1.74x slower. 16 passes is >= 5000 regex executions even
 * after event-type filtering discards most of the corpus for a given rule,
 * comfortably past the ~1000 transition, and costs about 2s across a whole run.
 */
const WARMUP_PASSES_MIN = 16;

/** Each timed window must span at least this long, to swamp timer resolution. */
const WINDOW_MS = 2;

/** Passes averaged after warmup to size the timing window. See calibrate(). */
const CALIBRATION_PASSES = 3;

/** Timed windows per rule; the minimum is kept (see profileRule). */
const REPS = 5;

/**
 * Independent full sweeps of the rule corpus; the per-rule MINIMUM is kept.
 *
 * One sweep is not enough, and the reason is structural rather than statistical.
 * Repeating a measurement 15 times inside one process moved a rule's relative
 * cost by only 1.09-1.15x, while the SAME rule measured in separate processes
 * moved up to 2.10x. So the variance does not live in the timing loop, where
 * more REPS would find it; it lives in whatever state the process starts in --
 * heap layout, the machine's mood during the cold probe, which optimisation
 * tier the shared RegExp machinery happens to be in. Two sweeps sample that
 * outer distribution twice, and the minimum discards the unlucky draw, exactly
 * as taking the minimum of REPS windows discards a descheduled window.
 *
 * With this and calibrate() in place, four profiles of an unchanged corpus --
 * two quiet, two run concurrently on a machine carrying 10 CPU hogs and 1.68x
 * slower for it -- spread per-rule by p50 1.122, p90 1.281, max 1.776, against
 * the 2.10x that single-sweep profiling produced under lighter load.
 *
 * Two, not more: the second sweep costs ~18s and removes most of the exposure
 * (a bad draw must now hit the same rule twice); a third would cost as much
 * again for a much smaller share of what is left.
 */
const PROFILE_PASSES = 2;

/**
 * Full-engine eval passes behind the shape figure; the median is kept.
 *
 * The shape covers the large share of engine cost that per-rule profiling does
 * not explain, and it is both the value compared and (via --write-baseline) the
 * value recorded, so one disturbed reading would distort the band for every
 * later run. Observed directly while a sibling process saturated this machine:
 * 2.254, against a quiet range of 1.919..1.986. Three passes and a median cost a
 * few seconds and remove the single-sample exposure.
 */
const SHAPE_REPS = 3;

// ---------------------------------------------------------------------------
// The measurement artifact
// ---------------------------------------------------------------------------

export interface RuleCost {
  /** Milliseconds for this rule alone to evaluate the entire corpus. */
  readonly ms: number;
  /** Repo-relative path, so a failure message points at a file to open. */
  readonly file: string;
}

export interface Profile {
  readonly generatedAt: string;
  /** Rules actually profiled and judgeable (evaluable AND corpus-covered). */
  readonly rules: number;
  /** Corpus samples each rule was run over. */
  readonly samples: number;
  /** Median of costs. Human-readable only -- never compared. */
  readonly medianRuleMs: number;
  /** Rules the engine would skip, so a later un-skip cannot inherit a pass. */
  readonly skippedRuleIds: readonly string[];
  /**
   * Rules the engine WOULD evaluate but this corpus cannot exercise, because it
   * emits no event of their agent_source.type. Excluded from costs: a number
   * measured there describes the dispatch loop, and letting it into the median
   * would drag the denominator toward zero.
   */
  readonly unprofilableRuleIds: readonly string[];
  /** Rule files that failed to parse. Non-zero means the profile is partial. */
  readonly unparsedFiles: number;
  /**
   * Uncommitted paths under rules/ at profiling time. Expected and harmless in a
   * rule-authoring PR; on a CI checkout it means something wrote into the tree
   * mid-run, which puts rules in the profile that are in no commit.
   */
  readonly dirtyRulePaths: readonly string[];
  readonly costs: Readonly<Record<string, RuleCost>>;
  /** Engine-wide p95/p50, median of SHAPE_REPS full eval passes. */
  readonly latencyShape: number;
  readonly latencyP50Ms: number;
  readonly latencyP95Ms: number;
}

/** Median of a numeric list. Even lengths average the two central values. */
export function median(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

/**
 * Median over every profiled rule. Used only when writing a fresh baseline,
 * where the anchor cohort is by definition the whole profile; a gating run uses
 * anchorMedianMs() in gate-rule-latency.ts instead, whose membership is pinned.
 *
 * Recomputed from the costs rather than read from profile.medianRuleMs. The
 * stored field is a by-product for humans; deriving the divisor here means a
 * hand-edited profile cannot make every rule look cheap by editing one number.
 */
export function profileMedianMs(profile: Profile): number {
  return median(Object.values(profile.costs).map((c) => c.ms));
}

export function parseProfile(doc: unknown, source: string): Profile {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error(`${source}: profile must be a JSON object`);
  }
  const partial = doc as Partial<Profile>;
  if (partial.costs === null || typeof partial.costs !== "object" || Array.isArray(partial.costs)) {
    throw new Error(`${source}: "costs" must be an object of ruleId -> {ms,file}`);
  }
  if (typeof partial.samples !== "number" || typeof partial.latencyShape !== "number") {
    throw new Error(`${source}: not a latency profile (expected samples + latencyShape). Produce it with --write-profile`);
  }
  return {
    skippedRuleIds: [],
    unprofilableRuleIds: [],
    unparsedFiles: 0,
    dirtyRulePaths: [],
    ...partial,
  } as Profile;
}

// ---------------------------------------------------------------------------
// Rule discovery
// ---------------------------------------------------------------------------

interface DiscoveredRule {
  readonly rule: ATRRule;
  readonly file: string;
}

interface Discovery {
  readonly rules: readonly DiscoveredRule[];
  readonly unparsedFiles: number;
}

/**
 * Walk the rules tree keeping the file path alongside each rule, which
 * loadRulesFromDirectory() drops. A failure message without a path costs the
 * reader a grep.
 *
 * Parse failures are counted rather than swallowed. The schema validator owns
 * that failure and this gate must not duplicate it, but a rule that stops
 * parsing also silently stops being profiled -- so the count is carried into the
 * Profile and printed, where a jump in it is visible.
 */
function discoverRules(dir: string): Discovery {
  const found: DiscoveredRule[] = [];
  let unparsedFiles = 0;
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      const nested = discoverRules(full);
      found.push(...nested.rules);
      unparsedFiles += nested.unparsedFiles;
      continue;
    }
    if (extname(entry) !== ".yaml" && extname(entry) !== ".yml") continue;
    try {
      found.push({ rule: loadRuleFile(full), file: relative(REPO_ROOT, full) });
    } catch {
      unparsedFiles += 1;
    }
  }
  return { rules: found, unparsedFiles };
}

/**
 * Mirror of the engine's own skip logic (src/engine.ts evaluateRaw): draft and
 * deprecated rules never fire, and the eval harness runs the default 'hunt' lane.
 */
export function isEvaluable(rule: ATRRule): boolean {
  if (rule.status === "deprecated" || rule.status === "draft") return false;
  return laneAllows(rule.maturity, "hunt");
}

/**
 * Can this corpus say anything about this rule's regexes?
 *
 * Only if the corpus emits an event whose source type the rule accepts. A
 * `trace` rule needs event.trace, which sampleToEvent never sets, so those are
 * out as well regardless of how their agent_source.type reads.
 */
export function isCorpusCovered(rule: ATRRule): boolean {
  if (rule.detection?.method === "trace") return false;
  return CORPUS_SOURCE_TYPES.has(rule.agent_source?.type ?? "");
}

/**
 * Uncommitted paths under rules/, or [] outside a git checkout.
 *
 * Not a verdict, an annotation. A concurrent process writing a rule file into
 * the tree mid-profile really happened during development: one profile contained
 * ATR-2026-99668 at 0.92ms and the eight around it did not, and the file exists
 * in no commit. On a CI checkout this list is empty; when it is not, the run's
 * membership deserves a second look before anyone acts on a failure.
 */
function dirtyRulePaths(dir: string): readonly string[] {
  try {
    const result = spawnSync("git", ["status", "--porcelain", "--", dir], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 20_000,
    });
    if (result.status !== 0 || typeof result.stdout !== "string") return [];
    return result.stdout
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

/**
 * Identical to eval-harness.ts sampleToEvent. Built once and reused across every
 * rule and iteration so the measurement is regex work, not object allocation.
 */
function corpusEvents(): readonly AgentEvent[] {
  const timestamp = new Date().toISOString();
  return EVAL_CORPUS.map((sample) => ({
    type: sample.eventType,
    content: sample.text,
    timestamp,
    fields: sample.fields,
  }));
}

/**
 * An engine holding exactly one rule.
 *
 * The empty directory is load-bearing. ATREngine.loadRules() appends
 * config.rules to whatever rulesDir yields, and when rulesDir is absent it falls
 * back to findBundledRulesDir(), which locates the repo's own rules/. Omitting
 * rulesDir here would silently profile all 768 rules once per rule.
 */
async function singleRuleEngine(rule: ATRRule, emptyDir: string): Promise<ATREngine> {
  const engine = new ATREngine({ rules: [rule], rulesDir: emptyDir });
  const count = await engine.loadRules();
  if (count !== 1) throw new Error(`expected a 1-rule engine for ${rule.id}, loaded ${count}`);
  return engine;
}

function passOnce(engine: ATREngine, events: readonly AgentEvent[]): void {
  for (const event of events) {
    try {
      engine.evaluate(event);
    } catch {
      // evaluateSampleRegex() swallows engine errors too; a throwing rule must
      // not abort the profile, and its cost is still the cost the engine pays.
    }
  }
}

/**
 * Milliseconds per pass, averaged over CALIBRATION_PASSES WARM passes.
 *
 * This exists because sizing the timing window from the COLD probe was a real
 * defect. iters = ceil(WINDOW_MS / probe) means a probe that read slow -- which
 * is exactly what happens when the machine stalls for a moment, and which
 * happens most to the expensive rules -- yields iters = 1, so the whole "window"
 * is a single pass and the measurement inherits every microsecond of that stall
 * undivided. The warmup floor fixed the tier-up half of the same bug; this is
 * the other half.
 */
function calibrate(engine: ATREngine, events: readonly AgentEvent[]): number {
  const start = performance.now();
  for (let i = 0; i < CALIBRATION_PASSES; i++) passOnce(engine, events);
  return Math.max((performance.now() - start) / CALIBRATION_PASSES, 1e-6);
}

/**
 * Cost of one rule over the whole corpus, in milliseconds per pass.
 *
 * Takes the MINIMUM of REPS windows rather than the mean. Scheduling and GC noise
 * is one-sided: it can only make a measurement slower than the work actually is,
 * never faster, so the minimum is the best available estimate of the true cost
 * and the mean is that estimate plus an arbitrary noise tax.
 */
function profileRule(engine: ATREngine, events: readonly AgentEvent[]): number {
  const probeStart = performance.now();
  passOnce(engine, events);
  const cold = Math.max(performance.now() - probeStart, 1e-6);

  const warmupPasses = Math.max(WARMUP_PASSES_MIN, Math.ceil(WARMUP_MS / cold));
  for (let i = 0; i < warmupPasses; i++) passOnce(engine, events);

  const warm = calibrate(engine, events);
  const iters = Math.max(1, Math.ceil(WINDOW_MS / warm));

  let best = Infinity;
  for (let rep = 0; rep < REPS; rep++) {
    const start = performance.now();
    for (let i = 0; i < iters; i++) passOnce(engine, events);
    best = Math.min(best, (performance.now() - start) / iters);
  }
  return best;
}

/**
 * Engine-wide p95/p50, as the median of SHAPE_REPS full eval passes.
 *
 * enableEmbedding is forced off. Whether @xenova/transformers resolves on a given
 * runner is a property of the runner, and letting it decide which code path the
 * shape describes would put exactly the machine-dependent term back into the
 * metric this gate exists to remove. It is not a small effect: with the embedding
 * module loaded the same corpus measured p50 14.3ms / p95 26.1ms locally, and
 * 7.7ms / 14.9ms without it.
 */
async function measureShape(rulesDir: string): Promise<{ shape: number; p50: number; p95: number }> {
  const runs: { shape: number; p50: number; p95: number }[] = [];
  for (let i = 0; i < SHAPE_REPS; i++) {
    const { report } = await runEval({ rulesDir, enableEmbedding: false });
    const { p50, p95 } = report.latency;
    if (p50 <= 0) throw new Error("engine eval reported a non-positive p50; cannot compute a latency shape");
    runs.push({ shape: p95 / p50, p50, p95 });
  }
  const mid = median(runs.map((r) => r.shape));
  // Keep the run whose shape IS the median, so the reported p50/p95 belong to one
  // real measurement rather than being averaged across passes.
  return runs.reduce((best, r) => (Math.abs(r.shape - mid) < Math.abs(best.shape - mid) ? r : best), runs[0]!);
}

/**
 * rulesDir is injectable so tests can profile a fixture corpus containing a
 * deliberately pathological regex and assert that the gate names it. Testing the
 * gate only against synthetic numbers would leave the measurement itself -- the
 * part that has to actually notice a backtracking regex -- unverified.
 */
export async function buildProfile(rulesDir: string = RULES_DIR): Promise<Profile> {
  const { rules: discovered, unparsedFiles } = discoverRules(rulesDir);
  if (discovered.length === 0) throw new Error(`no rules found under ${rulesDir}`);

  const evaluable = discovered.filter((d) => isEvaluable(d.rule));
  const skippedRuleIds = discovered.filter((d) => !isEvaluable(d.rule)).map((d) => d.rule.id).sort();
  if (evaluable.length === 0) throw new Error(`every rule under ${rulesDir} is draft/deprecated; nothing to profile`);

  const profilable = evaluable.filter((d) => isCorpusCovered(d.rule));
  const unprofilableRuleIds = evaluable.filter((d) => !isCorpusCovered(d.rule)).map((d) => d.rule.id).sort();
  if (profilable.length === 0) {
    throw new Error(`no rule under ${rulesDir} declares a source type the eval corpus emits; nothing to profile`);
  }

  const events = corpusEvents();
  const emptyDir = mkdtempSync(join(tmpdir(), "atr-latency-empty-"));

  const costs: Record<string, RuleCost> = {};
  for (let pass = 0; pass < PROFILE_PASSES; pass++) {
    for (const { rule, file } of profilable) {
      const engine = await singleRuleEngine(rule, emptyDir);
      const ms = profileRule(engine, events);
      const previous = costs[rule.id];
      costs[rule.id] = { ms: previous === undefined ? ms : Math.min(previous.ms, ms), file };
    }
  }

  const { shape, p50, p95 } = await measureShape(rulesDir);
  return {
    generatedAt: new Date().toISOString(),
    rules: profilable.length,
    samples: events.length,
    medianRuleMs: median(Object.values(costs).map((c) => c.ms)),
    skippedRuleIds,
    unprofilableRuleIds,
    unparsedFiles,
    dirtyRulePaths: dirtyRulePaths(rulesDir),
    costs,
    latencyShape: shape,
    latencyP50Ms: p50,
    latencyP95Ms: p95,
  };
}
