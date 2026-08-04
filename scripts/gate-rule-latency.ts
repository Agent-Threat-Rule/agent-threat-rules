/**
 * Per-rule regex cost ratchet -- CI gate over the whole ATR rule corpus.
 *
 * WHAT THIS REPLACES
 *   tests/eval-harness.test.ts used to assert `report.latency.p95 < 50` -- a
 *   wall-clock millisecond budget for the whole engine, measured on a shared
 *   GitHub runner. That threshold sat inside the runner's own noise band and
 *   failed builds that had changed nothing: PR #383 read 51.111ms while adding
 *   zero rules, #385 read 50.888ms, #389 read 50.400ms, and main's own
 *   2026-07-29 run was red. Across 14 real CI runs with an unchanged corpus,
 *   p50 varied by 2.708x and p95 by 2.716x. The assertion measured the runner.
 *
 * THE METRIC
 *   relCost(R) = cost(R) / median(cost over the ANCHOR COHORT)
 *
 *   cost(R) is the time one rule takes to evaluate the whole eval corpus. The
 *   anchor cohort is the set of rule IDs recorded in the baseline, measured in
 *   the same process, on the same machine, in the same profiling pass as R. So a
 *   runner k times slower scales numerator and denominator alike and the ratio
 *   does not move.
 *
 *   The cohort is named rather than computed for a reason that cost a rewrite to
 *   learn. Dividing by the median of ALL rules present in the run makes the
 *   denominator a function of who else is in the corpus. Measured against the
 *   real profile: adding 200 rules at the 14th percentile of cost -- an ordinary
 *   week of CVE-collector output -- moves the median 0.2095ms -> 0.1360ms and
 *   lifts EVERY rule's relCost by 1.540x with no rule having changed. The worst
 *   rule reads 29.1x before and 44.9x after. Stacked on measurement noise that
 *   reproduced a content-independent red run, which is precisely the disease
 *   being cured here. Pinning the cohort's membership in the baseline removes
 *   the term exactly: the same simulation against the anchor cohort lifts
 *   relCost by 1.0000x, because none of the 200 newcomers is in the denominator.
 *
 * WHY NOT THE TWO OBVIOUS ALTERNATIVES
 *   - An absolute baseline in milliseconds (`p95 <= baseline * 1.2`) just moves
 *     the problem: the baseline is itself a measurement on one runner, and the
 *     2.7x spread above walks straight through any sane tolerance.
 *   - p95 / ruleCount is not scale-free either. Engine cost per rule is not
 *     constant (dispatch and post-processing do not divide evenly), and the
 *     quantity it normalises -- corpus growth -- is expected behaviour rather
 *     than regression. Growing 768 -> 859 rules should cost more in total.
 *     What must not grow is what a single rule costs relative to its peers.
 *
 * WHY THE MEDIAN AND NOT THE MEAN
 *   The denominator is the thing an author would attack to hide a slow rule.
 *   A mean can be lifted by one catastrophic rule -- the culprit would
 *   manufacture its own alibi. A median has a 50% breakdown point: moving it
 *   requires making roughly half the cohort slower at once, which is not a
 *   quiet change.
 *
 * HOW MACHINE-INDEPENDENT IS IT, HONESTLY
 *   Not perfectly, and an earlier draft of this header overclaimed it as blind
 *   to machine speed "by construction". Runner slowness is not a clean scalar:
 *   contention reaches the expensive tail harder than the middle, so the ratio
 *   drifts under load rather than holding exactly. What it does not do is drift
 *   by the 2.7x that sank the absolute check.
 *
 *   Measured over four independent profiles of the same unchanged corpus -- two
 *   on a quiet machine, two running concurrently against each other on a machine
 *   also carrying 10 CPU hogs, which made it 1.68x slower by the denominator --
 *   per-rule relCost spread (max/min) was p50 1.122, p90 1.281, p99 1.456, max
 *   1.776. Restricted to the 22 rules at or above 5x, the ones that can actually
 *   fail: max 1.316. Every threshold in scripts/lib/rule-latency-thresholds.ts
 *   is sized against those figures, beside the measurement it came from.
 *
 *   ARCHITECTURE, though, is not noise, and it is bigger than expected. The same
 *   corpus profiled 30.9x for ATR-2026-00001 on arm64 macOS and 47.5x on the
 *   x64 ubuntu-latest runner -- a systematic 1.54x on the expensive tail, and a
 *   wider distribution overall (p95 4.23x local, 5.93x on CI). That is a real
 *   difference in relative regex cost between CPUs, not a timing artifact, and
 *   no tolerance should be asked to absorb it. So the committed baseline is
 *   generated FROM A CI PROFILE -- download the rule-latency-profile artifact
 *   and run --profile <artifact> --write-baseline -- never from a developer's
 *   machine. A local run is for finding your own regression, not for recording.
 *
 * WHAT FAILS THE BUILD
 *   - A rule absent from the baseline costs >= FAIL_FLOOR anchor medians. That
 *     is a newly authored expensive rule, or a previously cheap one made
 *     expensive.
 *   - A baselined rule is still >= FAIL_FLOOR AND has grown past its recorded
 *     value by more than TOLERANCE.
 *   - The engine-wide latency SHAPE (p95 / p50) rises past SHAPE_HIGH times the
 *     recorded value. The per-rule costs measured here sum to only ~4% of what
 *     the engine spends on the same corpus (291.7ms of 7321.9ms in one measured
 *     run) -- the rest is dispatch and post-processing that belongs to no single
 *     rule -- so this is a coarse net over the part per-rule profiling cannot see.
 *
 * WHOSE FAULT IT HAS TO BE (--changed-since)
 *   The corpus is judged as a whole, because rules land on main through doors
 *   that never open a pull request. But a pull request must not go red for a
 *   rule it did not touch -- that is the same content-independent failure this
 *   gate was built to remove, merely sourced from a neighbour instead of from a
 *   busy runner. It is not hypothetical: this gate's first CI run found
 *   ATR-2026-02300 at 288x, a rule merged in #321 with a variable-length
 *   lookbehind, and without scoping it would have reddened every unrelated
 *   rules PR from that moment on.
 *
 *   So on a pull request the gate takes --changed-since <baseRef> and only
 *   FAILS on rules whose files that diff touched. Everything else is printed
 *   under PRE-EXISTING and left to main's own run, which files an issue. If the
 *   diff touches anything that can change what every rule costs -- the engine,
 *   the eval corpus, the lane contract, the profiler, the lockfile -- then the
 *   whole corpus is in scope again, because such a change can make any rule
 *   expensive. A missing or unusable base ref widens the scope rather than
 *   narrowing it.
 *
 * WHAT DOES NOT FAIL THE BUILD
 *   - Any rule below FAIL_FLOOR, however it drifted. Relative measurement of
 *     cheap rules is inherently jittery -- V8 tiers a RegExp up to native code
 *     after roughly a thousand executions, and one corpus pass is only 341, so
 *     an un-warmed cheap rule reads bimodally. buildProfile() warms past that
 *     point, and this floor absorbs what warming does not.
 *   - A shape BELOW its band. Corpus growth pushes it down mechanically -- 670 ->
 *     1170 rules measured 1.93 -> 1.67 -- and growth is the expected behaviour
 *     this whole design refuses to call a regression. A low shape is reported,
 *     never fatal. See SHAPE_HIGH.
 *   - A rule that improved. Reported so the baseline can be tightened with
 *     --write-baseline, matching scripts/eval-generalization.ts --gate and
 *     scripts/gate-re2-portability.ts.
 *
 * WHAT THIS CATCHES THAT NOTHING ELSE DOES
 *   isReDoSSafe() in src/engine.ts deliberately permits a bounded outer
 *   quantifier wrapping an unbounded inner one -- its comment argues a finite
 *   bound caps backtracking at polynomial rather than exponential. True, and
 *   not a defence: the polynomial's degree is the bound. Measured here against
 *   one 61-character sample, `^(?:[a-z]+\s*){0,6}ZQXKFJ$` takes 175ms, `{0,8}`
 *   takes 9.8 SECONDS and `{0,10}` takes 76 seconds, and isReDoSSafe returns
 *   true for all three, so all three compile and load into the engine. That is
 *   a denial-of-service reachable from attacker-controlled input, and until
 *   this gate existed nothing in CI could see it: an absolute engine-wide p95
 *   cannot, because one rule out of 768 disappears into the noise of the sum.
 *   Relative per-rule cost ranks it 1st, by name, on the first run.
 *
 * WHAT IT STILL CANNOT SEE
 *   The same regex declared under a source type the eval corpus never emits.
 *   Measured: moved from llm_io to agent_trace it drops from 1st of 671 to
 *   670th, because the engine skips it on every sample. Six evaluable rules live
 *   there today (memory_access 2, context_window 2, skill_lifecycle 2). They are
 *   excluded from the metric rather than scored at a fictitious 0.1x, and any
 *   NEW arrival is printed as a warning on every run, so the hole is visible
 *   instead of merely documented. Closing it means widening src/eval/corpus.ts.
 *
 * WHERE THE MEASUREMENT LIVES
 *   scripts/lib/rule-latency-profile.ts. It produces a Profile and knows nothing
 *   about thresholds; this file holds every threshold and every verdict and
 *   knows nothing about timers. The seam matters: raw milliseconds are only
 *   meaningful next to other milliseconds from the same run, and keeping the
 *   two halves apart is what stops an absolute number leaking into a comparison.
 *
 * USAGE
 *   npx tsx scripts/gate-rule-latency.ts                       # profile + gate
 *   npx tsx scripts/gate-rule-latency.ts --profile p.json      # reuse a profile
 *   npx tsx scripts/gate-rule-latency.ts --write-profile p.json
 *   npx tsx scripts/gate-rule-latency.ts --write-baseline
 *   npx tsx scripts/gate-rule-latency.ts --profile ci.json --write-baseline
 *   npx tsx scripts/gate-rule-latency.ts --changed-since origin/main   # PR mode
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildProfile,
  median,
  parseProfile,
  profileMedianMs,
  RULES_DIR,
  type Profile,
} from "./lib/rule-latency-profile.js";
import {
  ANCHOR_MIN_COVERAGE,
  FAIL_FLOOR,
  RECORD_FLOOR,
  SHAPE_HIGH,
  SHAPE_REPORT_LOW,
  TOLERANCE,
} from "./lib/rule-latency-thresholds.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BASELINE_PATH = join(REPO_ROOT, "data/rule-latency-baseline.json");

// Re-exported so a consumer (and tests/gate-rule-latency.test.ts) has one entry
// point for the whole gate rather than having to know where measurement lives.
export {
  buildProfile,
  isCorpusCovered,
  isEvaluable,
  median,
  profileMedianMs,
  type Profile,
} from "./lib/rule-latency-profile.js";

// ---------------------------------------------------------------------------
// Thresholds
//
// Every number lives in scripts/lib/rule-latency-thresholds.ts, next to the
// measurement it came from, and is re-exported here so that a consumer has one
// entry point for the whole gate. They are separated from this file because a
// pull request that loosens one should read as a diff to a file whose entire
// contents are the justification, not as three characters inside 800 lines of
// machinery.
// ---------------------------------------------------------------------------

export {
  RECORD_FLOOR,
  FAIL_FLOOR,
  TOLERANCE,
  SHAPE_HIGH,
  SHAPE_REPORT_LOW,
  ANCHOR_MIN_COVERAGE,
} from "./lib/rule-latency-thresholds.js";

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

const BASELINE_NOTE =
  "Per-rule regex cost relative to the median rule of the anchor cohort, measured in the same " +
  "profiling pass. Ratchet only -- new entries must be fixed, not added. anchorRuleIds pins the " +
  "denominator's membership so that adding rules cannot dilute it; medianRuleMs is informational " +
  "and never compared, it is the runner-speed term this metric exists to divide out. " +
  "Do NOT widen the baseline to silence a failure. See scripts/gate-rule-latency.ts.";

export interface Baseline {
  readonly generatedAt: string;
  readonly note: string;
  readonly corpus: {
    readonly rules: number;
    readonly samples: number;
    readonly medianRuleMs: number;
  };
  readonly skippedRuleIds: readonly string[];
  /** Evaluable rules the eval corpus cannot exercise. Growth here is reported. */
  readonly unprofilableRuleIds: readonly string[];
  /**
   * The cohort whose median is the denominator. Fixed membership is the whole
   * point: see THE METRIC in the file header.
   */
  readonly anchorRuleIds: readonly string[];
  readonly latencyShape: number;
  /** ruleId -> relCost at the time the baseline was written. */
  readonly expensiveRules: Readonly<Record<string, number>>;
}

export const EMPTY_BASELINE: Baseline = {
  generatedAt: "",
  note: BASELINE_NOTE,
  corpus: { rules: 0, samples: 0, medianRuleMs: 0 },
  skippedRuleIds: [],
  unprofilableRuleIds: [],
  anchorRuleIds: [],
  latencyShape: 0,
  expensiveRules: {},
};

/**
 * Parse and validate a baseline. Never trusts the shape on disk.
 *
 * The array check is not paranoia: gate-re2-portability.ts learned that a
 * corrupt baseline which still passes a bare `typeof === "object"` reads as an
 * EMPTY baseline, which reclassifies the entire corpus as brand-new regressions.
 */
export function parseBaseline(doc: unknown, source: string): Baseline {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error(`${source}: baseline must be a JSON object`);
  }
  const partial = doc as Partial<Baseline>;
  const expensive = partial.expensiveRules;
  if (expensive === null || typeof expensive !== "object" || Array.isArray(expensive)) {
    throw new Error(`${source}: "expensiveRules" must be an object of ruleId -> relCost`);
  }
  for (const [id, value] of Object.entries(expensive)) {
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
      throw new Error(`${source}: entry "${id}" must be a positive number (relative cost), got ${JSON.stringify(value)}`);
    }
  }
  if (typeof partial.latencyShape !== "number" || !Number.isFinite(partial.latencyShape) || partial.latencyShape <= 0) {
    throw new Error(`${source}: "latencyShape" must be a positive number`);
  }
  const corpus = partial.corpus;
  if (corpus === null || typeof corpus !== "object" || typeof corpus.samples !== "number") {
    throw new Error(`${source}: "corpus.samples" must be a number`);
  }
  if (partial.anchorRuleIds !== undefined && !Array.isArray(partial.anchorRuleIds)) {
    throw new Error(`${source}: "anchorRuleIds" must be an array of rule ids`);
  }
  return {
    ...EMPTY_BASELINE,
    ...partial,
    corpus: { ...EMPTY_BASELINE.corpus, ...corpus },
    skippedRuleIds: partial.skippedRuleIds ?? [],
    unprofilableRuleIds: partial.unprofilableRuleIds ?? [],
    anchorRuleIds: partial.anchorRuleIds ?? [],
    expensiveRules: expensive as Record<string, number>,
  };
}

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`${path}: not readable as JSON -- ${(err as Error).message}`);
  }
}

function loadBaseline(): Baseline {
  if (!existsSync(BASELINE_PATH)) return EMPTY_BASELINE;
  return parseBaseline(readJson(BASELINE_PATH), BASELINE_PATH);
}

// ---------------------------------------------------------------------------
// Pure analysis
// ---------------------------------------------------------------------------

export interface RelCost {
  readonly ruleId: string;
  readonly file: string;
  readonly ms: number;
  readonly rel: number;
}

export interface AnchorCoverage {
  readonly recorded: number;
  readonly present: number;
  readonly fraction: number;
}

export function anchorCoverage(profile: Profile, base: Baseline): AnchorCoverage {
  const recorded = base.anchorRuleIds.length;
  if (recorded === 0) return { recorded: 0, present: 0, fraction: 1 };
  const present = base.anchorRuleIds.filter((id) => profile.costs[id] !== undefined).length;
  return { recorded, present, fraction: present / recorded };
}

/**
 * The denominator: median cost over the anchor cohort, measured in THIS profile.
 *
 * Falls back to the whole profile when no cohort is recorded, which happens in
 * exactly two situations -- writing the first baseline, and a fixture profile in
 * a test -- and in the first of those the two are the same set by construction.
 */
export function anchorMedianMs(profile: Profile, base: Baseline): number {
  const present = base.anchorRuleIds
    .map((id) => profile.costs[id])
    .filter((c): c is NonNullable<typeof c> => c !== undefined)
    .map((c) => c.ms);
  if (present.length === 0) return profileMedianMs(profile);
  return median(present);
}

/**
 * Turn absolute per-rule costs into anchor medians, descending.
 *
 * This is where runner speed cancels: multiply every `ms` by k and every `rel`
 * is byte-identical. tests/gate-rule-latency.test.ts pins that property, and
 * pins the other half too -- that adding rules to the corpus does not move it.
 */
export function relativeCosts(profile: Profile, base: Baseline = EMPTY_BASELINE): readonly RelCost[] {
  const mid = anchorMedianMs(profile, base);
  if (mid <= 0) return [];
  return Object.entries(profile.costs)
    .map(([ruleId, c]) => ({ ruleId, file: c.file, ms: c.ms, rel: c.ms / mid }))
    .sort((a, b) => b.rel - a.rel);
}

export interface Regression {
  readonly rule: RelCost;
  readonly reason: string;
}

export interface Comparison {
  readonly added: readonly Regression[];
  readonly worsened: readonly Regression[];
  readonly improved: readonly string[];
  readonly resolved: readonly string[];
}

/**
 * Which regressions this run is allowed to fail on.
 *
 * `null` means everything, which is both the default and the fail-closed
 * answer when a base ref cannot be resolved. A set means only rules whose file
 * appears in it.
 */
export type Blame = ReadonlySet<string> | null;

/**
 * Files that change what EVERY rule costs, so touching one puts the whole
 * corpus back in scope. The engine is the thing being timed; the eval corpus is
 * what it is timed over; the lane contract decides which rules are timed at all;
 * the profiler is the clock and the thresholds file is the verdict; the lockfile
 * carries the regex engine underneath.
 */
const MEASUREMENT_PATHS: readonly string[] = [
  "src/engine.ts",
  "src/eval/",
  "src/quality/rule-contract.ts",
  "scripts/lib/rule-latency-",
  "scripts/gate-rule-latency.ts",
  "package-lock.json",
];

/**
 * Rule files a diff touched, or null for "judge everything".
 *
 * Every failure path returns null on purpose. A gate that silently narrows its
 * own scope when git misbehaves is worse than one that occasionally asks an
 * author about a rule they did not write.
 */
export function blameScope(baseRef: string, cwd: string = REPO_ROOT): Blame {
  if (!baseRef) return null;
  const result = spawnSync("git", ["diff", "--name-only", `${baseRef}...HEAD`], {
    cwd,
    encoding: "utf8",
    timeout: 60_000,
  });
  if (result.status !== 0 || typeof result.stdout !== "string") return null;

  const changed = result.stdout.split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
  if (changed.length === 0) return null;
  if (changed.some((path) => MEASUREMENT_PATHS.some((prefix) => path.startsWith(prefix)))) return null;
  return new Set(changed.filter((path) => path.startsWith("rules/")));
}

/** Split regressions into the ones this change owns and the ones it inherited. */
export function splitByBlame(
  regressions: readonly Regression[],
  blame: Blame
): { readonly owned: readonly Regression[]; readonly inherited: readonly Regression[] } {
  if (blame === null) return { owned: regressions, inherited: [] };
  return {
    owned: regressions.filter((r) => blame.has(r.rule.file)),
    inherited: regressions.filter((r) => !blame.has(r.rule.file)),
  };
}

/**
 * Ratchet comparison. Only rules at or above FAIL_FLOOR can fail, whether or
 * not they are baselined -- see the WHAT DOES NOT FAIL note in the header.
 */
export function compareToBaseline(current: readonly RelCost[], base: Baseline): Comparison {
  const known = base.expensiveRules;
  const byId = new Map(current.map((c) => [c.ruleId, c]));

  const added = current
    .filter((c) => !(c.ruleId in known) && c.rel >= FAIL_FLOOR)
    .map((rule) => ({ rule, reason: `${rule.rel.toFixed(1)}x median, not in baseline (limit ${FAIL_FLOOR}x)` }));

  const worsened = current
    .filter((c) => c.ruleId in known && c.rel >= FAIL_FLOOR && c.rel > known[c.ruleId]! * TOLERANCE)
    .map((rule) => ({
      rule,
      reason: `${rule.rel.toFixed(1)}x median, was ${known[rule.ruleId]!.toFixed(1)}x (limit ${(known[rule.ruleId]! * TOLERANCE).toFixed(1)}x)`,
    }));

  // The ratchet advice uses the same deadband as the failure condition, and for
  // the same reason. relCost is a continuous quantity that jitters between two
  // profiles, so "cheaper than recorded" alone would flag roughly half the
  // baseline on every green run and train people to skim past the section.
  // Requiring a full TOLERANCE of improvement means the suggestion only appears
  // when something genuinely got faster. A baselined rule drifting a few percent
  // simply keeps its stale entry, which is harmless: it is below FAIL_FLOOR or
  // bounded by TOLERANCE either way.
  const baselineIds = Object.keys(known).sort();
  return {
    added,
    worsened,
    improved: baselineIds.filter((id) => {
      const now = byId.get(id);
      return now !== undefined && now.rel < known[id]! / TOLERANCE;
    }),
    // Discrete, so no deadband needed: the rule is gone from the corpus, or the
    // engine now skips it as draft/deprecated.
    resolved: baselineIds.filter((id) => !byId.has(id)),
  };
}

export interface ShapeVerdict {
  readonly ok: boolean;
  readonly observed: number;
  readonly low: number;
  readonly high: number;
}

/**
 * Secondary net: engine-wide tail shape must not rise past its band.
 *
 * `low` is reported, never enforced -- corpus growth pushes shape down and this
 * gate refuses to call growth a regression. See SHAPE_HIGH.
 */
export function checkShape(observed: number, base: Baseline): ShapeVerdict {
  if (base.latencyShape <= 0) return { ok: true, observed, low: 0, high: Infinity };
  const low = base.latencyShape * SHAPE_REPORT_LOW;
  const high = base.latencyShape * SHAPE_HIGH;
  return { ok: observed <= high, observed, low, high };
}

/**
 * A corpus smaller than the baseline recorded means the measurement basis was
 * cut, which is the cheapest way to make a pathological rule stop showing up.
 * That has to surface as a broken gate (exit 2), never as a green one.
 */
export function corpusShrank(profile: Profile, base: Baseline): string | null {
  if (base.corpus.samples <= 0) return null;
  if (profile.samples >= base.corpus.samples) return null;
  return (
    `eval corpus shrank ${base.corpus.samples} -> ${profile.samples} samples. ` +
    "The measurement basis moved, so this run cannot be compared to the baseline. " +
    "If the shrink is intentional, regenerate with --write-baseline in its own reviewed commit."
  );
}

/**
 * The other half of the same anti-muting check, on the other axis: the samples
 * are the corpus the rules run over, the anchors are the rules the denominator
 * is made of, and cutting either one moves every number without touching a
 * regex.
 */
export function anchorsEroded(profile: Profile, base: Baseline): string | null {
  const coverage = anchorCoverage(profile, base);
  if (coverage.recorded === 0) return null;
  if (coverage.fraction >= ANCHOR_MIN_COVERAGE) return null;
  return (
    `only ${coverage.present} of ${coverage.recorded} anchor rules are still evaluated ` +
    `(${(coverage.fraction * 100).toFixed(1)}%, floor ${(ANCHOR_MIN_COVERAGE * 100).toFixed(0)}%). ` +
    "The denominator is a median over those rules, so this run cannot be compared to the baseline. " +
    "If the attrition is intentional, regenerate with --write-baseline in its own reviewed commit."
  );
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/** Enough of the leaderboard to be useful, short enough to read in a CI log. */
const TOP_N = 10;

export interface GateResult {
  readonly exitCode: number;
  readonly lines: readonly string[];
}

/** Header plus the cost leaderboard, which is a useful artifact in its own right. */
function renderHeader(
  profile: Profile,
  current: readonly RelCost[],
  base: Baseline,
  shape: ShapeVerdict,
  medianMs: number
): string[] {
  const coverage = anchorCoverage(profile, base);
  const lines = [
    "",
    "=== ATR Rule Latency GATE ===",
    `corpus: ${profile.rules} rules profiled, ${profile.samples} samples, ` +
      `${profile.skippedRuleIds.length} draft/deprecated, ${profile.unprofilableRuleIds.length} not exercised by this corpus`,
    `denominator: median of ${coverage.recorded > 0 ? `${coverage.present}/${coverage.recorded} anchor rules` : "every profiled rule"} ` +
      `= ${medianMs.toFixed(4)}ms per corpus pass (absolute value informational -- never compared)`,
    `baseline: ${Object.keys(base.expensiveRules).length} rule(s) recorded at >= ${RECORD_FLOOR}x, fail floor ${FAIL_FLOOR}x, tolerance ${TOLERANCE}x`,
    `shape p95/p50: ${shape.observed.toFixed(3)} (fails above ${shape.high.toFixed(3)}; below ${shape.low.toFixed(3)} is reported, not fatal)`,
  ];

  if (profile.unparsedFiles > 0) {
    lines.push(
      `WARNING: ${profile.unparsedFiles} rule file(s) failed to parse and were not profiled. ` +
        "The schema gate owns that failure, but they are invisible to this one."
    );
  }
  if (profile.dirtyRulePaths.length > 0) {
    lines.push(
      `WARNING: ${profile.dirtyRulePaths.length} uncommitted path(s) under rules/ during profiling. ` +
        "Expected while authoring; on a CI checkout it means the profiled set is not the committed set."
    );
  }

  const newlyUnprofilable = profile.unprofilableRuleIds.filter((id) => !base.unprofilableRuleIds.includes(id));
  if (newlyUnprofilable.length > 0) {
    lines.push(
      `WARNING: ${newlyUnprofilable.length} new rule(s) declare a source type the eval corpus never emits, ` +
        "so their regexes are never run here and their cost is unmeasured:",
      ...newlyUnprofilable.slice(0, TOP_N).map((id) => `  ? ${id}`),
      "  Widen src/eval/corpus.ts to cover them, or accept the gap with --write-baseline."
    );
  }

  return [
    ...lines,
    "",
    `most expensive rules (top ${TOP_N} of ${current.length}):`,
    ...current.slice(0, TOP_N).map((c) => `  ${c.rel.toFixed(1).padStart(7)}x  ${c.ruleId}  ${c.ms.toFixed(4)}ms`),
  ];
}

/**
 * Accepted debt, restated on every run.
 *
 * A ratchet's baseline is a debt register, and a register nobody reads is a
 * place to hide things. Printing the rules that are only green because they were
 * already there -- ATR-2026-02300 sits at 288x with a variable-length lookbehind
 * -- keeps the cost of the compromise in front of whoever is looking at the log,
 * rather than one `git show` away.
 */
function renderDebt(current: readonly RelCost[], base: Baseline): string[] {
  const debt = current.filter((c) => c.rel >= FAIL_FLOOR && c.ruleId in base.expensiveRules);
  if (debt.length === 0) return [];
  return [
    "",
    `ACCEPTED DEBT -- ${debt.length} rule(s) above the ${FAIL_FLOOR}x fail floor, green only because the baseline records them:`,
    ...debt.map((c) => `  = ${c.rel.toFixed(1).padStart(7)}x  ${c.ruleId}  ${c.file}`),
    "  These are not fine. They are grandfathered. Fixing one and re-running --write-baseline",
    "  is how this list gets shorter; it is the only thing that ever makes it shorter.",
  ];
}

function renderRatchet({ improved, resolved }: Comparison): string[] {
  if (improved.length === 0 && resolved.length === 0) return [];
  return [
    "",
    "RATCHET -- these improved and should be tightened in the baseline:",
    ...resolved.map((id) => `  + ${id}: no longer evaluated (removed, or now draft/deprecated)`),
    ...improved.map((id) => `  + ${id}: now more than ${TOLERANCE}x cheaper than the baseline records`),
    "  (run --write-baseline to tighten)",
  ];
}

function renderRegressions(regressions: readonly Regression[], profile: Profile, medianMs: number): string[] {
  if (regressions.length === 0) return [];
  return [
    "",
    "GATE FAIL -- rule regex cost regressed:",
    ...regressions.flatMap(({ rule, reason }) => [
      `  - ${rule.ruleId}  ${reason}`,
      `      ${rule.file}`,
      `      ${rule.ms.toFixed(4)}ms to evaluate ${profile.samples} samples (anchor median: ${medianMs.toFixed(4)}ms)`,
    ]),
    "",
    "How to fix:",
    "  Find the quantifier that backtracks. The usual shape is a bounded outer",
    "  quantifier wrapping an unbounded inner one -- `(?:[a-z]+\\s*){0,8}` and",
    "  friends -- which isReDoSSafe() in src/engine.ts deliberately permits and",
    "  which costs polynomially in the bound: {0,6} measured 175ms and {0,8} 9.8s",
    "  on a single 61-character sample. Make the inner atom unable to overlap its",
    "  delimiter (a character class that excludes it), drop the bound to something",
    "  a human picked, or narrow the field the condition reads.",
    "",
    "This is measured against a cohort of rules fixed by the baseline and timed in",
    "the SAME profiling run, so it is neither a slow-runner artifact nor an effect",
    "of the corpus having grown. Do NOT widen the baseline to silence this.",
  ];
}

function renderShapeFailure(shape: ShapeVerdict): string[] {
  if (shape.ok) return [];
  return [
    "",
    "GATE FAIL -- engine latency shape rose past its band:",
    `  p95/p50 = ${shape.observed.toFixed(3)}, ceiling ${shape.high.toFixed(3)}`,
    "  Per-rule profiling explains only a small share of engine cost; this ceiling covers",
    "  the rest. A shape change this large means the tail of the per-sample distribution",
    "  moved -- normalisation, dispatch or a new tier. Machine load moved it 1.93 -> 2.13",
    "  in measurement, well inside the 2.5x headroom above.",
  ];
}

function renderInherited(inherited: readonly Regression[], medianMs: number): string[] {
  if (inherited.length === 0) return [];
  return [
    "",
    "PRE-EXISTING -- above the fail floor, but not introduced by this change:",
    ...inherited.map(({ rule, reason }) => `  ! ${rule.ruleId}  ${reason}  ${rule.file}`),
    `  (anchor median ${medianMs.toFixed(4)}ms. Reported, not fatal: a pull request must not go red for`,
    "   a rule it did not touch. main's own run of this gate opens an issue for these.)",
  ];
}

export function renderGate(
  profile: Profile,
  current: readonly RelCost[],
  base: Baseline,
  blame: Blame = null
): GateResult {
  const blocked = corpusShrank(profile, base) ?? anchorsEroded(profile, base);
  if (blocked) return { exitCode: 2, lines: ["", "=== ATR Rule Latency GATE ===", "", `GATE ERROR -- ${blocked}`, ""] };

  const comparison = compareToBaseline(current, base);
  const shape = checkShape(profile.latencyShape, base);
  const medianMs = anchorMedianMs(profile, base);
  const { owned, inherited } = splitByBlame([...comparison.added, ...comparison.worsened], blame);

  const out = [
    ...renderHeader(profile, current, base, shape, medianMs),
    ...renderDebt(current, base),
    ...renderRatchet(comparison),
    ...renderInherited(inherited, medianMs),
  ];

  // The shape ceiling is never scoped by blame. It is one engine-wide number
  // with 2.5x of headroom rather than a per-rule debt someone else can own, so
  // there is nobody to inherit it from: if the tail has blown up, every change
  // should stop until the baseline says otherwise.
  if (owned.length === 0 && shape.ok) {
    return { exitCode: 0, lines: [...out, "", "GATE PASS -- no rule got pathologically expensive relative to its peers.", ""] };
  }
  return {
    exitCode: 1,
    lines: [...out, ...renderRegressions(owned, profile, medianMs), ...renderShapeFailure(shape), ""],
  };
}

// ---------------------------------------------------------------------------
// Baseline writing
// ---------------------------------------------------------------------------

export function baselineFrom(profile: Profile, current: readonly RelCost[]): Baseline {
  const recorded = current.filter((c) => c.rel >= RECORD_FLOOR).sort((a, b) => b.rel - a.rel);
  return {
    generatedAt: new Date().toISOString(),
    note: BASELINE_NOTE,
    corpus: { rules: profile.rules, samples: profile.samples, medianRuleMs: round(profileMedianMs(profile), 4) },
    skippedRuleIds: profile.skippedRuleIds,
    unprofilableRuleIds: profile.unprofilableRuleIds,
    anchorRuleIds: Object.keys(profile.costs).sort(),
    latencyShape: round(profile.latencyShape, 3),
    expensiveRules: Object.fromEntries(recorded.map((c) => [c.ruleId, round(c.rel, 1)])),
  };
}

function round(value: number, digits: number): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function flagValue(argv: readonly string[], flag: string): string {
  const idx = argv.indexOf(flag);
  if (idx === -1) return "";
  const value = argv[idx + 1] ?? "";
  if (!value || value.startsWith("--")) throw new Error(`${flag} needs a path`);
  return value;
}

export async function main(argv: readonly string[]): Promise<number> {
  const profilePath = flagValue(argv, "--profile");
  const writeProfilePath = flagValue(argv, "--write-profile");

  const profile = profilePath
    ? parseProfile(readJson(profilePath), profilePath)
    : await buildProfile(RULES_DIR);

  if (writeProfilePath) {
    writeFileSync(writeProfilePath, JSON.stringify(profile, null, 2) + "\n");
    process.stdout.write(`wrote profile: ${profile.rules} rules -> ${writeProfilePath}\n`);
  }

  if (argv.includes("--write-baseline")) {
    // A fresh baseline defines its own anchor cohort, so the denominator is the
    // whole profile: relativeCosts() with no baseline. Reusing the OLD cohort
    // here would bake the previous run's denominator into the new record.
    const baseline = baselineFrom(profile, relativeCosts(profile));
    writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + "\n");
    process.stdout.write(
      `wrote baseline: ${Object.keys(baseline.expensiveRules).length} rule(s) >= ${RECORD_FLOOR}x median, ` +
        `${baseline.anchorRuleIds.length} anchor rules, shape ${baseline.latencyShape} -> ${BASELINE_PATH}\n`
    );
    return 0;
  }

  const base = loadBaseline();
  const blame = argv.includes("--changed-since") ? blameScope(flagValue(argv, "--changed-since")) : null;
  const { exitCode, lines } = renderGate(profile, relativeCosts(profile, base), base, blame);
  process.stdout.write(lines.join("\n"));
  return exitCode;
}

/**
 * Exit codes are distinct on purpose: 1 means a rule regressed and an author
 * must act, 2 means the gate itself could not run. A CI log that conflates the
 * two teaches people to ignore the gate.
 */
const INVOKED_DIRECTLY =
  process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err: unknown) => {
      process.stderr.write(`\nRule latency gate could not run: ${err instanceof Error ? err.message : String(err)}\n\n`);
      process.exitCode = 2;
    });
}
