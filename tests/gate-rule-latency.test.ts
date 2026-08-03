/**
 * Tests for scripts/gate-rule-latency.ts -- the per-rule regex cost ratchet.
 *
 * This gate exists because the assertion it replaces, `p95 < 50ms` in
 * tests/eval-harness.test.ts, measured the CI runner rather than the rules: PR
 * #383 read 51.111ms while adding zero rules, and across 14 real runs with an
 * unchanged corpus p95 varied by 2.716x. So the properties pinned here are
 * exactly the ones whose absence made the old gate useless:
 *
 *  1. IMMUNE TO RUNNER SPEED. Scale every measurement by k and the verdict is
 *     bit-identical. This is a property of the metric (a ratio of two numbers
 *     from the same profiling pass), not a tolerance, so the test asserts
 *     equality rather than approximate equality.
 *  2. IMMUNE TO CORPUS GROWTH. Adding 200 rules to a corpus of 200 must not move
 *     an existing rule's verdict by so much as a digit. The old absolute
 *     threshold failed on growth alone, which is what blocked #385 and #389 --
 *     and so, less obviously, did an earlier draft of THIS gate, which divided
 *     by the median of whoever happened to be in the run. That regression has
 *     its own test below ("does not move an existing rule's number at all").
 *  3. CATCHES A PATHOLOGICAL REGEX, BY NAME. Both synthetically and -- in the
 *     end-to-end block -- by really profiling a fixture rule whose regex
 *     backtracks. A gate whose measurement layer is untested is a gate that can
 *     silently stop measuring.
 *  4. CANNOT BE QUIETLY MUTED. Shrinking the corpus, or culling the rules the
 *     denominator is made of, is exit 2 (gate broken), not exit 0 (gate happy).
 *     A corrupt baseline throws instead of reading as empty. The median
 *     denominator cannot be moved by the rule under suspicion.
 *  5. DOES NOT CRY WOLF. Cheap-rule jitter, which really does reach 2.46x
 *     between clean runs, never fails the build.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import {
  median,
  profileMedianMs,
  anchorMedianMs,
  anchorCoverage,
  anchorsEroded,
  relativeCosts,
  compareToBaseline,
  checkShape,
  corpusShrank,
  renderGate,
  parseBaseline,
  baselineFrom,
  buildProfile,
  isEvaluable,
  isCorpusCovered,
  EMPTY_BASELINE,
  RECORD_FLOOR,
  FAIL_FLOOR,
  TOLERANCE,
  SHAPE_HIGH,
  ANCHOR_MIN_COVERAGE,
  type Profile,
  type Baseline,
} from "../scripts/gate-rule-latency.js";
import type { ATRRule } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(REPO_ROOT, "scripts/gate-rule-latency.ts");
const COMMITTED_BASELINE_PATH = join(REPO_ROOT, "data/rule-latency-baseline.json");

// ---------------------------------------------------------------------------
// Synthetic profile builders
// ---------------------------------------------------------------------------

const BASE_SHAPE = 1.92;

/** Median rule cost of every synthetic profile, in milliseconds. */
const MEDIAN_MS = 0.1;

/**
 * A profile shaped like the real one: a dense cluster of ordinary rules around
 * the median plus a short expensive tail. `extra` adds rules at a chosen
 * multiple of the median, `scale` simulates a slower machine.
 *
 * The ordinary rules are laid out symmetrically -- matched pairs below (down to
 * 0.6x) and above (up to 3.0x) around a small plateau at exactly 1.0x. The
 * plateau is sized to cover however many expensive rules the caller adds, so
 * the median is exactly MEDIAN_MS whatever the test does and an assertion can
 * name an exact multiple. The upper tail reaching 3.0x mirrors the real corpus,
 * whose p90 is 3.16x of its median.
 */
function makeProfile(extra: Record<string, number> = {}, ordinary = 201, scale = 1, samples = 341): Profile {
  const plateau = 2 * Object.keys(extra).length + 3;
  const pairs = Math.max(1, Math.floor((ordinary - plateau) / 2));
  const spreads = Array.from({ length: plateau }, () => 1);
  for (let k = 1; k <= pairs; k++) {
    spreads.push(1 - (0.4 * k) / pairs, 1 + (2 * k) / pairs);
  }

  const costs: Record<string, { ms: number; file: string }> = {};
  for (const [i, spread] of spreads.entries()) {
    costs[`ATR-ORD-${String(i).padStart(4, "0")}`] = {
      ms: MEDIAN_MS * spread * scale,
      file: `rules/synthetic/ord-${i}.yaml`,
    };
  }
  for (const [id, rel] of Object.entries(extra)) {
    costs[id] = { ms: MEDIAN_MS * rel * scale, file: `rules/synthetic/${id}.yaml` };
  }
  return {
    generatedAt: "2026-08-03T00:00:00.000Z",
    rules: Object.keys(costs).length,
    samples,
    medianRuleMs: MEDIAN_MS * scale,
    skippedRuleIds: [],
    unprofilableRuleIds: [],
    unparsedFiles: 0,
    dirtyRulePaths: [],
    costs,
    latencyShape: BASE_SHAPE,
    latencyP50Ms: 7.6 * scale,
    latencyP95Ms: 7.6 * BASE_SHAPE * scale,
  };
}

/** Multiply every measured quantity by k -- i.e. run the same corpus on a slower box. */
function onSlowerRunner(profile: Profile, k: number): Profile {
  const costs = Object.fromEntries(
    Object.entries(profile.costs).map(([id, c]) => [id, { ...c, ms: c.ms * k }])
  );
  return {
    ...profile,
    costs,
    medianRuleMs: profile.medianRuleMs * k,
    latencyP50Ms: profile.latencyP50Ms * k,
    latencyP95Ms: profile.latencyP95Ms * k,
    // Shape is a ratio of two numbers that both scaled, so it does not move.
    latencyShape: profile.latencyShape,
  };
}

/**
 * Append `count` brand-new rules at `rel` times the profile's own median, leaving
 * every existing rule's measured cost untouched. This is what a week of
 * CVE-collector output looks like, and the thing an earlier draft got wrong.
 */
function withNewRules(profile: Profile, count: number, rel: number): Profile {
  const unit = profileMedianMs(profile) * rel;
  const costs = { ...profile.costs };
  for (let i = 0; i < count; i++) {
    costs[`ATR-NEW-${String(i).padStart(4, "0")}`] = { ms: unit, file: `rules/synthetic/new-${i}.yaml` };
  }
  return { ...profile, rules: Object.keys(costs).length, costs };
}

/** Drop rules from a profile, as deleting or drafting them would. */
function withoutRules(profile: Profile, ids: readonly string[]): Profile {
  const costs = Object.fromEntries(Object.entries(profile.costs).filter(([id]) => !ids.includes(id)));
  return { ...profile, rules: Object.keys(costs).length, costs };
}

function baselineOf(profile: Profile): Baseline {
  return baselineFrom(profile, relativeCosts(profile));
}

function verdict(profile: Profile, base: Baseline): number {
  return renderGate(profile, relativeCosts(profile, base), base).exitCode;
}

function report(profile: Profile, base: Baseline): string {
  return renderGate(profile, relativeCosts(profile, base), base).lines.join("\n");
}

function relOf(profile: Profile, base: Baseline, ruleId: string): number {
  return relativeCosts(profile, base).find((c) => c.ruleId === ruleId)!.rel;
}

// ---------------------------------------------------------------------------
// 1. The metric itself
// ---------------------------------------------------------------------------

describe("relative cost metric", () => {
  it("computes cost relative to the median rule of the same profile", () => {
    const profile = makeProfile({ "ATR-SLOW-1": 20 });
    const costs = relativeCosts(profile);

    expect(profileMedianMs(profile)).toBeCloseTo(0.1, 6);
    expect(costs[0]!.ruleId).toBe("ATR-SLOW-1");
    expect(costs[0]!.rel).toBeCloseTo(20, 6);
  });

  it("derives the median from the costs, not from the stored medianRuleMs field", () => {
    // A hand-edited profile claiming a huge median must not make every rule
    // look cheap. The stored field is documentation; the divisor is measured.
    const profile = { ...makeProfile({ "ATR-SLOW-1": 20 }), medianRuleMs: 999 };
    expect(relativeCosts(profile)[0]!.rel).toBeCloseTo(20, 6);
  });

  it("median ignores a single catastrophic outlier (a mean would not)", () => {
    const values = [1, 1, 1, 1, 1, 1, 1, 1, 1, 10_000];
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    expect(median(values)).toBe(1);
    // The denominator is what an author would attack to hide a slow rule. With
    // a mean, the culprit manufactures its own alibi -- 1000x here.
    expect(mean).toBeGreaterThan(1000);
  });

  it("one pathological rule cannot inflate the denominator that judges it", () => {
    const clean = makeProfile();
    const poisoned = makeProfile({ "ATR-SYN-8": 800 });
    expect(profileMedianMs(poisoned)).toBeCloseTo(profileMedianMs(clean), 6);
  });

  it("divides by the anchor cohort, not by whoever is in the run", () => {
    const profile = makeProfile({ "ATR-EXP-1": 12 });
    const base = baselineOf(profile);
    // Anchors are the rules that existed when the baseline was written...
    expect(base.anchorRuleIds).toContain("ATR-EXP-1");
    expect(anchorMedianMs(profile, base)).toBeCloseTo(MEDIAN_MS, 9);
    // ...and newcomers are absent from them, so they cannot enter the divisor.
    const grown = withNewRules(profile, 50, 0.4);
    expect(anchorMedianMs(grown, base)).toBeCloseTo(MEDIAN_MS, 9);
    expect(profileMedianMs(grown)).toBeLessThan(MEDIAN_MS);
  });
});

// ---------------------------------------------------------------------------
// 2. Runner speed immunity -- the whole point
// ---------------------------------------------------------------------------

describe("runner speed", () => {
  const profile = makeProfile({ "ATR-EXP-1": 12, "ATR-EXP-2": 4 });
  const base = baselineOf(profile);

  it.each([0.37, 1, 2.716, 7.8])("verdict is unchanged when the box is %sx slower", (k) => {
    const scaled = onSlowerRunner(profile, k);
    const before = relativeCosts(profile, base).map((c) => c.rel);
    const after = relativeCosts(scaled, base).map((c) => c.rel);

    // Equality, not closeness: the k cancels exactly in a ratio.
    for (const [i, rel] of after.entries()) expect(rel).toBeCloseTo(before[i]!, 12);
    expect(verdict(scaled, base)).toBe(0);
  });

  it("a 2.716x spread -- the real CI runner spread -- would have failed an absolute budget", () => {
    // Same corpus, two runners. The metric this gate replaces used p95 directly.
    const fast = makeProfile({ "ATR-EXP-1": 12 });
    const slow = onSlowerRunner(fast, 2.716);
    expect(slow.latencyP95Ms).toBeGreaterThan(fast.latencyP95Ms * 2.7);
    // ...and yet both are the same verdict here.
    expect(verdict(slow, baselineOf(fast))).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 3. Corpus growth immunity
// ---------------------------------------------------------------------------

describe("corpus growth", () => {
  it("does not move an existing rule's number at all", () => {
    // The regression that motivated the anchor cohort. Measured on the real
    // profile: 200 new rules at the 14th percentile of cost moved a run-local
    // median 0.2095 -> 0.1360ms and lifted every relCost by 1.540x, with nothing
    // having changed. Against the anchor cohort the lift is exactly 1.
    const before = makeProfile({ "ATR-EXP-1": 12 }, 200);
    const base = baselineOf(before);
    const grown = withNewRules(before, 200, 0.48);

    expect(profileMedianMs(grown)).toBeLessThan(profileMedianMs(before) * 0.8);
    expect(relOf(grown, base, "ATR-EXP-1")).toBeCloseTo(relOf(before, base, "ATR-EXP-1"), 12);
    expect(verdict(grown, base)).toBe(0);
  });

  it("would have failed on growth alone with a run-local denominator", () => {
    // Pins the counterfactual, so nobody re-derives the divisor from the run.
    const before = makeProfile({ "ATR-EXP-1": 12 }, 200);
    const grown = withNewRules(before, 200, 0.48);
    const runLocalRel = profileMedianMs(before) / profileMedianMs(grown);
    expect(runLocalRel).toBeGreaterThan(1.3);
    expect(12 * runLocalRel).toBeGreaterThan(FAIL_FLOOR);
  });

  it("passes when the rule count grows but per-rule cost does not", () => {
    const before = makeProfile({ "ATR-EXP-1": 12 }, 200);
    const base = baselineOf(before);
    // 200 -> 500 ordinary rules, same cost distribution: engine total goes up
    // 2.5x, which is exactly what sank #385 and #389 under an absolute budget.
    const after = makeProfile({ "ATR-EXP-1": 12 }, 500);
    expect(after.rules).toBeGreaterThan(before.rules * 2);
    expect(verdict(after, base)).toBe(0);
  });

  it("tolerates ordinary attrition in the anchor cohort", () => {
    const before = makeProfile({ "ATR-EXP-1": 12 }, 400);
    const base = baselineOf(before);
    const someIds = Object.keys(before.costs).filter((id) => id.startsWith("ATR-ORD-")).slice(0, 20);
    const after = withoutRules(before, someIds);
    expect(anchorCoverage(after, base).fraction).toBeGreaterThan(ANCHOR_MIN_COVERAGE);
    expect(verdict(after, base)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 4. Catching a slow rule
// ---------------------------------------------------------------------------

describe("expensive rules", () => {
  const base = baselineOf(makeProfile({ "ATR-EXP-1": 12 }));

  it("fails, and names the rule, when a new rule lands above the fail floor", () => {
    const profile = makeProfile({ "ATR-EXP-1": 12, "ATR-SYN-6": 64.4 });
    const result = renderGate(profile, relativeCosts(profile, base), base);

    expect(result.exitCode).toBe(1);
    const text = result.lines.join("\n");
    expect(text).toContain("GATE FAIL");
    expect(text).toContain("ATR-SYN-6");
    expect(text).toContain("64.4x median");
    expect(text).toContain("rules/synthetic/ATR-SYN-6.yaml");
    expect(text).toContain("Do NOT widen the baseline to silence this.");
  });

  it.each([
    ["{0,6} -- 64.4x", 64.4],
    ["{0,8} -- 822.7x", 822.7],
    ["{0,10} -- 10657x", 10_657],
  ])("fails on a measured catastrophic construct: %s", (_label, rel) => {
    expect(verdict(makeProfile({ "ATR-EXP-1": 12, "ATR-SYN": rel }), base)).toBe(1);
  });

  it("passes a merely thick new rule on an unlucky runner", () => {
    // Derivation of FAIL_FLOOR: across four profiles of an unchanged corpus, the
    // highest reading taken by any rule sitting at or below the distribution's
    // p95 (4.23x) was 5.52x. That is the worst an innocent rule can look.
    expect(verdict(makeProfile({ "ATR-EXP-1": 12, "ATR-NEW": 5.52 }), base)).toBe(0);
    expect(5.52).toBeLessThan(FAIL_FLOOR);
  });

  it("fails a baselined rule that grew past its tolerance", () => {
    const profile = makeProfile({ "ATR-EXP-1": 12 * TOLERANCE + 1 });
    const text = report(profile, base);
    expect(verdict(profile, base)).toBe(1);
    expect(text).toContain("ATR-EXP-1");
    expect(text).toContain("was 12.0x");
  });

  it("passes a baselined rule that grew within its tolerance", () => {
    expect(verdict(makeProfile({ "ATR-EXP-1": 12 * TOLERANCE - 1 }), base)).toBe(0);
  });

  it("never fails on cheap-rule jitter, even across the fail floor", () => {
    // Measured: V8 tiers a RegExp up to native code after ~1000 executions and
    // one corpus pass is 341, so an unwarmed cheap rule read 4.1x in one clean
    // profile and 10.1x in the next -- 2.46x of pure measurement artifact.
    // profileRule() warms past the transition; RECORD_FLOOR covers the rest, by
    // recording the rule at 4.1x so the jittered reading is judged against its
    // own history rather than treated as a brand-new expensive rule.
    const cheapBase = baselineOf(makeProfile({ "ATR-CHEAP": 4.1 }));
    expect(cheapBase.expensiveRules["ATR-CHEAP"]).toBeCloseTo(4.1, 5);
    expect(verdict(makeProfile({ "ATR-CHEAP": 4.1 * 2.46 }), cheapBase)).toBe(0);
  });

  it("records the tail in the baseline but only fails above the fail floor", () => {
    const written = baselineOf(makeProfile({ "ATR-MID": 5, "ATR-HIGH": 12 }));
    expect(written.expensiveRules["ATR-MID"]).toBeCloseTo(5, 1);
    expect(written.expensiveRules["ATR-HIGH"]).toBeCloseTo(12, 1);
    expect(RECORD_FLOOR).toBeLessThan(FAIL_FLOOR);
  });

  it("bounds a recorded mid-tail rule by tolerance once it crosses the fail floor", () => {
    // 5x is recorded but cannot fail; growing it to 50x can, because RECORD_FLOOR
    // sits below FAIL_FLOOR precisely so this growth has a recorded starting point.
    const base5 = baselineOf(makeProfile({ "ATR-MID": 5 }));
    expect(verdict(makeProfile({ "ATR-MID": 13 }), base5)).toBe(0);
    expect(verdict(makeProfile({ "ATR-MID": 50 }), base5)).toBe(1);
  });

  it("judges a newly expensive rule that was previously too cheap to record", () => {
    // Nothing vouched for it, so it takes the added-rule path with no tolerance.
    const quiet = baselineOf(makeProfile({ "ATR-WAS-CHEAP": 1.1 }));
    expect(quiet.expensiveRules).not.toHaveProperty("ATR-WAS-CHEAP");
    expect(verdict(makeProfile({ "ATR-WAS-CHEAP": 60 }), quiet)).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 5. Ratchet direction
// ---------------------------------------------------------------------------

describe("ratchet", () => {
  const base = baselineOf(makeProfile({ "ATR-EXP-1": 12 }));

  it("reports an improvement instead of failing on it", () => {
    const profile = makeProfile({ "ATR-EXP-1": 1.5 });
    const result = renderGate(profile, relativeCosts(profile, base), base);
    expect(result.exitCode).toBe(0);
    expect(result.lines.join("\n")).toContain("--write-baseline to tighten");
  });

  it("stays quiet about improvements inside the measurement noise band", () => {
    // Clean back-to-back profiles drift. Reporting every rule that read a few
    // percent cheaper would flag half the baseline on every green run and train
    // people to skim the section.
    const profile = makeProfile({ "ATR-EXP-1": 12 / 1.2 });
    const result = renderGate(profile, relativeCosts(profile, base), base);
    expect(result.exitCode).toBe(0);
    expect(result.lines.join("\n")).not.toContain("--write-baseline to tighten");
  });

  it("reports a baselined rule that left the corpus entirely", () => {
    const profile = makeProfile();
    expect(report(profile, base)).toContain("no longer evaluated");
  });

  it("an empty baseline records the tail rather than failing every rule", () => {
    const profile = makeProfile({ "ATR-EXP-1": 12 });
    // First run against a missing baseline still fails loudly on >= FAIL_FLOOR
    // rules, which is correct: nothing has vouched for them yet.
    expect(verdict(makeProfile({ "ATR-EXP-1": 30 }), EMPTY_BASELINE)).toBe(1);
    expect(Object.keys(baselineOf(profile))).toContain("anchorRuleIds");
  });

  it("a fresh baseline anchors on itself rather than on the previous cohort", () => {
    // --write-baseline must define its own denominator; inheriting the old
    // cohort would bake one run's divisor into the next record.
    const grown = withNewRules(makeProfile({ "ATR-EXP-1": 12 }), 100, 0.5);
    const written = baselineOf(grown);
    expect(written.anchorRuleIds).toHaveLength(Object.keys(grown.costs).length);
    expect(written.anchorRuleIds).toContain("ATR-NEW-0000");
  });
});

// ---------------------------------------------------------------------------
// 6. Shape band (the secondary net)
// ---------------------------------------------------------------------------

describe("latency shape", () => {
  const base = baselineOf(makeProfile({ "ATR-EXP-1": 12 }));

  it("accepts the platform spread between arm64-macOS and x64-ubuntu", () => {
    // Measured 2.00 vs 1.91 -- 4.5% apart. A developer must not go red locally.
    expect(checkShape(BASE_SHAPE * 1.045, base).ok).toBe(true);
    expect(checkShape(BASE_SHAPE / 1.045, base).ok).toBe(true);
  });

  it("accepts the full 14-run CI spread", () => {
    // 1.8386 .. 2.0506 around a 1.9144 mean.
    for (const observed of [1.8386, 1.9144, 2.0506]) {
      expect(checkShape(observed, { ...base, latencyShape: 1.9144 }).ok).toBe(true);
    }
  });

  it("accepts the shape a contended machine produces", () => {
    // Measured 1.928/1.972 quiet, 2.054/2.134 under 10 CPU hogs.
    expect(checkShape(2.134, { ...base, latencyShape: 1.928 }).ok).toBe(true);
  });

  it("never fails downward, because corpus growth pushes shape down", () => {
    // Measured on a quiet machine: 670, 870 and 1170 rules -> 1.93, 1.88, 1.67.
    // A lower bound would eventually fail on rule growth alone, which is the
    // exact disease this change exists to cure.
    for (const observed of [BASE_SHAPE * 0.86, BASE_SHAPE * 0.4, 0.01]) {
      expect(checkShape(observed, base).ok).toBe(true);
    }
    const flat: Profile = { ...makeProfile({ "ATR-EXP-1": 12 }), latencyShape: BASE_SHAPE * 0.4 };
    expect(verdict(flat, base)).toBe(0);
  });

  it("fails when the tail blows up", () => {
    const blown: Profile = { ...makeProfile({ "ATR-EXP-1": 12 }), latencyShape: BASE_SHAPE * 5 };
    expect(verdict(blown, base)).toBe(1);
    expect(report(blown, base)).toContain("latency shape rose past its band");
  });

  it("is skipped when the baseline has no recorded shape", () => {
    expect(checkShape(99, EMPTY_BASELINE).ok).toBe(true);
    expect(SHAPE_HIGH).toBeGreaterThan(1);
  });
});

// ---------------------------------------------------------------------------
// 7. Anti-muting
// ---------------------------------------------------------------------------

describe("cannot be quietly muted", () => {
  const base = baselineOf(makeProfile({ "ATR-EXP-1": 12 }));

  it("a shrunken eval corpus is a broken gate (exit 2), not a passing one", () => {
    // Deleting the sample that triggers a pathological regex is the cheapest way
    // to make it disappear. Exit 0 would reward that.
    const shrunk: Profile = { ...makeProfile({ "ATR-EXP-1": 12 }), samples: 200 };
    expect(corpusShrank(shrunk, base)).toContain("shrank");
    expect(verdict(shrunk, base)).toBe(2);
  });

  it("a grown eval corpus is fine", () => {
    const grown: Profile = { ...makeProfile({ "ATR-EXP-1": 12 }), samples: 400 };
    expect(corpusShrank(grown, base)).toBeNull();
    expect(verdict(grown, base)).toBe(0);
  });

  it("a culled anchor cohort is a broken gate (exit 2), not a cheaper corpus", () => {
    // The other axis of the same attack: the denominator is a median over named
    // rules, so deleting or drafting enough of them moves every relCost with no
    // regex having changed.
    const profile = makeProfile({ "ATR-EXP-1": 12 }, 400);
    const wide = baselineOf(profile);
    const culled = withoutRules(
      profile,
      Object.keys(profile.costs).filter((id) => id.startsWith("ATR-ORD-")).slice(0, 200)
    );
    expect(anchorCoverage(culled, wide).fraction).toBeLessThan(ANCHOR_MIN_COVERAGE);
    expect(anchorsEroded(culled, wide)).toContain("anchor rules");
    expect(verdict(culled, wide)).toBe(2);
  });

  it("rejects a baseline whose expensiveRules is an array", () => {
    // gate-re2-portability.ts learned this one: an array passes a bare typeof
    // check, reads as an empty baseline, and turns the whole corpus into
    // "new regressions" -- or, with the failure floor, into a silent pass.
    expect(() => parseBaseline({ expensiveRules: [], latencyShape: 1.9, corpus: { samples: 341 } }, "x")).toThrow(
      /must be an object/
    );
  });

  it.each([
    [{ expensiveRules: { "ATR-1": "12" }, latencyShape: 1.9, corpus: { samples: 341 } }, /positive number/],
    [{ expensiveRules: { "ATR-1": -3 }, latencyShape: 1.9, corpus: { samples: 341 } }, /positive number/],
    [{ expensiveRules: {}, latencyShape: 0, corpus: { samples: 341 } }, /latencyShape/],
    [{ expensiveRules: {}, latencyShape: 1.9, corpus: {} }, /corpus.samples/],
    [
      { expensiveRules: {}, latencyShape: 1.9, corpus: { samples: 341 }, anchorRuleIds: {} },
      /anchorRuleIds/,
    ],
  ])("rejects a malformed baseline (%#)", (doc, pattern) => {
    expect(() => parseBaseline(doc, "x")).toThrow(pattern);
  });

  it("keeps the skipped-rule list so an un-skipped rule cannot inherit a pass", () => {
    const profile: Profile = { ...makeProfile({ "ATR-EXP-1": 12 }), skippedRuleIds: ["ATR-DRAFT-1"] };
    const written = baselineOf(profile);
    expect(written.skippedRuleIds).toContain("ATR-DRAFT-1");
    // It is not in expensiveRules, so flipping it back to active makes it a
    // not-in-baseline rule and it gets judged on its own merits.
    expect(written.expensiveRules).not.toHaveProperty("ATR-DRAFT-1");
  });

  it("warns when a new rule hides in an event type the corpus never emits", () => {
    // The measured blind spot: the same backtracking regex declared agent_trace
    // instead of llm_io ranks 670th of 671 because the engine skips it. Silence
    // would make that a discovery; a warning makes it a decision.
    const profile: Profile = {
      ...makeProfile({ "ATR-EXP-1": 12 }),
      unprofilableRuleIds: ["ATR-2026-00070", "ATR-2026-99999"],
    };
    const known: Baseline = { ...base, unprofilableRuleIds: ["ATR-2026-00070"] };
    const text = report(profile, known);
    expect(text).toContain("ATR-2026-99999");
    expect(text).not.toContain("? ATR-2026-00070");
    expect(verdict(profile, known)).toBe(0);
  });

  it("warns when rule files failed to parse or the tree was dirty mid-profile", () => {
    const profile: Profile = {
      ...makeProfile({ "ATR-EXP-1": 12 }),
      unparsedFiles: 3,
      dirtyRulePaths: ["?? rules/prompt-injection/ATR-2026-99668.yaml"],
    };
    const text = report(profile, base);
    expect(text).toContain("3 rule file(s) failed to parse");
    expect(text).toContain("uncommitted path(s) under rules/");
  });
});

// ---------------------------------------------------------------------------
// 8. Engine agreement -- what the profiler skips must match what the engine skips
// ---------------------------------------------------------------------------

describe("evaluability mirrors the engine", () => {
  const rule = (over: Partial<ATRRule>): ATRRule => ({ status: "experimental", maturity: "test", ...over }) as ATRRule;

  it.each([
    ["draft", false],
    ["deprecated", false],
    ["experimental", true],
    ["active", true],
  ])("status %s -> evaluable %s", (status, expected) => {
    expect(isEvaluable(rule({ status: status as ATRRule["status"] }))).toBe(expected);
  });

  it("skips maturity=deprecated, which the engine drops in every lane", () => {
    expect(isEvaluable(rule({ maturity: "deprecated" }))).toBe(false);
    expect(isEvaluable(rule({ maturity: "stable" }))).toBe(true);
  });

  it.each([
    ["llm_io", true],
    ["tool_call", true],
    ["mcp_exchange", true],
    ["multi_agent_comm", true],
    ["memory_access", false],
    ["context_window", false],
    ["skill_lifecycle", false],
  ])("source type %s -> exercised by the eval corpus: %s", (type, expected) => {
    expect(isCorpusCovered(rule({ agent_source: { type } } as Partial<ATRRule>))).toBe(expected);
  });

  it("treats a trace-method rule as unexercised whatever its source type says", () => {
    // sampleToEvent never sets event.trace, so the engine's traceWithPayload
    // branch cannot fire and the rule's primitives never run.
    expect(
      isCorpusCovered(rule({ agent_source: { type: "llm_io" }, detection: { method: "trace" } } as Partial<ATRRule>))
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 9. End to end -- real measurement over a fixture corpus
// ---------------------------------------------------------------------------

/**
 * A schema-valid rule whose single condition is a regex over the event content.
 * `(?:[a-z]+\s*){0,6}` is the construct isReDoSSafe() in src/engine.ts
 * explicitly permits -- a bounded outer quantifier around an unbounded inner
 * one -- and which measures 175ms against a single 61-character sample.
 */
function fixtureRule(id: string, pattern: string, sourceType = "llm_io"): string {
  return [
    `title: 'Latency fixture ${id}'`,
    `id: ${id}`,
    "rule_version: 1",
    "status: experimental",
    "description: 'Fixture rule used by tests/gate-rule-latency.test.ts.'",
    "author: 'ATR tests'",
    'date: "2026/08/03"',
    'schema_version: "0.1"',
    "detection_tier: pattern",
    "maturity: test",
    "severity: low",
    "tags:",
    "  category: prompt-injection",
    "  scan_target: both",
    "  confidence: low",
    "agent_source:",
    `  type: ${sourceType}`,
    "  framework: [any]",
    "  provider: [any]",
    "detection:",
    "  conditions:",
    "    - field: content",
    "      operator: regex",
    `      value: '${pattern}'`,
    "      description: 'fixture'",
    "  condition: any",
    "response:",
    "  actions: [alert]",
    `  message_template: '[${id}] fixture'`,
    "",
  ].join("\n");
}

describe("end to end over a fixture corpus", () => {
  it(
    "really measures a backtracking regex and names it",
    { timeout: 240_000 },
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "atr-latency-fixture-"));
      mkdirSync(join(dir, "prompt-injection"), { recursive: true });
      const write = (id: string, pattern: string, type?: string): void =>
        writeFileSync(join(dir, "prompt-injection", `${id}.yaml`), fixtureRule(id, pattern, type));

      try {
        // Five ordinary rules so the median is a real median, plus one whose
        // bounded outer quantifier wraps an unbounded inner one.
        write("ATR-2026-90001", "ignore\\s+previous\\s+instructions");
        write("ATR-2026-90002", "system\\s+prompt");
        write("ATR-2026-90003", "developer\\s+mode");
        write("ATR-2026-90004", "reveal\\s+your\\s+rules");
        write("ATR-2026-90005", "act\\s+as\\s+DAN");
        write("ATR-2026-90666", "^(?:[a-z]+\\s*){0,6}ZQXKFJ$");

        const profile = await buildProfile(dir);
        expect(profile.rules).toBe(6);
        expect(profile.samples).toBeGreaterThan(300);

        const costs = relativeCosts(profile);
        expect(costs[0]!.ruleId).toBe("ATR-2026-90666");
        // Measured at 50x-72x the median of these five trivial rules. Assert only
        // the floor the gate actually uses, so this does not quietly become a
        // machine-speed test.
        expect(costs[0]!.rel).toBeGreaterThan(FAIL_FLOOR);

        const result = renderGate(profile, costs, EMPTY_BASELINE);
        expect(result.exitCode).toBe(1);
        expect(result.lines.join("\n")).toContain("ATR-2026-90666");

        // ...and once accepted into a baseline, the same measurement passes.
        const accepted = baselineFrom(profile, costs);
        expect(verdict(profile, accepted)).toBe(0);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  );

  it("excludes rules this corpus cannot exercise instead of scoring them", { timeout: 240_000 }, async () => {
    // The honest half of the blind spot: the same pathological regex declared
    // under a source type the corpus never emits profiles at dispatch cost. It
    // must not enter the denominator as a fake cheap rule.
    const dir = mkdtempSync(join(tmpdir(), "atr-latency-uncovered-"));
    mkdirSync(join(dir, "prompt-injection"), { recursive: true });
    try {
      writeFileSync(
        join(dir, "prompt-injection", "ATR-2026-90201.yaml"),
        fixtureRule("ATR-2026-90201", "ignore\\s+previous")
      );
      writeFileSync(
        join(dir, "prompt-injection", "ATR-2026-90202.yaml"),
        fixtureRule("ATR-2026-90202", "^(?:[a-z]+\\s*){0,6}ZQXKFJ$", "memory_access")
      );

      const profile = await buildProfile(dir);
      expect(Object.keys(profile.costs)).toEqual(["ATR-2026-90201"]);
      expect(profile.unprofilableRuleIds).toEqual(["ATR-2026-90202"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("skips draft and deprecated rules the engine would never evaluate", { timeout: 240_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-latency-skip-"));
    mkdirSync(join(dir, "prompt-injection"), { recursive: true });
    try {
      writeFileSync(
        join(dir, "prompt-injection", "ATR-2026-90101.yaml"),
        fixtureRule("ATR-2026-90101", "ignore\\s+previous")
      );
      writeFileSync(
        join(dir, "prompt-injection", "ATR-2026-90102.yaml"),
        fixtureRule("ATR-2026-90102", "system\\s+prompt").replace("status: experimental", "status: draft")
      );

      const profile = await buildProfile(dir);
      expect(Object.keys(profile.costs)).toEqual(["ATR-2026-90101"]);
      expect(profile.skippedRuleIds).toEqual(["ATR-2026-90102"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// 10. The committed baseline, and the CLI entry point
// ---------------------------------------------------------------------------

describe("committed baseline", () => {
  const committed = parseBaseline(JSON.parse(readFileSync(COMMITTED_BASELINE_PATH, "utf8")), COMMITTED_BASELINE_PATH);

  /**
   * A synthetic profile whose membership is the committed anchor cohort, so the
   * CLI tests exercise the real baseline rather than a fixture. Costs are read
   * back out of the baseline itself, which keeps the fixture in step when the
   * baseline is regenerated -- the previous version hard-coded samples: 341 and
   * would have started returning exit 2 (corpus shrank) the day the eval corpus
   * grew and the baseline was refreshed.
   */
  function profileFromCommitted(extra: Record<string, number> = {}): Profile {
    const costs: Record<string, { ms: number; file: string }> = {};
    for (const id of committed.anchorRuleIds) {
      costs[id] = { ms: MEDIAN_MS * (committed.expensiveRules[id] ?? 1), file: `rules/committed/${id}.yaml` };
    }
    for (const [id, rel] of Object.entries(extra)) {
      costs[id] = { ms: MEDIAN_MS * rel, file: `rules/synthetic/${id}.yaml` };
    }
    return {
      ...makeProfile({}, 3, 1, committed.corpus.samples),
      rules: Object.keys(costs).length,
      costs,
      latencyShape: committed.latencyShape,
    };
  }

  it("records a cohort, a corpus and a shape that the gate can actually use", () => {
    expect(committed.anchorRuleIds.length).toBeGreaterThan(100);
    expect(committed.corpus.samples).toBeGreaterThan(300);
    expect(committed.latencyShape).toBeGreaterThan(1);
    expect(Object.keys(committed.expensiveRules).length).toBeGreaterThan(0);
    // Every recorded expensive rule is in the cohort it was measured against.
    for (const id of Object.keys(committed.expensiveRules)) {
      expect(committed.anchorRuleIds).toContain(id);
    }
  });

  it("passes the rules it recorded, at the costs it recorded", () => {
    expect(verdict(profileFromCommitted(), committed)).toBe(0);
  });

  it("still fails a pathological newcomer against the committed cohort", () => {
    expect(verdict(profileFromCommitted({ "ATR-SYN-500": 500 }), committed)).toBe(1);
  });
});

describe("CLI", () => {
  const committed = parseBaseline(JSON.parse(readFileSync(COMMITTED_BASELINE_PATH, "utf8")), COMMITTED_BASELINE_PATH);

  function runCli(args: readonly string[]): { status: number; out: string } {
    const result = spawnSync("npx", ["tsx", SCRIPT, ...args], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 240_000,
    });
    return { status: result.status ?? -1, out: `${result.stdout ?? ""}${result.stderr ?? ""}` };
  }

  function writeProfileFixture(profile: Profile): string {
    const dir = mkdtempSync(join(tmpdir(), "atr-latency-cli-"));
    const path = join(dir, "profile.json");
    writeFileSync(path, JSON.stringify(profile, null, 2));
    return path;
  }

  it("exits 1 and names the rule when a profile regresses", { timeout: 240_000 }, () => {
    const costs: Record<string, { ms: number; file: string }> = {};
    for (const id of committed.anchorRuleIds) {
      costs[id] = { ms: MEDIAN_MS * (committed.expensiveRules[id] ?? 1), file: `rules/committed/${id}.yaml` };
    }
    costs["ATR-SYN-500"] = { ms: MEDIAN_MS * 500, file: "rules/synthetic/ATR-SYN-500.yaml" };
    const profile: Profile = {
      ...makeProfile({}, 3, 1, committed.corpus.samples),
      rules: Object.keys(costs).length,
      costs,
      latencyShape: committed.latencyShape,
    };

    const { status, out } = runCli(["--profile", writeProfileFixture(profile)]);
    expect(status).toBe(1);
    expect(out).toContain("ATR-SYN-500");
    expect(out).toContain("Do NOT widen the baseline to silence this.");
  });

  it("exits 2 when it cannot run", { timeout: 240_000 }, () => {
    const { status, out } = runCli(["--profile", "/nonexistent/profile.json"]);
    expect(status).toBe(2);
    expect(out).toContain("could not run");
  });

  it("exits 2 on a flag missing its argument rather than silently ignoring it", { timeout: 240_000 }, () => {
    const { status } = runCli(["--profile"]);
    expect(status).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// 11. Comparison plumbing
// ---------------------------------------------------------------------------

describe("compareToBaseline", () => {
  it("separates added, worsened, improved and resolved", () => {
    const before = makeProfile({ "ATR-A": 20, "ATR-B": 16 });
    const base = baselineOf(before);
    const after = makeProfile({ "ATR-A": 20 * TOLERANCE + 1, "ATR-C": 30 });

    const comparison = compareToBaseline(relativeCosts(after, base), base);
    expect(comparison.worsened.map((r) => r.rule.ruleId)).toEqual(["ATR-A"]);
    expect(comparison.added.map((r) => r.rule.ruleId)).toEqual(["ATR-C"]);
    expect(comparison.resolved).toContain("ATR-B");
  });
});
