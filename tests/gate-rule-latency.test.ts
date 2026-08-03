/**
 * Tests for the per-rule regex cost ratchet -- the metric and its verdicts.
 *
 * The parts that touch a real engine, a real git repository or the committed
 * baseline live in tests/gate-rule-latency-guards.test.ts; shared synthetic
 * profile builders live in tests/rule-latency-fixtures.ts.
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
 *  3. DOES NOT CRY WOLF. Cheap-rule jitter, which really does reach 2.46x
 *     between clean runs, never fails the build.
 *  4. BLAMES THE RIGHT CHANGE. A pull request fails only for rules its own diff
 *     touched. This gate's first CI run found ATR-2026-02300 at 288x, merged in
 *     #321; without scoping it would have reddened every unrelated rules PR from
 *     that moment on -- the same content-independent failure, sourced from a
 *     neighbour rather than from a busy runner.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import {
  median,
  profileMedianMs,
  anchorMedianMs,
  anchorCoverage,
  blameScope,
  splitByBlame,
  relativeCosts,
  compareToBaseline,
  checkShape,
  renderGate,
  baselineFrom,
  EMPTY_BASELINE,
  RECORD_FLOOR,
  FAIL_FLOOR,
  TOLERANCE,
  SHAPE_HIGH,
  ANCHOR_MIN_COVERAGE,
  type Profile,
} from "../scripts/gate-rule-latency.js";
import {
  BASE_SHAPE,
  MEDIAN_MS,
  baselineOf,
  makeProfile,
  onSlowerRunner,
  relOf,
  report,
  verdict,
  withNewRules,
  withoutRules,
} from "./rule-latency-fixtures.js";
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
// 11. Blame scoping -- a pull request must not go red for someone else's rule
// ---------------------------------------------------------------------------

describe("blame scoping", () => {
  const base = baselineOf(makeProfile({ "ATR-EXP-1": 12 }));
  // Two newcomers well above the floor: one the change introduced, one it inherited.
  const profile = makeProfile({ "ATR-EXP-1": 12, "ATR-MINE": 60, "ATR-THEIRS": 288 });

  it("fails only on the rule the diff touched", () => {
    const blame = new Set(["rules/synthetic/ATR-MINE.yaml"]);
    const result = renderGate(profile, relativeCosts(profile, base), base, blame);
    const text = result.lines.join("\n");

    expect(result.exitCode).toBe(1);
    expect(text).toContain("GATE FAIL");
    // The owned one is prosecuted...
    expect(text).toMatch(/GATE FAIL[\s\S]*ATR-MINE/);
    // ...and the inherited one is reported without being charged to this author.
    expect(text).toContain("PRE-EXISTING");
    expect(text).toContain("ATR-THEIRS");
    expect(text).not.toMatch(/GATE FAIL[\s\S]*ATR-THEIRS/);
  });

  it("passes a change that touched no rule, however bad the corpus already is", () => {
    // The measured case: this gate's first CI run found ATR-2026-02300 at 288x,
    // merged in #321. Without scoping, every later rules PR inherits that red --
    // the same content-independent failure the gate exists to remove.
    const result = renderGate(profile, relativeCosts(profile, base), base, new Set<string>());
    expect(result.exitCode).toBe(0);
    expect(result.lines.join("\n")).toContain("PRE-EXISTING");
  });

  it("judges the whole corpus when there is no scope (push to main, or fail-closed)", () => {
    expect(renderGate(profile, relativeCosts(profile, base), base, null).exitCode).toBe(1);
    expect(renderGate(profile, relativeCosts(profile, base), base).exitCode).toBe(1);
  });

  it("never lets blame scoping excuse an engine-wide shape blow-up", () => {
    // There is nobody to inherit one number from, and it has 2.5x of headroom.
    const blown: Profile = { ...profile, latencyShape: BASE_SHAPE * 5 };
    expect(renderGate(blown, relativeCosts(blown, base), base, new Set<string>()).exitCode).toBe(1);
  });

  it("splits regressions by file, not by rule id", () => {
    const regressions = [
      { rule: { ruleId: "A", file: "rules/x/a.yaml", ms: 1, rel: 20 }, reason: "" },
      { rule: { ruleId: "B", file: "rules/x/b.yaml", ms: 1, rel: 20 }, reason: "" },
    ];
    const split = splitByBlame(regressions, new Set(["rules/x/b.yaml"]));
    expect(split.owned.map((r) => r.rule.ruleId)).toEqual(["B"]);
    expect(split.inherited.map((r) => r.rule.ruleId)).toEqual(["A"]);
    expect(splitByBlame(regressions, null).owned).toHaveLength(2);
  });

  describe("blameScope over a real git repo", () => {
    function initRepo(): string {
      const dir = mkdtempSync(join(tmpdir(), "atr-latency-git-"));
      const git = (...args: string[]): void => {
        const r = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
        if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
      };
      git("init", "-q", "-b", "main");
      git("config", "user.email", "tests@example.invalid");
      git("config", "user.name", "ATR tests");
      mkdirSync(join(dir, "rules", "x"), { recursive: true });
      mkdirSync(join(dir, "src", "quality"), { recursive: true });
      writeFileSync(join(dir, "rules", "x", "base.yaml"), "seed\n");
      writeFileSync(join(dir, "src", "engine.ts"), "seed\n");
      writeFileSync(join(dir, "src", "quality", "rule-contract.ts"), "seed\n");
      git("add", "-A");
      git("commit", "-qm", "seed");
      git("branch", "baseline");
      return dir;
    }

    function commitInto(dir: string, files: Record<string, string>): void {
      for (const [path, body] of Object.entries(files)) writeFileSync(join(dir, path), body);
      spawnSync("git", ["add", "-A"], { cwd: dir });
      spawnSync("git", ["commit", "-qm", "change"], { cwd: dir });
    }

    it("returns the rule files a diff touched", () => {
      const dir = initRepo();
      try {
        commitInto(dir, { "rules/x/new.yaml": "new\n" });
        expect(blameScope("baseline", dir)).toEqual(new Set(["rules/x/new.yaml"]));
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it.each(["src/engine.ts", "src/quality/rule-contract.ts"])(
      "widens to the whole corpus when %s changed",
      (path) => {
        const dir = initRepo();
        try {
          commitInto(dir, { [path]: "changed\n", "rules/x/new.yaml": "new\n" });
          expect(blameScope("baseline", dir)).toBeNull();
        } finally {
          rmSync(dir, { recursive: true, force: true });
        }
      }
    );

    it("fails closed on an unresolvable base ref rather than excusing everything", () => {
      const dir = initRepo();
      try {
        expect(blameScope("no-such-ref", dir)).toBeNull();
        expect(blameScope("", dir)).toBeNull();
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("fails closed on an empty diff", () => {
      // Nothing changed, so nothing can be excused by "you did not touch it".
      const dir = initRepo();
      try {
        expect(blameScope("baseline", dir)).toBeNull();
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});

// ---------------------------------------------------------------------------
// 12. Accepted debt is restated, not buried in the baseline file
// ---------------------------------------------------------------------------

describe("accepted debt", () => {
  it("names every baselined rule still above the fail floor, on a passing run", () => {
    const profile = makeProfile({ "ATR-DEBT": 288, "ATR-OK": 2 });
    const base = baselineOf(profile);
    const result = renderGate(profile, relativeCosts(profile, base), base);

    expect(result.exitCode).toBe(0);
    const text = result.lines.join("\n");
    expect(text).toContain("ACCEPTED DEBT");
    expect(text).toContain("ATR-DEBT");
    expect(text).toContain("They are grandfathered.");
    expect(text).not.toContain("ATR-OK");
  });

  it("says nothing when the corpus carries none", () => {
    const profile = makeProfile({ "ATR-OK": 2 });
    expect(report(profile, baselineOf(profile))).not.toContain("ACCEPTED DEBT");
  });
});

// ---------------------------------------------------------------------------
// 13. Comparison plumbing
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
