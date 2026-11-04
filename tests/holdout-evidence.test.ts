/**
 * Unit tests for the holdout evidence pipeline's arithmetic and verdicts:
 * scripts/lib/binomial-ci.ts and scripts/lib/holdout-evidence.ts.
 *
 * The intervals are checked against values computed independently
 * (scipy.stats.beta.ppf, the textbook Clopper-Pearson form), because a CI that
 * is quietly too narrow is exactly the overclaim this pipeline exists to stop.
 */
import { describe, it, expect } from "vitest";
import { binomialCdf, rateWithCi } from "../scripts/lib/binomial-ci.js";
import {
  ENFORCE_EVIDENCE_BAR,
  evidenceFailures,
  percentile,
  recommend,
  ruleEvidence,
  type RuleEvidenceInput,
} from "../scripts/lib/holdout-evidence.js";

describe("rateWithCi (Clopper-Pearson, 95%)", () => {
  it("matches scipy for 0/n, the case the rule of three describes", () => {
    const r = rateWithCi(0, 1000);
    expect(r.rate).toBe(0);
    expect(r.ci95![0]).toBe(0);
    // scipy.stats.beta.ppf(0.975, 1, 1000) = 0.0036821
    expect(r.ci95![1]).toBeCloseTo(0.0036821, 6);
  });

  it("matches scipy for an interior rate", () => {
    const r = rateWithCi(7, 466);
    // beta.ppf(0.025, 7, 460) = 0.0060602 ; beta.ppf(0.975, 8, 459) = 0.0307039
    expect(r.ci95![0]).toBeCloseTo(0.0060602, 6);
    expect(r.ci95![1]).toBeCloseTo(0.0307039, 6);
  });

  it("matches scipy for n/n", () => {
    const r = rateWithCi(32, 32);
    // beta.ppf(0.025, 32, 1) = 0.8911188
    expect(r.ci95![0]).toBeCloseTo(0.8911188, 6);
    expect(r.ci95![1]).toBe(1);
  });

  it("reports a rate over no samples as null, never 0", () => {
    expect(rateWithCi(0, 0)).toEqual({ k: 0, n: 0, rate: null, ci95: null });
  });

  it("refuses impossible counts", () => {
    expect(() => rateWithCi(3, 2)).toThrow();
    expect(() => rateWithCi(-1, 2)).toThrow();
    expect(() => rateWithCi(0.5, 2)).toThrow();
  });

  it("has a CDF that sums to 1", () => {
    expect(binomialCdf(10, 10, 0.3)).toBe(1);
    expect(binomialCdf(4, 10, 0.5)).toBeCloseTo(0.376953125, 9);
  });
});

function input(over: Partial<RuleEvidenceInput> = {}): RuleEvidenceInput {
  return {
    id: "ATR-2026-99999",
    maturity: "stable",
    severity: "high",
    tpIds: ["a1", "a2", "a3"],
    fpIds: [],
    attackN: 5000,
    benignN: 15000,
    tpBySlice: {},
    fpBySlice: {},
    evasion: { declared: 3, notTriggeredButTriggered: 0, triggeredButNotTriggered: 0 },
    robustness: [],
    latency: { p50: 0.1, p99: 1, max: 2, longInputMs: 10 },
    redosBaselineEntries: [],
    unmeasurableFields: [],
    confirmEmbedding: false,
    ...over,
  };
}

describe("evidence bar", () => {
  it("passes a rule with enough benign samples, 0 FP, 3 TP and 3 evasion tests", () => {
    const ev = ruleEvidence(input());
    expect(ev.failures).toEqual([]);
    expect(ev.meetsBar).toBe(true);
    expect(recommend(ev)).toBe("keep");
  });

  it("reads the 0.5% against the upper bound, not the point estimate", () => {
    // 0/600: point 0%, upper bound 0.61% -> fails.
    expect(evidenceFailures(input({ benignN: 600 }), rateWithCi(0, 600))).toContain("fp_upper_bound_above_bar");
    // 0/1000 is still below the sample floor even though its bound clears.
    expect(evidenceFailures(input({ benignN: 1000 }), rateWithCi(0, 1000))).not.toContain("fp_upper_bound_above_bar");
    // 50/15000: point 0.33%, upper bound 0.44% -> passes the rate bar.
    expect(evidenceFailures(input(), rateWithCi(50, 15000))).not.toContain("fp_upper_bound_above_bar");
    // 60/15000: point 0.40%, upper bound 0.51% -> fails.
    expect(evidenceFailures(input(), rateWithCi(60, 15000))).toContain("fp_upper_bound_above_bar");
  });

  it("demands that a rule catch something", () => {
    const ev = ruleEvidence(input({ tpIds: ["a1", "a2"] }));
    expect(ev.failures).toEqual(["too_few_holdout_tp"]);
    expect(recommend(ev)).toBe("demote_no_holdout_tp");
  });

  it("treats missing evasion tests as documentation, not as a reason to demote", () => {
    const ev = ruleEvidence(input({ evasion: { declared: 0, notTriggeredButTriggered: 0, triggeredButNotTriggered: 0 } }));
    expect(ev.failures).toEqual(["too_few_evasion_tests"]);
    expect(recommend(ev)).toBe("keep_after_evasion_tests");
    expect(recommend(ruleEvidence({ ...input({ maturity: "test" }), evasion: ev.evasion }))).toBe("promote_after_evasion_tests");
  });

  it("puts FP ahead of every other reason to demote", () => {
    const ev = ruleEvidence(input({ fpIds: Array.from({ length: 200 }, (_, i) => `b${i}`), redosBaselineEntries: ["x#0"] }));
    expect(recommend(ev)).toBe("demote_fp");
  });

  it("demotes a stable rule with a known backtracking condition or a slow long input", () => {
    expect(recommend(ruleEvidence(input({ redosBaselineEntries: ["ATR-2026-99999#0"] })))).toBe("demote_cost");
    const slow = input({ latency: { p50: 0, p99: 0, max: 0, longInputMs: ENFORCE_EVIDENCE_BAR.maxLongInputMs + 1 } });
    expect(recommend(ruleEvidence(slow))).toBe("demote_cost");
  });

  it("never recommends demoting a rule that is not in the enforce lane", () => {
    expect(recommend(ruleEvidence(input({ maturity: "test", tpIds: [] })))).toBe("stay");
  });

  it("counts a documented evasion that the rule now catches as harmless, the reverse as a failure", () => {
    const caught = input({ evasion: { declared: 3, notTriggeredButTriggered: 2, triggeredButNotTriggered: 0 } });
    expect(ruleEvidence(caught).failures).toEqual([]);
    const missed = input({ evasion: { declared: 3, notTriggeredButTriggered: 0, triggeredButNotTriggered: 1 } });
    expect(ruleEvidence(missed).failures).toEqual(["documented_evasion_contradicted"]);
  });
});

describe("percentile", () => {
  it("is nearest-rank", () => {
    expect(percentile([5, 1, 3, 2, 4], 0.5)).toBe(3);
    expect(percentile([5, 1, 3, 2, 4], 0.99)).toBe(5);
    expect(percentile([], 0.5)).toBe(0);
  });
});
