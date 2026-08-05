import { describe, it, expect } from "vitest";
import {
  computeConfidence,
  deploymentFor,
  applyCrossContextPenalty,
} from "../../src/quality/compute-confidence.js";
import type { RuleMetadata } from "../../src/quality/types.js";

/** Minimal rule metadata for focused tests */
function rule(overrides: Partial<RuleMetadata> = {}): RuleMetadata {
  return {
    id: "TEST-001",
    title: "Test rule",
    maturity: "experimental",
    conditions: 1,
    truePositives: 0,
    trueNegatives: 0,
    evasionTests: 0,
    hasOwaspRef: false,
    hasMitreRef: false,
    hasFalsePositiveDocs: false,
    ...overrides,
  };
}

describe("computeConfidence", () => {
  describe("precision component (weight 0.40)", () => {
    it("returns 0 for a rule with no test cases and no wild data", () => {
      const score = computeConfidence(rule());
      expect(score.precisionScore).toBe(0);
    });

    it("scales precision score with test case count (max at 10)", () => {
      expect(
        computeConfidence(rule({ truePositives: 5, trueNegatives: 5 }))
          .precisionScore,
      ).toBe(100);
      expect(
        computeConfidence(rule({ truePositives: 3, trueNegatives: 2 }))
          .precisionScore,
      ).toBe(50);
      expect(
        computeConfidence(rule({ truePositives: 10, trueNegatives: 10 }))
          .precisionScore,
      ).toBe(100);
    });

    it("uses wild FP rate directly when measured", () => {
      // 0% FP rate = 100 precision
      expect(
        computeConfidence(rule({ wildSamples: 1000, wildFpRate: 0 }))
          .precisionScore,
      ).toBe(100);
      // 5% FP rate = 95 precision
      expect(
        computeConfidence(rule({ wildSamples: 1000, wildFpRate: 5 }))
          .precisionScore,
      ).toBe(95);
      // 50% FP rate = 50 precision
      expect(
        computeConfidence(rule({ wildSamples: 1000, wildFpRate: 50 }))
          .precisionScore,
      ).toBe(50);
    });

    it("treats an out-of-range FP rate as unmeasured, not as a clamped one", () => {
      // BEHAVIOUR CHANGE (see src/quality/wild-measurement.ts).
      //
      // This used to clamp: `Math.max(0, Math.min(100, rule.wildFpRate))`, so
      // wildFpRate: -5 became 0 and scored 100 — a corrupt value earning the
      // MAXIMUM precision score. That is the same failure this module exists to
      // close, one layer down: a number the code cannot interpret must not be
      // read as evidence of precision.
      //
      // A rate outside [0, 100] is not a measurement, so the score now falls
      // back to the honest test-case estimate. With this fixture's 0 test cases
      // that estimate is 0 for both directions.
      expect(
        computeConfidence(rule({ wildSamples: 1000, wildFpRate: -5 }))
          .precisionScore,
      ).toBe(0);
      expect(
        computeConfidence(rule({ wildSamples: 1000, wildFpRate: 150 }))
          .precisionScore,
      ).toBe(0);
      // ...and the fallback really is the test-case estimate, not a hard 0.
      expect(
        computeConfidence(
          rule({
            wildSamples: 1000,
            wildFpRate: -5,
            truePositives: 5,
            trueNegatives: 5,
          }),
        ).precisionScore,
      ).toBe(100);
    });
  });

  describe("wild validation component (weight 0.30)", () => {
    it("returns 0 when wildSamples is undefined", () => {
      expect(computeConfidence(rule()).wildValidationScore).toBe(0);
    });

    it("scales with sample count (max at 10,000)", () => {
      expect(
        computeConfidence(rule({ wildSamples: 0 })).wildValidationScore,
      ).toBe(0);
      expect(
        computeConfidence(rule({ wildSamples: 5000 })).wildValidationScore,
      ).toBe(50);
      expect(
        computeConfidence(rule({ wildSamples: 10000 })).wildValidationScore,
      ).toBe(100);
      expect(
        computeConfidence(rule({ wildSamples: 100000 })).wildValidationScore,
      ).toBe(100);
    });
  });

  describe("coverage component (weight 0.20)", () => {
    it("scales with condition count (max at 5)", () => {
      expect(computeConfidence(rule({ conditions: 0 })).coverageScore).toBe(0);
      expect(computeConfidence(rule({ conditions: 1 })).coverageScore).toBe(20);
      expect(computeConfidence(rule({ conditions: 3 })).coverageScore).toBe(60);
      expect(computeConfidence(rule({ conditions: 5 })).coverageScore).toBe(
        100,
      );
      expect(computeConfidence(rule({ conditions: 15 })).coverageScore).toBe(
        100,
      );
    });
  });

  describe("evasion docs component (weight 0.10)", () => {
    it("scales with evasion test count (max at 5)", () => {
      expect(computeConfidence(rule({ evasionTests: 0 })).evasionScore).toBe(0);
      expect(computeConfidence(rule({ evasionTests: 3 })).evasionScore).toBe(
        60,
      );
      expect(computeConfidence(rule({ evasionTests: 5 })).evasionScore).toBe(
        100,
      );
      expect(computeConfidence(rule({ evasionTests: 10 })).evasionScore).toBe(
        100,
      );
    });
  });

  describe("total score", () => {
    it("applies weights correctly for a fully-loaded rule", () => {
      const score = computeConfidence(
        rule({
          conditions: 5,
          truePositives: 5,
          trueNegatives: 5,
          evasionTests: 5,
          wildSamples: 10000,
          wildFpRate: 0,
        }),
      );
      // 100 * 0.4 + 100 * 0.3 + 100 * 0.2 + 100 * 0.1 = 100
      expect(score.total).toBe(100);
    });

    it("gives a bare-minimum rule a low score", () => {
      const score = computeConfidence(
        rule({
          conditions: 1,
          truePositives: 1,
          trueNegatives: 1,
          evasionTests: 0,
          wildSamples: 0,
        }),
      );
      // precision: 20 * 0.4 = 8
      // wild: 0 * 0.3 = 0
      // coverage: 20 * 0.2 = 4
      // evasion: 0 * 0.1 = 0
      // total: 12
      expect(score.total).toBe(12);
    });

    it("rounds to integer", () => {
      const score = computeConfidence(
        rule({ conditions: 2, truePositives: 3, trueNegatives: 2 }),
      );
      expect(Number.isInteger(score.total)).toBe(true);
    });
  });

  describe("LLM cap", () => {
    it("caps LLM-generated rules at 70 without human review", () => {
      const highScoringLlmRule = rule({
        conditions: 5,
        truePositives: 5,
        trueNegatives: 5,
        evasionTests: 5,
        wildSamples: 10000,
        wildFpRate: 0,
        llmGenerated: true,
      });
      const score = computeConfidence(highScoringLlmRule);
      expect(score.total).toBe(70);
      expect(score.capped).toBe(true);
    });

    it("does not cap LLM-generated rules after human review", () => {
      const score = computeConfidence(
        rule({
          conditions: 5,
          truePositives: 5,
          trueNegatives: 5,
          evasionTests: 5,
          wildSamples: 10000,
          wildFpRate: 0,
          llmGenerated: true,
          humanReviewed: true,
        }),
      );
      expect(score.total).toBe(100);
      expect(score.capped).toBe(false);
    });

    it("does not cap human-authored rules", () => {
      const score = computeConfidence(
        rule({
          conditions: 5,
          truePositives: 5,
          trueNegatives: 5,
          evasionTests: 5,
          wildSamples: 10000,
          wildFpRate: 0,
          // llmGenerated not set
        }),
      );
      expect(score.total).toBe(100);
      expect(score.capped).toBe(false);
    });

    it("does not cap LLM rules that already score below 70", () => {
      const score = computeConfidence(
        rule({
          conditions: 2,
          truePositives: 3,
          trueNegatives: 2,
          llmGenerated: true,
        }),
      );
      expect(score.capped).toBe(false);
      expect(score.total).toBeLessThan(70);
    });
  });
});

describe("deploymentFor", () => {
  it("maps score bands to deployment recommendations", () => {
    expect(deploymentFor(100)).toBe("block-in-production");
    expect(deploymentFor(90)).toBe("block-in-production");
    expect(deploymentFor(89)).toBe("block-with-monitoring");
    expect(deploymentFor(80)).toBe("block-with-monitoring");
    expect(deploymentFor(79)).toBe("alert-only");
    expect(deploymentFor(60)).toBe("alert-only");
    expect(deploymentFor(59)).toBe("evaluation-only");
    expect(deploymentFor(40)).toBe("evaluation-only");
    expect(deploymentFor(39)).toBe("do-not-deploy");
    expect(deploymentFor(0)).toBe("do-not-deploy");
  });
});

describe("applyCrossContextPenalty", () => {
  it("returns the same score for native context", () => {
    expect(applyCrossContextPenalty(100, false)).toBe(100);
    expect(applyCrossContextPenalty(85, false)).toBe(85);
  });

  it("multiplies by 0.7 for cross-context", () => {
    expect(applyCrossContextPenalty(100, true)).toBe(70);
    expect(applyCrossContextPenalty(90, true)).toBe(63);
  });

  it("rounds to integer", () => {
    // 85 * 0.7 = 59.4999... due to IEEE754, rounds to 59
    expect(applyCrossContextPenalty(85, true)).toBe(59);
    // 80 * 0.7 = 56 exactly
    expect(applyCrossContextPenalty(80, true)).toBe(56);
  });
});
