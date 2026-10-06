/**
 * ATR Quality Standard — Confidence Scoring
 *
 * Pure function implementing the RFC-001 §2 confidence formula:
 *
 *   confidence = round(
 *       precision_score    * 0.40
 *     + wild_validation    * 0.30
 *     + coverage_score     * 0.20
 *     + evasion_docs       * 0.10
 *   )
 *
 * @module agent-threat-rules/quality/compute-confidence
 */

import { isMeasuredFpRate, isMeasuredSampleCount } from "./wild-measurement.js";
import type {
  ConfidenceScore,
  DeploymentRecommendation,
  RuleMetadata,
} from "./types.js";

/** Max confidence an LLM-generated rule can reach without human review */
const LLM_CAP_WITHOUT_REVIEW = 70;

/**
 * Compute the confidence score for a rule.
 *
 * Score is in [0, 100]. Higher is more trustworthy.
 *
 * @param rule - Rule metadata (vendor-agnostic)
 * @returns Score breakdown and total
 */
export function computeConfidence(rule: RuleMetadata): ConfidenceScore {
  const precisionScore = computePrecisionScore(rule);
  const wildValidationScore = computeWildValidationScore(rule);
  const coverageScore = computeCoverageScore(rule);
  const evasionScore = computeEvasionScore(rule);

  const rawTotal =
    precisionScore * 0.4 +
    wildValidationScore * 0.3 +
    coverageScore * 0.2 +
    evasionScore * 0.1;

  let total = Math.round(rawTotal);
  let capped = false;

  // LLM-generated rules are capped at LLM_CAP_WITHOUT_REVIEW until a human reviews them.
  // Rationale: LLMs can produce subtly wrong rules that pass static validation
  // but fail in the wild. Human review is the only reliable backstop.
  if (rule.llmGenerated === true && rule.humanReviewed !== true) {
    if (total > LLM_CAP_WITHOUT_REVIEW) {
      total = LLM_CAP_WITHOUT_REVIEW;
      capped = true;
    }
  }

  return {
    total,
    precisionScore: Math.round(precisionScore),
    wildValidationScore: Math.round(wildValidationScore),
    coverageScore: Math.round(coverageScore),
    evasionScore: Math.round(evasionScore),
    capped,
  };
}

/**
 * Precision component (weight 0.40).
 *
 * If wild FP rate is measured, use it directly: (1 - fpRate/100) * 100.
 * Otherwise, estimate from test case coverage: more test cases = higher
 * confidence in precision (max at 10 total).
 */
function computePrecisionScore(rule: RuleMetadata): number {
  // Requires a real measurement on both axes. Under the old `!== undefined`
  // check a `wild_fp_rate: null` reached `Math.min(100, null)` as 0 and scored
  // a flat 100 — the maximum precision score, awarded for the absence of a
  // measurement. Unmeasured rules fall through to the test-case estimate below,
  // which is weaker and honest. See src/quality/wild-measurement.ts.
  if (
    isMeasuredFpRate(rule.wildFpRate) &&
    isMeasuredSampleCount(rule.wildSamples) &&
    rule.wildSamples > 0
  ) {
    return 100 - rule.wildFpRate;
  }
  // Fallback: estimate from test case depth
  const testCaseCount = rule.truePositives + rule.trueNegatives;
  return Math.min(testCaseCount / 10, 1) * 100;
}

/**
 * Wild validation component (weight 0.30).
 *
 * Scales with sample size up to 10,000 samples. More real-world data
 * = higher score. A rule tested on 0 samples gets 0. A rule tested on
 * 10,000+ samples gets 100.
 */
function computeWildValidationScore(rule: RuleMetadata): number {
  // `?? 0` would keep a null/NaN sample count out, but a numeric string would
  // reach Math.min as NaN and poison the score; the predicate is explicit.
  const samples = isMeasuredSampleCount(rule.wildSamples)
    ? rule.wildSamples
    : 0;
  return Math.min(samples / 10000, 1) * 100;
}

/**
 * Coverage component (weight 0.20).
 *
 * Scales with number of detection conditions (layers). A single-condition
 * rule gets 20. A 5+ condition rule gets 100. Defense in depth matters.
 */
function computeCoverageScore(rule: RuleMetadata): number {
  return Math.min(rule.conditions / 5, 1) * 100;
}

/**
 * Evasion documentation component (weight 0.10).
 *
 * Rewards honest acknowledgment of known bypasses. A rule with 0 evasion
 * tests gets 0. A rule with 5+ evasion tests gets 100.
 */
function computeEvasionScore(rule: RuleMetadata): number {
  return Math.min(rule.evasionTests / 5, 1) * 100;
}

/**
 * Map a confidence score to a deployment recommendation.
 *
 * This is the consumer-facing signal: "should I deploy this rule in
 * blocking mode, alert mode, or not at all?"
 */
export function deploymentFor(score: number): DeploymentRecommendation {
  if (score >= 90) return "block-in-production";
  if (score >= 80) return "block-with-monitoring";
  if (score >= 60) return "alert-only";
  if (score >= 40) return "evaluation-only";
  return "do-not-deploy";
}

/**
 * Apply the cross-context penalty to a match's contribution.
 *
 * When a rule designed for one scan context (e.g. MCP runtime) fires in
 * a different context (e.g. SKILL.md static scan), the match's contribution
 * is downweighted by 0.7. This prevents cross-context noise from inflating
 * overall detection confidence.
 *
 * @param score - The base confidence score of the rule
 * @param isCrossContext - True if the match is outside the rule's native context
 * @returns Adjusted score
 */
export function applyCrossContextPenalty(
  score: number,
  isCrossContext: boolean,
): number {
  return isCrossContext ? Math.round(score * 0.7) : score;
}
