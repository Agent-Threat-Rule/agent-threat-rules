/**
 * ATR Quality Standard — Maturity Promotion and Demotion
 *
 * Pure functions that decide whether a rule is eligible to promote to a
 * higher maturity level, or should be automatically demoted due to
 * quality regression.
 *
 * See docs/proposals/001-atr-quality-standard-rfc.md §1 for the gate
 * definitions.
 *
 * @module agent-threat-rules/quality/validate-maturity
 */

import { computeConfidence } from "./compute-confidence.js";
import { validateRuleMeetsStandard } from "./quality-gate.js";
import { isMeasuredFpRate, unmeasuredFpReason } from "./wild-measurement.js";
import type {
  DemotionDecision,
  FpReport,
  Maturity,
  PromotionDecision,
  RuleMetadata,
} from "./types.js";

/** Minimum days a rule must spend at experimental before promotion to stable */
const MIN_EXPERIMENTAL_DAYS = 14;
/** Minimum wild samples for stable promotion */
const MIN_WILD_SAMPLES_FOR_STABLE = 1000;
/** Maximum wild FP rate for stable promotion (percent) */
const MAX_WILD_FP_FOR_STABLE = 0.5;
/** Minimum confidence score for stable promotion */
const MIN_CONFIDENCE_FOR_STABLE = 80;
/** Wild FP rate that triggers automatic demotion from stable */
const DEMOTION_FP_RATE_THRESHOLD = 2.0;
/** Number of unresolved FP reports in the demotion window that trigger demotion */
const DEMOTION_FP_REPORT_COUNT = 3;
/** Demotion window in days */
const DEMOTION_WINDOW_DAYS = 30;

/**
 * Determine whether a rule is eligible to promote from its current maturity
 * to the next level.
 *
 * @param rule - Rule metadata
 * @param target - Target maturity level
 * @param now - Current timestamp (ISO string) for age calculations
 * @returns Promotion decision with blockers listed
 */
export function canPromote(
  rule: RuleMetadata,
  target: Maturity,
  now: string = new Date().toISOString(),
): PromotionDecision {
  const blockers: string[] = [];

  // Must pass the quality gate for the target level
  const gate = validateRuleMeetsStandard(rule, target);
  if (!gate.passed) {
    blockers.push(...gate.issues);
  }

  // Stable has additional wild validation + time-in-experimental gates
  if (target === "stable") {
    if (rule.maturity !== "experimental") {
      blockers.push(
        `rule must be at experimental to promote to stable (current: ${rule.maturity})`,
      );
    }

    if (
      rule.wildSamples === undefined ||
      rule.wildSamples < MIN_WILD_SAMPLES_FOR_STABLE
    ) {
      blockers.push(
        `wild_samples ${rule.wildSamples ?? 0} below threshold ${MIN_WILD_SAMPLES_FOR_STABLE}`,
      );
    }
    // Default-deny: an unmeasured rate is not a low one. stable IS the enforce
    // (auto-block) lane, so the absence of a measurement has to read as "not
    // eligible", never as "clean". isMeasuredFpRate also rejects null/NaN,
    // which would otherwise sail through `> MAX` as false. See
    // src/quality/wild-measurement.ts for why omission is the encoding.
    if (!isMeasuredFpRate(rule.wildFpRate)) {
      blockers.push(
        `wild_fp_rate unmeasured — ${unmeasuredFpReason(rule.wildFpRate)}`,
      );
    } else if (rule.wildFpRate > MAX_WILD_FP_FOR_STABLE) {
      blockers.push(
        `wild_fp_rate ${rule.wildFpRate}% above threshold ${MAX_WILD_FP_FOR_STABLE}%`,
      );
    }
    if (rule.wildValidatedAt) {
      const ageMs =
        new Date(now).getTime() - new Date(rule.wildValidatedAt).getTime();
      const ageDays = ageMs / (1000 * 60 * 60 * 24);
      if (ageDays < MIN_EXPERIMENTAL_DAYS) {
        blockers.push(
          `only ${Math.floor(ageDays)} days since wild validation (need ${MIN_EXPERIMENTAL_DAYS}+)`,
        );
      }
    } else {
      blockers.push("no wild_validated_at timestamp");
    }

    // Confidence must meet stable threshold
    const confidence = computeConfidence(rule);
    if (confidence.total < MIN_CONFIDENCE_FOR_STABLE) {
      blockers.push(
        `confidence ${confidence.total} below stable threshold ${MIN_CONFIDENCE_FOR_STABLE}`,
      );
    }
  }

  return {
    eligible: blockers.length === 0,
    to: target,
    blockers,
  };
}

/**
 * Determine whether a stable rule should be automatically demoted to
 * experimental due to quality regression.
 *
 * Triggers:
 *  - Wild FP rate exceeds DEMOTION_FP_RATE_THRESHOLD
 *  - DEMOTION_FP_REPORT_COUNT+ unresolved FP reports in the window
 *
 * @param rule - Rule metadata
 * @param recentFpReports - FP reports from the demotion window
 * @param now - Current timestamp (ISO string)
 * @returns Demotion decision
 */
export function shouldDemote(
  rule: RuleMetadata,
  recentFpReports: readonly FpReport[],
  now: string = new Date().toISOString(),
): DemotionDecision {
  const reasons: string[] = [];

  // Only stable rules are subject to automatic demotion
  if (rule.maturity !== "stable") {
    return { shouldDemote: false, reasons: [] };
  }

  // Reason 1: wild FP rate exceeds threshold.
  //
  // Note the asymmetry with canPromote, which is deliberate. Promotion is
  // default-DENY on an unmeasured rate: it must not grant the enforce lane on
  // a rate nobody took. Demotion is default-KEEP: it revokes on evidence of
  // harm, and an absent measurement is not evidence of harm. Making absence
  // demote would today evict all 106 maturity: stable rules, only 2 of which
  // carry a wild_fp_rate at all — a lane-wide policy change, not a bug fix.
  // The absence is surfaced instead by tests/wild-fp-provenance.test.ts.
  //
  // isMeasuredFpRate (not `!== undefined`) so null/NaN cannot suppress a
  // demotion by failing the `>` comparison.
  if (
    isMeasuredFpRate(rule.wildFpRate) &&
    rule.wildFpRate > DEMOTION_FP_RATE_THRESHOLD
  ) {
    reasons.push(
      `wild_fp_rate ${rule.wildFpRate}% exceeds demotion threshold ${DEMOTION_FP_RATE_THRESHOLD}%`,
    );
  }

  // Reason 2: unresolved FP reports in the demotion window
  const windowStart =
    new Date(now).getTime() - DEMOTION_WINDOW_DAYS * 24 * 60 * 60 * 1000;
  const unresolvedInWindow = recentFpReports.filter((r) => {
    if (r.resolved) return false;
    return new Date(r.reportedAt).getTime() >= windowStart;
  });
  if (unresolvedInWindow.length >= DEMOTION_FP_REPORT_COUNT) {
    reasons.push(
      `${unresolvedInWindow.length} unresolved FP reports in last ${DEMOTION_WINDOW_DAYS} days`,
    );
  }

  return {
    shouldDemote: reasons.length > 0,
    reasons,
  };
}

/**
 * Public accessor for the promotion/demotion thresholds.
 * Useful for documentation and UI that displays the gate policy.
 */
export function getMaturityThresholds(): {
  minExperimentalDays: number;
  minWildSamplesForStable: number;
  maxWildFpForStable: number;
  minConfidenceForStable: number;
  demotionFpRateThreshold: number;
  demotionFpReportCount: number;
  demotionWindowDays: number;
} {
  return {
    minExperimentalDays: MIN_EXPERIMENTAL_DAYS,
    minWildSamplesForStable: MIN_WILD_SAMPLES_FOR_STABLE,
    maxWildFpForStable: MAX_WILD_FP_FOR_STABLE,
    minConfidenceForStable: MIN_CONFIDENCE_FOR_STABLE,
    demotionFpRateThreshold: DEMOTION_FP_RATE_THRESHOLD,
    demotionFpReportCount: DEMOTION_FP_REPORT_COUNT,
    demotionWindowDays: DEMOTION_WINDOW_DAYS,
  };
}
