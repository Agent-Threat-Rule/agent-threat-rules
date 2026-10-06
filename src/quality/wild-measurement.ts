/**
 * ATR Quality Standard — Wild-validation measurement provenance
 *
 * The fourth axis of "clean must never mean never looked at it", after
 * fieldCoverage (src/corpus-event.ts), statusCoverage and skillPathCoverage.
 * Those three ask whether a corpus run could ever have exercised a rule. This
 * one asks the prior question: does a `wild_fp_rate` on disk correspond to a
 * measurement at all?
 *
 * THE DEFECT THIS MODULE EXISTS TO PREVENT
 *
 * scripts/compute-confidence.ts derived every rule's rate from a scan report:
 *
 *     const fireCount = ruleHitMap.get(baseMetadata.id) ?? 0;
 *     const wildFpRate = fireCount > 0 ? (fireCount / wildSampleCount) * 100 : 0;
 *
 * A scan report names the rules that FIRED. It does not name the rules it
 * loaded, so "absent from rule_hits" conflates two states that must never be
 * merged:
 *
 *   (a) the rule was evaluated against the corpus and stayed silent  -> 0% is real
 *   (b) the rule was never loaded, or could not reach the event shape -> no measurement
 *
 * The `?? 0` wrote (b) as if it were (a). ATR-2026-00061 is the worked example:
 * it carried `wild_fp_rate: 0` while firing on 2,814 of 5,352 benign samples
 * (52.58%). It was silent in the wild scan because that scan walked SKILL.md
 * bodies and the rule reads `tool_args`/`tool_response` — nobody ever populated
 * the fields it needs, so it could not fire, so it was scored as precise.
 *
 * WHY OMISSION AND NOT `null`
 *
 * `wild_fp_rate` is an input to gates that decide the enforce (auto-block) lane.
 * A gate that cannot read a measurement must refuse, not pass. Of the three
 * candidate encodings only omission actually refuses:
 *
 *   omitted -> wildFpRate === undefined -> validate-maturity blocks. Correct.
 *   null    -> `null === undefined` is false AND `null > 0.5` is false, so BOTH
 *              halves of the stable gate's disjunction are false and the rule
 *              promotes. `null` is indistinguishable from a perfect score.
 *   0       -> the bug this module removes.
 *
 * So "unmeasured" is encoded as the absence of the field, and isMeasuredFpRate()
 * below is the single predicate every consumer must use so that a future `null`,
 * `NaN` or `"0"` cannot re-open the same hole.
 *
 * @module agent-threat-rules/quality/wild-measurement
 */

/**
 * The fields that together form one wild-validation record.
 *
 * They are written and cleared as a unit. A rate without a sample count is not
 * interpretable (1 FP in 10 samples and 1 in 100,000 are not the same claim),
 * and a sample count without a rate still feeds the confidence score's wild
 * validation component, so a half-record inflates confidence just as a fake
 * rate inflated precision.
 */
export const WILD_MEASUREMENT_FIELDS: readonly string[] = Object.freeze([
  "wild_fp_rate",
  "wild_samples",
  "wild_validated",
]);

/** Largest meaningful false-positive rate, in percent. */
const MAX_FP_RATE = 100;

/**
 * True when a value is an actual measured false-positive rate.
 *
 * Deliberately narrow. Anything that is not a finite number in [0, 100] is
 * treated as "no measurement" — including `null`, `NaN`, `Infinity` and numeric
 * strings — because every one of those reaches a comparison like
 * `rate > threshold` as `false` and would silently pass a gate it never met.
 */
export function isMeasuredFpRate(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= MAX_FP_RATE
  );
}

/**
 * True when a value is an actual measured wild sample count: a finite,
 * non-negative integer. Same default-deny reasoning as isMeasuredFpRate.
 */
export function isMeasuredSampleCount(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

/**
 * Why this value cannot be treated as a measured rate — a sentence for a gate
 * to print — or null when it is measured and needs no explanation.
 */
export function unmeasuredFpReason(value: unknown): string | null {
  if (isMeasuredFpRate(value)) return null;
  if (value === undefined) {
    return (
      "wild_fp_rate is absent — no wild-validation run has reported this rule. " +
      "Absence is not 0%: it is the absence of a measurement, and a gate that " +
      "cannot read one must refuse rather than assume precision."
    );
  }
  return (
    `wild_fp_rate is ${JSON.stringify(value)}, which is not a finite ` +
    `percentage in [0, ${MAX_FP_RATE}] — treated as unmeasured. Encode an ` +
    "unmeasured rule by omitting the field, never by null or a placeholder."
  );
}

/** One rule's entry in a wild-scan report: it fired, this many times. */
export interface WildScanHit {
  readonly id: string;
  readonly count: number;
}

/**
 * What a scan report can say about one rule.
 *
 * `substantiated` is true ONLY when the report names the rule. A report lists
 * hits, not its loaded roster, so silence is unattributable by construction.
 */
export interface WildRateDerivation {
  readonly substantiated: boolean;
  /** The measured percentage, or null when the report cannot substantiate one. */
  readonly fpRate: number | null;
  readonly reason: string;
}

/**
 * Derive a rule's wild FP rate from a scan report's hit list — or refuse to.
 *
 * This is the corrected form of the `?? 0` at the top of this file. A rule the
 * report names fired, and the rate is real. A rule the report does not name may
 * have been clean, unloaded, or unreachable; the report cannot tell us which,
 * so no number is produced and the caller must leave the field off.
 *
 * @param hits - The report's rule_hits list
 * @param ruleId - The rule being scored
 * @param sampleCount - The report's total scanned count (the denominator)
 */
export function deriveWildFpRate(
  hits: readonly WildScanHit[],
  ruleId: string,
  sampleCount: number,
): WildRateDerivation {
  if (!isMeasuredSampleCount(sampleCount) || sampleCount <= 0) {
    return {
      substantiated: false,
      fpRate: null,
      reason: `scan report has no usable sample count (${JSON.stringify(sampleCount)})`,
    };
  }

  const hit = hits.find((h) => h.id === ruleId);
  if (hit === undefined) {
    return {
      substantiated: false,
      fpRate: null,
      reason:
        `rule is absent from the report's rule_hits list. The report records ` +
        `which rules fired, not which it loaded, so this is equally consistent ` +
        `with "evaluated and clean" and with "never evaluated" — it cannot ` +
        `substantiate 0%.`,
    };
  }

  const rate = (hit.count / sampleCount) * 100;
  return {
    substantiated: true,
    fpRate: Math.round(rate * 10000) / 10000,
    reason: `fired on ${hit.count} of ${sampleCount} samples`,
  };
}
