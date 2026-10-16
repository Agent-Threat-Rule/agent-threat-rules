/**
 * Confidence of a pattern or trace match, derived from the rule's
 * `tags.confidence` label and the share of its conditions that matched.
 *
 * Scored in basis points so the label bases, the coverage bonus and the
 * verdict thresholds are exact integers. In doubles 0.7 + 0.1 is
 * 0.7999999999999999: a `medium` rule with every condition matched used to
 * land one ulp under the high-severity deny threshold, and its verdict was
 * `ask` because of rounding rather than by rule. Computing the same quantity
 * as an integer percentage, or rounding it before comparing, gives 0.8 and
 * denies. tests/verdict-confidence-boundary.test.ts pins the semantics below.
 *
 * @module agent-threat-rules/rule-confidence
 */

import type { ATRConfidence } from './types.js';
import { HIGH_SEVERITY_DENY_CONFIDENCE } from './verdict.js';

const BASIS_POINTS = 10_000;

/** Base per label. Any other value, or none, scores as `low`. */
const LABEL_BASE_BP: Readonly<Record<ATRConfidence, number>> = {
  high: 9_000,
  medium: 7_000,
  low: 5_000,
};

/** Added in proportion to the share of the rule's conditions that matched. */
const COVERAGE_BONUS_MAX_BP = 1_000;

const DENY_BP = Math.round(HIGH_SEVERITY_DENY_CONFIDENCE * BASIS_POINTS);

/**
 * The label decides deny; coverage never carries a match into it. A label
 * whose base is below the high-severity deny threshold is capped one basis
 * point under it, so `medium` peaks at 0.7999 and never denies a high-severity
 * match on its own. Coverage still lifts `low` to exactly 0.6, the
 * medium-severity ask threshold, as it always has. The cap follows the
 * threshold: raised above 0.9, it would cap `high` too, and no label-scored
 * match would deny.
 *
 * Judge and embedding confidences do not come from here and are not capped.
 *
 * @param matchRatio matched conditions / total conditions; 0 for a trace match.
 *   Clamped to [0, 1]; a non-finite value counts as 0.
 */
export function ruleConfidence(label: ATRConfidence | undefined, matchRatio: number): number {
  const base = labelBaseBp(label);
  const ratio = Number.isFinite(matchRatio) ? Math.min(Math.max(matchRatio, 0), 1) : 0;
  const ceiling = base < DENY_BP ? DENY_BP - 1 : BASIS_POINTS;
  return Math.min(base + ratio * COVERAGE_BONUS_MAX_BP, ceiling) / BASIS_POINTS;
}

function labelBaseBp(label: ATRConfidence | undefined): number {
  return label === 'high' || label === 'medium' ? LABEL_BASE_BP[label] : LABEL_BASE_BP.low;
}
