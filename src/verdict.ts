/**
 * Verdict computation from ATR rule matches.
 *
 * Pure functions that determine the outcome (allow/ask/deny)
 * based on severity, confidence, and auto-response thresholds.
 *
 * @module agent-threat-rules/verdict
 */

import type {
  ATRMatch,
  ATRMatchDecider,
  ATRSeverity,
  ATRAction,
  ATRVerdict,
  VerdictOutcome,
} from './types.js';
import { ACTION_TIERS, actionTier } from './quality/action-eligibility.js';

/**
 * Decisions a model made rather than a rule's own logic: a semantic rule's
 * judge, the Tier 2.5 embedding signal, the Layer 3 semantic module. The
 * benign-corpus false-positive evidence measures none of them (it runs the
 * synchronous engine, where a semantic rule is its pattern fallback), so by
 * default they are reported and not enforced.
 */
const MODEL_DECIDERS: ReadonlySet<ATRMatchDecider> = new Set<ATRMatchDecider>([
  'semantic-judge',
  'embedding',
  'semantic-layer',
]);

/** Whether a model, not a rule's deterministic logic, decided this match. */
export function isModelDecided(match: Pick<ATRMatch, 'decidedBy'>): boolean {
  return match.decidedBy !== undefined && MODEL_DECIDERS.has(match.decidedBy);
}

/**
 * What a model-decided match may do.
 *   'advisory' (default): it is reported and its observe-tier actions run, but
 *     it takes no part in the outcome and its actions above observe are not
 *     dispatched.
 *   'enforce': it counts like any other match. Its false-positive rate has not
 *     been measured; choose this only if you accept that.
 */
export type ModelDecisions = 'advisory' | 'enforce';

export interface VerdictOptions {
  readonly modelDecisions?: ModelDecisions;
}

/** Read a modelDecisions setting, refusing anything but the two values. */
export function modelDecisionsFromConfig(value: unknown): ModelDecisions {
  if (value === undefined) return 'advisory';
  if (value === 'advisory' || value === 'enforce') return value;
  throw new TypeError(
    `modelDecisions must be 'advisory' or 'enforce', not ${JSON.stringify(value)}`,
  );
}

/** Severity rank from most severe (0) to least severe (4) */
export const SEVERITY_RANK: Readonly<Record<ATRSeverity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

/**
 * Minimum confidence at which a high-severity match denies; below it, asks.
 *
 * Compared as given. A confidence the engine derives from a rule's
 * `tags.confidence` label reaches this threshold only from a `high` label:
 * `src/rule-confidence.ts` caps every lower label one basis point under it.
 */
export const HIGH_SEVERITY_DENY_CONFIDENCE = 0.8;

/**
 * Minimum confidence at which a medium-severity match asks; below it, allows.
 * A `low` label reaches it exactly (0.6) when every condition matched.
 */
export const MEDIUM_SEVERITY_ASK_CONFIDENCE = 0.6;

/**
 * Check whether auto-response is enabled for a matched rule.
 * The auto_response_threshold field on ATRResponse indicates the
 * minimum confidence level at which the action should be taken
 * automatically (without human approval).
 */
export function isAutoResponseEnabled(
  match: ATRMatch
): boolean {
  const threshold = match.rule.response.auto_response_threshold;
  if (!threshold) return false;

  const thresholdMap: Record<string, number> = {
    high: 0.9,
    medium: 0.7,
    low: 0.5,
  };

  const requiredConfidence = thresholdMap[threshold];
  if (requiredConfidence === undefined) return false;

  return match.confidence >= requiredConfidence;
}

/**
 * Determine the verdict outcome based on severity and confidence.
 *
 * Decision matrix:
 *   - critical severity           -> deny
 *   - high severity, conf >= 0.8  -> deny
 *   - high severity, conf < 0.8   -> ask
 *   - medium severity, conf >= 0.6 -> ask
 *   - everything else             -> allow
 */
function determineOutcome(
  severity: ATRSeverity,
  confidence: number
): VerdictOutcome {
  if (severity === 'critical') {
    return 'deny';
  }
  if (severity === 'high') {
    return confidence >= HIGH_SEVERITY_DENY_CONFIDENCE ? 'deny' : 'ask';
  }
  if (severity === 'medium' && confidence >= MEDIUM_SEVERITY_ASK_CONFIDENCE) {
    return 'ask';
  }
  return 'allow';
}

/**
 * Collect unique actions from all matched rules, preserving order
 * of first appearance.
 */
function collectUniqueActions(
  matches: readonly ATRMatch[]
): readonly ATRAction[] {
  const seen = new Set<ATRAction>();
  const actions: ATRAction[] = [];

  for (const match of matches) {
    for (const action of match.rule.response.actions) {
      if (!seen.has(action)) {
        seen.add(action);
        actions.push(action);
      }
    }
  }

  return Object.freeze(actions);
}

/** The observe-tier actions of matches whose other actions are not dispatched. */
function observeActions(matches: readonly ATRMatch[]): readonly ATRAction[] {
  return collectUniqueActions(matches).filter((a) => actionTier(a) === ACTION_TIERS.OBSERVE);
}

/**
 * Build a human-readable reason string from the highest severity match.
 */
function buildReason(
  highestMatch: ATRMatch | undefined,
  outcome: VerdictOutcome,
  matchCount: number
): string {
  if (!highestMatch) {
    return 'No rules matched.';
  }

  const { rule, confidence } = highestMatch;
  const pct = Math.round(confidence * 100);

  return (
    `${outcome.toUpperCase()}: ${rule.title} ` +
    `[${rule.severity}/${pct}% confidence] ` +
    `(${matchCount} rule${matchCount === 1 ? '' : 's'} matched)`
  );
}

/**
 * Compute a verdict from an array of ATR matches.
 *
 * A match a model decided (isModelDecided) is reported but, unless
 * options.modelDecisions is 'enforce', takes no part in the outcome, and of its
 * actions only the observe tier is dispatched: no benign-corpus measurement
 * stands behind a model's decision. Every other match counts as before.
 *
 * This is a pure function -- no side effects, no mutation.
 * Returns a frozen ATRVerdict object.
 */
export function computeVerdict(
  matches: readonly ATRMatch[],
  options: VerdictOptions = {},
): ATRVerdict {
  const modelDecisions = modelDecisionsFromConfig(options.modelDecisions);
  const advisory = modelDecisions === 'advisory' ? matches.filter(isModelDecided) : [];
  const enforcing = advisory.length === 0 ? matches : matches.filter((m) => !isModelDecided(m));

  if (matches.length === 0) {
    return Object.freeze({
      outcome: 'allow' as const,
      reason: 'No rules matched.',
      matchCount: 0,
      highestSeverity: null,
      highestConfidence: 0,
      actions: Object.freeze([]),
      matches: Object.freeze([]),
      advisory: Object.freeze([]),
      timestamp: new Date().toISOString(),
    });
  }

  // Matches are already sorted by the engine (severity desc, confidence desc),
  // so the first enforcing match has the highest severity among them.
  const highestMatch = enforcing[0];
  const highestSeverity = highestMatch?.rule.severity ?? null;
  const highestConfidence = highestMatch?.confidence ?? 0;

  const outcome = highestMatch ? determineOutcome(highestMatch.rule.severity, highestMatch.confidence) : 'allow';
  const actions = Object.freeze([
    ...new Set([...collectUniqueActions(enforcing), ...observeActions(advisory)]),
  ]);
  const reason = highestMatch
    ? buildReason(highestMatch, outcome, matches.length) + advisoryNote(advisory.length)
    : `ALLOW: ${advisory.length} model-decided match${advisory.length === 1 ? '' : 'es'} ` +
      `reported, not enforced (modelDecisions: advisory).`;

  return Object.freeze({
    outcome,
    reason,
    matchCount: matches.length,
    highestSeverity,
    highestConfidence,
    actions,
    matches: Object.freeze([...matches]),
    advisory: Object.freeze([...advisory]),
    timestamp: new Date().toISOString(),
  });
}

function advisoryNote(count: number): string {
  return count === 0 ? '' : `; ${count} model-decided match${count === 1 ? '' : 'es'} reported, not enforced`;
}
