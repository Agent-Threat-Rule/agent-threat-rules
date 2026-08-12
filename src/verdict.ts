/**
 * Verdict computation from ATR rule matches.
 *
 * Pure functions that determine the outcome (allow/ask/deny)
 * based on severity, confidence, rule maturity, and auto-response thresholds.
 *
 * WHY MATURITY IS PART OF THE DECISION
 *
 * `src/engine.ts` gates which rules may FIRE via the lane filter
 * (`laneAllows(rule.maturity, config.lane ?? 'hunt')`), and `hunt` — the default,
 * the one every shipped caller actually runs — admits every maturity. Nothing in
 * the shipped code sets `lane: 'enforce'`. So before this module read maturity,
 * the path
 *
 *   hook-handler.evaluateAndRespond -> engine.evaluateWithVerdict -> computeVerdict
 *
 * turned a single `maturity: experimental` rule at `severity: critical` into
 * `permissionDecision: deny` — an auto-block issued on the authority of a rule
 * whose false-positive rate was never measured. The lane gate was the only
 * maturity check on that path and its default value switches it off.
 *
 * The ceiling below does not weaken detection: every match is still returned,
 * still counted, still reported. It withholds *blocking authority* from rules
 * that have not earned it, which is the one intervention that costs zero recall.
 *
 * SCOPE — what this module does NOT govern
 *
 * `verdict.actions` feeds the ActionExecutor, and blast-radius eligibility for
 * those actions is a separate, evidence-based policy that already exists:
 * `src/quality/action-eligibility.ts` (measured FP rate -> highest action tier a
 * rule may declare) applied to rule files by `scripts/downgrade-unearned-actions.ts`.
 * That ladder is strictly stronger than a maturity-only cap because it reads the
 * measurement rather than the label, so this module deliberately does not
 * reimplement a second, weaker copy of it here. The two are complementary:
 * eligibility governs what an action may DESTROY, this module governs what the
 * hook DECIDES.
 *
 * @module agent-threat-rules/verdict
 */

import { normalizeMaturity } from './quality/rule-contract.js';
import type { Maturity } from './quality/rule-contract.js';
import type {
  ATRMatch,
  ATRSeverity,
  ATRAction,
  ATRVerdict,
  VerdictOutcome,
} from './types.js';

/** Severity rank from most severe (0) to least severe (4) */
export const SEVERITY_RANK: Readonly<Record<ATRSeverity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

/**
 * How restrictive an outcome is. Higher = takes more authority away from the
 * agent. Used to fold per-rule outcomes together and to clamp against a ceiling.
 */
export const OUTCOME_STRICTNESS: Readonly<Record<VerdictOutcome, number>> = {
  allow: 0,
  ask: 1,
  deny: 2,
};

/**
 * The strictest outcome a rule of each maturity is allowed to produce.
 *
 * Three of these are lifted, not invented. docs/QUALITY-STANDARD.md defines
 * STABLE as "Safe for blocking actions in enterprise deployments", EXPERIMENTAL
 * as "Safe for evaluation and non-blocking alerting", and DRAFT as "Not
 * deployed. Draft rules are development artifacts only." Those three sentences
 * are the `deny` / `allow` / `allow` rows below; nothing here re-decides them.
 *
 * `test` is NOT in that published ladder — it exists only in
 * `src/quality/rule-contract.ts`, where `laneAllows` admits it to the `alert`
 * (analyst/correlation) lane but not to `enforce` (auto-block). `ask` is the
 * verdict-side reading of exactly that: it may put the decision in front of a
 * human, it may not make the decision itself.
 *
 * `deprecated` sits at `allow` because it is retired — `laneAllows` refuses it
 * in every lane — so if one ever reaches a verdict it must not be the blocker.
 */
const MATURITY_CEILING: Readonly<Record<Maturity, VerdictOutcome>> = {
  stable: 'deny',
  test: 'ask',
  experimental: 'allow',
  draft: 'allow',
  deprecated: 'allow',
};

/**
 * The strictest outcome this maturity may produce.
 *
 * Missing, empty, misspelled, or otherwise unrecognisable maturity resolves —
 * via `normalizeMaturity`, the single source of truth for the ladder — to
 * `experimental`, i.e. a ceiling of `allow`. "Cannot be determined" must never
 * be read as "may block": that direction is how a rule nobody ever measured
 * ends up issuing auto-blocks, and it is the precise defect this repo has spent
 * its recent history removing (`wild_fp_rate: 0` on 230 never-measured rules
 * came from the same `?? default-to-the-permissive-value` reflex).
 */
export function maturityCeiling(maturity: unknown): VerdictOutcome {
  return MATURITY_CEILING[normalizeMaturity(maturity)];
}

/** Return whichever of the two outcomes is more restrictive. */
function strictest(a: VerdictOutcome, b: VerdictOutcome): VerdictOutcome {
  return OUTCOME_STRICTNESS[a] >= OUTCOME_STRICTNESS[b] ? a : b;
}

/** Clamp an outcome so it is never stricter than the given ceiling. */
function clamp(outcome: VerdictOutcome, ceiling: VerdictOutcome): VerdictOutcome {
  return OUTCOME_STRICTNESS[outcome] <= OUTCOME_STRICTNESS[ceiling] ? outcome : ceiling;
}

/** Options that change how a verdict is computed. */
export interface VerdictOptions {
  /**
   * Escape hatch that restores the pre-maturity-ceiling behaviour exactly:
   * severity and confidence alone decide, and an unmeasured rule can `deny`.
   *
   * DEFAULT: `false` (the ceiling is applied).
   *
   * The default is the safe side in the sense that matters here. Turning the
   * ceiling ON cannot cause a missed detection — matches, counts, actions and
   * alerts are unchanged, only the auto-block is withheld — while turning it
   * OFF re-arms auto-blocking for the ~90% of critical-severity rules that are
   * not `maturity: stable`. A false block is the failure mode that gets a guard
   * uninstalled, and an uninstalled guard detects nothing at all. Downstream
   * consumers that deliberately want the old behaviour opt in explicitly and
   * therefore own the FP risk knowingly, which is the whole point of an
   * explicit flag over a silent default.
   */
  readonly denyIgnoresMaturity?: boolean;
}

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
    return confidence >= 0.8 ? 'deny' : 'ask';
  }
  if (severity === 'medium' && confidence >= 0.6) {
    return 'ask';
  }
  return 'allow';
}

/**
 * The outcome ONE match is allowed to produce, on its own authority.
 *
 * WHY THIS IS PER-MATCH AND NOT "highest severity, then cap"
 *
 * The obvious shortcut — take the highest-severity match as before, then clamp
 * that one by its own maturity — is wrong, and wrong in the dangerous
 * direction. Given an `experimental` + `critical` match alongside a `stable` +
 * `medium` one, the shortcut looks only at the experimental critical rule (it
 * sorts first), clamps it to `allow`, and returns `allow`: the unproven rule's
 * severity SUPPRESSES the proven rule's `ask`. A rule with less evidence would
 * be able to lower the verdict of a rule with more, purely by shouting louder.
 *
 * Each match therefore earns its own ceiling from its own maturity, and
 * `computeVerdict` folds the results by taking the most restrictive. Severity
 * and maturity belong to the same rule and must be read together; they are not
 * two independent knobs to be sampled from two different rules.
 */
export function outcomeForMatch(
  match: ATRMatch,
  options?: VerdictOptions
): VerdictOutcome {
  const raw = determineOutcome(match.rule.severity, match.confidence);
  if (options?.denyIgnoresMaturity === true) return raw;
  return clamp(raw, maturityCeiling(match.rule.maturity));
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

/**
 * Build a human-readable reason string from the match that decided the outcome.
 *
 * `capNote` is appended when the maturity ceiling lowered the verdict, so an
 * operator reading a log can tell "nothing severe matched" apart from "something
 * severe matched but was not trusted enough to block".
 */
function buildReason(
  decidingMatch: ATRMatch | undefined,
  outcome: VerdictOutcome,
  matchCount: number,
  capNote: string
): string {
  if (!decidingMatch) {
    return 'No rules matched.';
  }

  const { rule, confidence } = decidingMatch;
  const pct = Math.round(confidence * 100);

  return (
    `${outcome.toUpperCase()}: ${rule.title} ` +
    `[${rule.severity}/${pct}% confidence] ` +
    `(${matchCount} rule${matchCount === 1 ? '' : 's'} matched)` +
    capNote
  );
}

/**
 * Compute a verdict from an array of ATR matches.
 *
 * This is a pure function -- no side effects, no mutation.
 * Returns a frozen ATRVerdict object.
 *
 * `highestSeverity` / `highestConfidence` continue to describe the
 * highest-severity match (the engine sorts by severity desc, confidence desc).
 * `outcome` is the fold described on `outcomeForMatch`, which is a strict
 * generalisation: with `denyIgnoresMaturity: true` no match can out-rank the
 * first one, so the fold reproduces the old "matches[0] decides" behaviour
 * exactly.
 */
export function computeVerdict(
  matches: readonly ATRMatch[],
  options?: VerdictOptions
): ATRVerdict {
  if (matches.length === 0) {
    return Object.freeze({
      outcome: 'allow' as const,
      reason: 'No rules matched.',
      matchCount: 0,
      highestSeverity: null,
      highestConfidence: 0,
      actions: Object.freeze([]),
      matches: Object.freeze([]),
      timestamp: new Date().toISOString(),
    });
  }

  // Matches are already sorted by the engine (severity desc, confidence desc).
  // The first match has the highest severity.
  const highestMatch = matches[0]!;
  const highestSeverity = highestMatch.rule.severity;
  const highestConfidence = highestMatch.confidence;

  // Fold the per-rule outcomes, keeping the most restrictive. Ties keep the
  // earliest match, i.e. the highest-severity one, so the reason string still
  // names the most serious rule that actually justified the outcome.
  let decidingMatch = highestMatch;
  let outcome = outcomeForMatch(highestMatch, options);
  let uncapped = determineOutcome(highestSeverity, highestConfidence);

  for (let i = 1; i < matches.length; i++) {
    const match = matches[i]!;
    const candidate = outcomeForMatch(match, options);
    if (OUTCOME_STRICTNESS[candidate] > OUTCOME_STRICTNESS[outcome]) {
      outcome = candidate;
      decidingMatch = match;
    }
    uncapped = strictest(
      uncapped,
      determineOutcome(match.rule.severity, match.confidence)
    );
  }

  const capNote =
    outcome === uncapped
      ? ''
      : ` [maturity-capped from ${uncapped.toUpperCase()}: no matched rule is` +
        ` mature enough to ${uncapped === 'deny' ? 'block' : 'interrupt'}]`;

  const actions = collectUniqueActions(matches);
  const reason = buildReason(decidingMatch, outcome, matches.length, capNote);

  return Object.freeze({
    outcome,
    reason,
    matchCount: matches.length,
    highestSeverity,
    highestConfidence,
    actions,
    matches: Object.freeze([...matches]),
    timestamp: new Date().toISOString(),
  });
}
