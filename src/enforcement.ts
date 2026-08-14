/**
 * Enforcement policy — the two operator switches, and the one precedence rule
 * that governs both.
 *
 * ATR separates DETECTION from ENFORCEMENT. Detection always runs; enforcement
 * is what the engine is allowed to DO with a detection:
 *
 *   lane      Which rule maturities may fire at all.
 *             'enforce' = stable only, 'alert' = stable+test, 'hunt' = all.
 *             Implemented by the lane gate in engine.ts (see passesLane).
 *
 *   blocking  Whether ATR may express a blocking decision. OFF BY DEFAULT.
 *             When off: the Claude Code hook contract omits permissionDecision
 *             entirely (the host applies its own default — ATR does not vote),
 *             and the ActionExecutor refuses to dispatch any response action
 *             above the OBSERVE blast-radius tier. Detection output is
 *             unchanged in both modes.
 *
 * WHY BLOCKING IS OPT-IN
 *
 * spec/atr-method-v1.1.md:164 — "Engines SHOULD NOT auto-block ... without
 * operator policy explicitly enabling it". SPEC.md §5.5 — "Engines MUST NOT
 * execute response actions automatically without an explicit configuration
 * directive from the operator." docs/QUALITY-STANDARD.md restricts blocking to
 * `maturity: stable` rules. Until this module existed there was no way for an
 * operator to express that directive: no CLI flag, no environment variable, no
 * documented config key. This module IS that directive.
 *
 * WHY "NOT BLOCKING" IS NOT THE SAME AS "allow"
 *
 * In the Claude Code PreToolUse contract, `permissionDecision: "allow"` is not
 * neutral — it is an affirmative approval that suppresses the host's own
 * permission prompt. Downgrading a block to `allow` would make ATR *weaken* the
 * host's built-in safety. Advisory mode therefore omits the field rather than
 * setting it, so the host falls back to whatever it would have done with no
 * hook installed. See toClaudeCodePreToolUse in hook-handler.ts.
 *
 * PRECEDENCE (identical for both switches, deliberately explicit)
 *
 *     explicit programmatic config  >  environment variable  >  built-in default
 *
 * An explicit value always wins, so a host embedding the engine cannot have its
 * policy silently overridden by an environment variable it did not set. An
 * invalid value from either source throws instead of falling back: a typo in
 * ATR_LANE must never leave the operator believing they are in a lane they are
 * not.
 *
 * @module agent-threat-rules/enforcement
 */

import { LANES, type Lane } from './quality/rule-contract.js';
import { ACTION_TIERS, actionTier } from './quality/action-eligibility.js';

/** Environment variable naming the detection lane. */
export const LANE_ENV_VAR = 'ATR_LANE';

/** Environment variable enabling blocking (the operator directive). */
export const BLOCKING_ENV_VAR = 'ATR_BLOCKING';

/**
 * Lane used when neither config nor environment says otherwise.
 * 'hunt' keeps every maturity visible — advisory breadth, which is safe
 * precisely because blocking is off by default.
 */
export const DEFAULT_LANE: Lane = 'hunt';

/** Blocking is off until an operator turns it on. */
export const DEFAULT_BLOCKING = false;

const LANE_SET: ReadonlySet<string> = new Set(LANES);

const TRUE_VALUES: ReadonlySet<string> = new Set(['1', 'true', 'yes', 'on']);
const FALSE_VALUES: ReadonlySet<string> = new Set(['0', 'false', 'no', 'off']);

/** Minimal read-only view of an environment. Keeps this module testable. */
export type EnvSource = Readonly<Record<string, string | undefined>>;

/**
 * Parse a lane name. Returns null for anything not in LANES, so callers that
 * want to report a usage error (the CLI) can do so without a try/catch.
 */
export function parseLane(value: string): Lane | null {
  const trimmed = value.trim();
  return LANE_SET.has(trimmed) ? (trimmed as Lane) : null;
}

/**
 * Parse a boolean switch value. Returns null for anything unrecognised.
 * An empty string is treated as "not set" by the resolvers, not by this
 * function — it returns null here so the caller decides.
 */
export function parseBooleanFlag(value: string): boolean | null {
  const normalized = value.trim().toLowerCase();
  if (TRUE_VALUES.has(normalized)) return true;
  if (FALSE_VALUES.has(normalized)) return false;
  return null;
}

/**
 * Resolve the active detection lane: explicit > env > default.
 *
 * @throws TypeError when either source carries a value that is not a lane.
 */
export function resolveLane(
  explicit?: Lane | string,
  env: EnvSource = process.env
): Lane {
  if (explicit !== undefined) {
    const parsed = parseLane(explicit);
    if (parsed === null) {
      throw new TypeError(
        `Invalid lane "${explicit}". Expected one of: ${LANES.join(', ')}.`
      );
    }
    return parsed;
  }

  const fromEnv = env[LANE_ENV_VAR];
  if (fromEnv !== undefined && fromEnv.trim() !== '') {
    const parsed = parseLane(fromEnv);
    if (parsed === null) {
      throw new TypeError(
        `Invalid ${LANE_ENV_VAR}="${fromEnv}". Expected one of: ${LANES.join(', ')}.`
      );
    }
    return parsed;
  }

  return DEFAULT_LANE;
}

/**
 * Resolve whether blocking is enabled: explicit > env > default (false).
 *
 * @throws TypeError when the environment variable is set to a value that is
 *         neither truthy nor falsy by the table above. Silently reading
 *         `ATR_BLOCKING=enabled` as "off" would be the worst possible failure:
 *         an operator who believes enforcement is on while it is not.
 */
export function resolveBlocking(
  explicit?: boolean,
  env: EnvSource = process.env
): boolean {
  if (explicit !== undefined) return explicit;

  const fromEnv = env[BLOCKING_ENV_VAR];
  if (fromEnv !== undefined && fromEnv.trim() !== '') {
    const parsed = parseBooleanFlag(fromEnv);
    if (parsed === null) {
      throw new TypeError(
        `Invalid ${BLOCKING_ENV_VAR}="${fromEnv}". Expected one of: ` +
          `${[...TRUE_VALUES].join('/')} or ${[...FALSE_VALUES].join('/')}.`
      );
    }
    return parsed;
  }

  return DEFAULT_BLOCKING;
}

/**
 * Is this response action enforcement rather than observation?
 *
 * The observe/enforce split is NOT redefined here — it reads the blast-radius
 * ladder in src/quality/action-eligibility.ts, which is the project's single
 * ranking of what an action destroys. OBSERVE (alert / snapshot / shadow /
 * escalate) changes nothing about the agent's execution and therefore always
 * runs. Everything above it (INTERRUPT / DEGRADE / TERMINATE) denies an
 * operation, alters session state, or destroys the session — that is
 * enforcement and requires the operator directive.
 */
export function isEnforcementAction(action: string): boolean {
  return actionTier(action) > ACTION_TIERS.OBSERVE;
}
