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
 * The load-bearing requirement is SPEC.md §5.5, which is engine-wide:
 * "Engines MUST NOT execute response actions automatically without an explicit
 * configuration directive from the operator." Until this module existed there
 * was no way for an operator to express that directive — no CLI flag, no
 * environment variable, no documented config key. This module IS that directive.
 *
 * Two weaker statements point the same way but must not be quoted as general
 * rules, because they are not:
 *   - spec/atr-method-v1.1.md §5.6 says "Engines SHOULD NOT auto-block ON A
 *     HASH MATCH without operator policy explicitly enabling it". That sits
 *     under §5 Signature Method and is scoped to hash matches. An earlier
 *     revision of this comment elided "on a hash match" and widened it into a
 *     general SHOULD NOT. It is not one.
 *   - docs/QUALITY-STANDARD.md restricts blocking to `maturity: stable` rules,
 *     but that section is deployment guidance addressed to consumers, not a
 *     normative engine requirement.
 *
 * WHY ATR NEVER SAYS "allow"
 *
 * In the Claude Code PreToolUse contract, `permissionDecision: "allow"` is not
 * neutral — it is an affirmative approval that suppresses the host's own
 * permission prompt. ATR emits a permission decision only to RESTRAIN an
 * operation (deny / ask). "No rule matched" is not "I approve this": it is ATR
 * having nothing to say, and the host must be left on its own default path.
 * This holds in BOTH modes — advisory omits every decision, and blocking omits
 * the affirmative one. See toClaudeCodePreToolUse in hook-handler.ts.
 *
 * WHO READS THE ENVIRONMENT
 *
 * For the lane and blocking switches: only the CLI. `resolveEnforcementPolicy`
 * below is the only function that reads `process.env` for THESE TWO switches,
 * and `src/cli.ts` is its only caller; it hands the resolved values to
 * ATREngine / ActionExecutor / HookHandler explicitly.
 *
 * Not "the only function in the package that touches process.env" — that is
 * false and an earlier revision of this comment said it. Ten files under src/
 * read the environment in code, including `adapters/openshell-filter.ts` and
 * `adapters/nemoclaw-preflight.ts`, which read `ATR_MIN_SEVERITY` and block by
 * default. Those adapters are outside this switch and stay that way; see the
 * scope limit in CHANGELOG.md.
 *
 * `grep -rl "process\.env" src/` returns eleven, not ten: `src/index.ts` only
 * names it in a comment. The correction above was itself first written as
 * "eleven" off that grep, which is the same mistake one level down.
 *
 * Library constructors take `laneFromConfig` / `blockingFromConfig`, which
 * cannot read the environment — `resolveLane` and `resolveBlocking` require an
 * EnvSource argument, so there is no overload that silently falls through to
 * `process.env`. This is structural, not a convention: an embedder cannot
 * accidentally opt into ambient configuration.
 *
 * The rule exists because ambient configuration crosses trust boundaries
 * invisibly. `new ATREngine()` inside a VS Code extension, a Mastra pipeline,
 * or the `/openshell-filter`, `/nemoclaw-preflight` and `/mcp` entry points did
 * not ask to be reconfigured by a shell profile — and `ATR_LANE=enforce` is a
 * VALID value, so the old behaviour produced no warning at all while narrowing
 * those callers to maturity=stable rules only.
 *
 * PRECEDENCE
 *
 *   library:  explicit config  >  built-in default
 *   CLI:      flag  >  environment variable  >  built-in default
 *
 * An invalid explicit value (config field or CLI flag) throws or exits: that is
 * the caller's own bug, reported where the caller is looking. An invalid
 * ENVIRONMENT value degrades loudly instead — see resolveEnforcementPolicy for
 * the measurement behind that split.
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
 *
 * Trimmed and case-INSENSITIVE, matching parseBooleanFlag exactly. The two were
 * asymmetric: `ATR_BLOCKING=ON` worked while `ATR_LANE=ENFORCE` did not, and the
 * pair `ATR_LANE=ENFORCE ATR_BLOCKING=ON` therefore turned blocking on while
 * silently widening the lane to hunt — the operator asked for the narrowest
 * enforcement posture and got the broadest one. The fallback direction was
 * exactly the dangerous one, so the fix is to accept the spelling, not to
 * document the trap.
 */
export function parseLane(value: string): Lane | null {
  const normalized = value.trim().toLowerCase();
  return LANE_SET.has(normalized) ? (normalized as Lane) : null;
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
 * `env` is REQUIRED and has no `process.env` default. That is the whole
 * mechanism keeping ambient configuration out of the library: a caller must
 * name the environment it wants read, and library constructors pass NO_ENV via
 * laneFromConfig. Only the CLI passes `process.env`.
 *
 * @throws TypeError when either source carries a value that is not a lane.
 */
export function resolveLane(
  explicit: Lane | string | undefined,
  env: EnvSource
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
 * `env` is REQUIRED — see resolveLane for why.
 *
 * @throws TypeError when the explicit value is not a boolean, or when the
 *         environment variable is set to a value that is neither truthy nor
 *         falsy by the table above.
 *
 *         The explicit-value check is not decoration. `blocking` crosses from
 *         untyped JavaScript (and from JSON config files) as often as from
 *         TypeScript, and every non-empty string is truthy: without this,
 *         `new ActionExecutor({ adapter, blocking: "false" })` TURNS BLOCKING
 *         ON while reading, to its author, as an explicit "off". The lane path
 *         validated its explicit value from the start; this one did not, and a
 *         switch that fails toward "more enforcement" is the wrong asymmetry to
 *         leave in place.
 */
export function resolveBlocking(
  explicit: boolean | undefined,
  env: EnvSource
): boolean {
  if (explicit !== undefined) {
    if (typeof explicit !== 'boolean') {
      throw new TypeError(
        `Invalid blocking value ${JSON.stringify(explicit)} (${typeof explicit}). ` +
          `Expected a boolean. Note that any non-empty string, including "false", ` +
          `would otherwise enable blocking.`
      );
    }
    return explicit;
  }

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
 * An environment that is empty by construction. Library constructors resolve
 * against this, so "the library does not read the environment" is enforced by
 * the type system rather than by reviewer vigilance.
 */
const NO_ENV: EnvSource = Object.freeze({});

/**
 * Lane for a LIBRARY caller: explicit config, or the built-in default. Never
 * reads the environment.
 *
 * @throws TypeError when the caller passes something that is not a lane.
 */
export function laneFromConfig(explicit?: Lane | string): Lane {
  return resolveLane(explicit, NO_ENV);
}

/**
 * Blocking for a LIBRARY caller: explicit config, or off. Never reads the
 * environment.
 *
 * @throws TypeError when the caller passes a non-boolean.
 */
export function blockingFromConfig(explicit?: boolean): boolean {
  return resolveBlocking(explicit, NO_ENV);
}

/** The enforcement posture a CLI process will run under. */
export interface EnforcementPolicy {
  readonly lane: Lane;
  readonly blocking: boolean;
  /** Human-readable problems found while resolving. Empty on a clean read. */
  readonly notes: readonly string[];
}

/**
 * Resolve the posture for a CLI process: flag > environment > default.
 *
 * THE ONLY FUNCTION IN THIS PACKAGE THAT READS `process.env`.
 *
 * A bad FLAG is a usage error the CLI reports and exits on (see readLaneOption
 * in cli.ts): it was typed by a person at a prompt who is looking at the exit
 * code. A bad ENVIRONMENT VALUE is different, and this function degrades
 * instead of throwing. That split was measured, not assumed.
 *
 * MEASUREMENT (Claude Code 2.1.76, hook dispatcher in the shipped binary)
 * A `command` hook's exit status is mapped as:
 *   status 0  -> `hook_success`; the renderer for that attachment returns null.
 *   status 2  -> `hook_blocking_error`; stderr is shown AND the tool is blocked.
 *   otherwise -> `hook_non_blocking_error`; the tool RUNS, the attachment maps
 *                to [] for the model, and the renderer prints exactly
 *                "<hookName> hook error" — the captured stderr is not shown.
 *
 * So for `atr guard`, which `atr init` installs as a PreToolUse command hook,
 * exiting non-zero over a typo would: lose all detection for that call, let the
 * tool run anyway, and tell the operator nothing beyond a bare "hook error".
 * It buys no visibility at the cost of the entire product. The only loud exit
 * status is 2 — which BLOCKS the tool, i.e. a stray shell variable would block
 * every tool call. Both alternatives are worse than degrading.
 *
 * THE TRADE-OFF, STATED
 * Degrading means an operator can believe enforcement is on when it is not.
 * That is a real cost and it is why `notes` is not optional: the caller must
 * print every note. It is accepted because the degraded posture is advisory —
 * ATR emits no permission decision and dispatches no action above OBSERVE — so
 * the failure mode is "ATR does not act", never "ATR acts wrongly". Exiting
 * would produce "ATR does not act" too, and silently, minus the detection.
 *
 * WHY AN UNREADABLE LANE ALSO FORCES BLOCKING OFF
 * Falling back to hunt while blocking is on is the one combination that makes
 * the degraded posture MORE dangerous than the requested one: the operator
 * asked to block on maturity=stable rules only, and would instead block on
 * every maturity including draft. So when the requested lane cannot be honoured
 * the process drops to advisory. An explicit `--blocking` does not override
 * this: the flag says "you may block", not "block on a lane I never chose".
 */
export function resolveEnforcementPolicy(
  flags: { readonly lane?: Lane | undefined; readonly blocking?: boolean | undefined } = {},
  env: EnvSource = process.env
): EnforcementPolicy {
  const notes: string[] = [];

  let lane: Lane;
  let laneHonoured = true;
  try {
    lane = resolveLane(flags.lane, env);
  } catch (error) {
    if (flags.lane !== undefined) throw error; // a flag is the caller's bug
    laneHonoured = false;
    lane = DEFAULT_LANE;
    notes.push(
      `${(error as Error).message} Falling back to lane "${DEFAULT_LANE}". ` +
        `Detection still runs; this only changes which maturities may fire.`
    );
  }

  let blocking: boolean;
  try {
    blocking = resolveBlocking(flags.blocking, env);
  } catch (error) {
    if (flags.blocking !== undefined) throw error;
    blocking = DEFAULT_BLOCKING;
    notes.push(
      `${(error as Error).message} Falling back to blocking=${DEFAULT_BLOCKING}. ` +
        `If you meant to enable enforcement, it is NOT enabled.`
    );
  }

  if (!laneHonoured && blocking) {
    blocking = false;
    notes.push(
      `Blocking disabled: ${LANE_ENV_VAR} could not be read, and blocking on the ` +
        `fallback lane "${DEFAULT_LANE}" would enforce on more rule maturities ` +
        `than you asked for. Fix ${LANE_ENV_VAR} to re-enable enforcement.`
    );
  }

  return Object.freeze({ lane, blocking, notes: Object.freeze(notes) });
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
