/**
 * ATR Quality Standard — Response-action eligibility
 *
 * The fifth axis of "clean must never mean never looked at it". The four before
 * it (fieldCoverage, statusCoverage, skillPathCoverage, wild-measurement) all
 * ask whether a rule's precision was ever measured. This one asks what a rule is
 * allowed to DO with the precision it actually demonstrated.
 *
 * THE DEFECT THIS MODULE EXISTS TO PREVENT
 *
 * `src/action-executor.ts` contains no maturity filter and no lane filter. Grep
 * it: the words `lane` and `maturity` do not appear. The lane gate in
 * `src/engine.ts` decides whether a rule may FIRE; once it has fired,
 * `computeVerdict()` unions `response.actions` across every match and the
 * executor runs all of them in priority order. So the lane named "alert" —
 * documented as the analyst/correlation lane — executes `kill_agent` exactly as
 * readily as the enforce lane does.
 *
 * Measured, not reasoned (see docs/RESPONSE-ACTION-ELIGIBILITY.md for the run):
 * ATR-2026-00062 is `maturity: test`, false-positives on 209 of 5,352 benign
 * samples (3.91%), and declares `kill_agent`. Driven through
 * `engine.evaluateWithVerdict()` at `lane: 'alert'` with a recording adapter and
 * a real benign corpus document, all five of its actions executed —
 * `kill_agent` first, because it has the highest executor priority.
 *
 * WHY THIS IS THE ONE ZERO-COST INTERVENTION
 *
 * Every other way to reduce false-positive damage costs recall. Tightening a
 * regex on this same rule set traded a 64-95% FP reduction for a 64-67% recall
 * loss. Removing an action a rule never earned costs exactly zero recall: the
 * rule still fires, still matches, still reports, still alerts. It just stops
 * destroying a session it was never shown to be right about.
 *
 * WHAT IT DOES NOT BUY (measured, so it cannot be overclaimed)
 *
 * `response.actions` feeds the ActionExecutor. It does NOT feed the hook
 * verdict: `src/verdict.ts` computeVerdict derives allow/ask/deny from severity
 * and confidence alone, and `toClaudeCodePreToolUse` maps that verdict to
 * `permissionDecision`. Stripping every action off a `severity: critical` rule
 * leaves `permissionDecision: deny` unchanged. This module governs executed
 * response actions, not the hook's block decision.
 *
 * THE LADDER
 *
 * Actions are ranked by blast radius — what survives the action, not how loud it
 * is. The ranking is deliberately NOT the executor's priority order, which
 * encodes urgency (kill_agent runs first so it cannot be pre-empted), not harm.
 *
 * @module agent-threat-rules/quality/action-eligibility
 */

import { createHash } from "node:crypto";

/** Blast-radius tiers, ascending. A rule may declare actions at or below its earned tier. */
export const ACTION_TIERS = Object.freeze({
  /** Nothing about the agent's execution changes. Pure observation and routing. */
  OBSERVE: 0,
  /** One operation is denied. The agent survives, retains state, and can retry. */
  INTERRUPT: 1,
  /** Session-wide state is altered for the remainder of the run. The agent survives, degraded. */
  DEGRADE: 2,
  /** The session or the agent is destroyed. Unrecoverable; in-flight work is lost. */
  TERMINATE: 3,
} as const);

export type ActionTier = (typeof ACTION_TIERS)[keyof typeof ACTION_TIERS];

/** Human-readable tier names, indexed by tier. */
export const TIER_NAMES: readonly string[] = Object.freeze([
  "observe",
  "interrupt",
  "degrade",
  "terminate",
]);

/**
 * Blast radius of every action the executor can dispatch.
 *
 * `escalate` sits at OBSERVE because `PlatformAdapter.escalate` routes to a
 * human; it changes who is watching, not what the agent may do. `reset_context`
 * sits at DEGRADE rather than TERMINATE because the agent process survives —
 * but it has lost its working memory for the rest of the session, which is not
 * a per-operation denial, so it does not belong at INTERRUPT either.
 */
const TIER_BY_ACTION: ReadonlyMap<string, ActionTier> = Object.freeze(
  new Map<string, ActionTier>([
    ["alert", ACTION_TIERS.OBSERVE],
    ["snapshot", ACTION_TIERS.OBSERVE],
    ["shadow", ACTION_TIERS.OBSERVE],
    ["escalate", ACTION_TIERS.OBSERVE],
    ["block_input", ACTION_TIERS.INTERRUPT],
    ["block_output", ACTION_TIERS.INTERRUPT],
    ["block_tool", ACTION_TIERS.INTERRUPT],
    ["reduce_permissions", ACTION_TIERS.DEGRADE],
    ["reset_context", ACTION_TIERS.DEGRADE],
    ["quarantine_session", ACTION_TIERS.TERMINATE],
    ["kill_agent", ACTION_TIERS.TERMINATE],
  ]),
);

/** Every action name this module assigns a tier to — the dispatchable set. */
export const TIERED_ACTIONS: readonly string[] = Object.freeze([
  ...TIER_BY_ACTION.keys(),
]);

/**
 * Blast-radius tier of an action name.
 *
 * An unrecognised action is OBSERVE, and that is safe rather than lenient:
 * `ACTION_METHOD_MAP` in src/action-executor.ts has no entry for it, so the
 * executor returns `Unknown action` without dispatching. Four such names are on
 * disk today (`require_human_review`, `quarantine_artifact`, `rate_limit_source`,
 * `log_alert`); they are inert, not destructive.
 */
export function actionTier(action: string): ActionTier {
  return TIER_BY_ACTION.get(action) ?? ACTION_TIERS.OBSERVE;
}

/** Highest blast-radius tier present in a list of actions. */
export function highestTier(actions: readonly string[]): ActionTier {
  return actions.reduce<ActionTier>(
    (max, a) => (actionTier(a) > max ? actionTier(a) : max),
    ACTION_TIERS.OBSERVE,
  );
}

/**
 * Percentage false-positive rate at or below which the published standard says a
 * rule is production-grade. docs/QUALITY-STANDARD.md, STABLE promotion criteria:
 * "Wild FP rate <= 0.5%". docs/proposals/001-atr-quality-standard-rfc.md §3
 * repeats it as a hard requirement for `stable`.
 */
export const STABLE_FP_CEILING_PCT = 0.5;

/**
 * Percentage false-positive rate at which the published standard withdraws
 * production status. docs/QUALITY-STANDARD.md, STABLE demotion criteria:
 * "Wild FP rate > 2% -> Automatic demotion". A rule the standard would demote
 * out of the blocking tier must not keep blocking actions while it sits there.
 */
export const DEMOTION_FP_PCT = 2.0;

/**
 * Stable fingerprint of everything that decides whether a rule fires.
 *
 * A false-positive count is a measurement OF a detection, not of a rule id. Edit
 * the conditions and the number on file describes a rule that no longer exists —
 * the same way a green CI run expires when the corpus or the measuring tool moves
 * underneath it. Consumers store this alongside the count and treat a mismatch as
 * "unmeasured", which by the policy below caps the rule at OBSERVE until someone
 * re-measures it.
 *
 * Keys are sorted recursively so that YAML reordering, which changes nothing the
 * engine sees, does not invalidate a measurement. `scan_target` is folded in
 * because it selects the skill-path compound gate and therefore changes which
 * inputs can reach the rule at all.
 */
export function detectionFingerprint(rule: {
  detection?: unknown;
  tags?: { scan_target?: unknown };
  agent_source?: { type?: unknown };
}): string {
  const canonical = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(canonical);
    if (v !== null && typeof v === "object") {
      const src = v as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(src).sort()) out[k] = canonical(src[k]);
      return out;
    }
    return v;
  };
  const payload = canonical({
    detection: rule.detection ?? null,
    scan_target: rule.tags?.scan_target ?? null,
    source_type: rule.agent_source?.type ?? null,
  });
  return createHash("sha256")
    .update(JSON.stringify(payload))
    .digest("hex")
    .slice(0, 16);
}

/** A false-positive measurement, or the explicit absence of one. */
export interface FpEvidence {
  /**
   * False positives observed. `undefined` means no measurement exists — which is
   * NOT the same as zero and must never be coerced to it (see wild-measurement.ts
   * for the `?? 0` collapse that put `wild_fp_rate: 0` on 230 never-measured rules).
   */
  readonly fpCount?: number;
  /** Benign samples the count was observed over. Required to interpret fpCount. */
  readonly sampleCount?: number;
  /**
   * True when the harness reported that some of the rule's declared conditions
   * could not be exercised at all (fieldCoverage / trace / behavioral). A partial
   * measurement bounds nothing, so it is treated as no measurement.
   */
  readonly partial?: boolean;
  /**
   * Maturity as recorded at measurement time. `stable` is the only maturity the
   * published ladder calls "safe for blocking actions in enterprise deployments"
   * (docs/QUALITY-STANDARD.md) and the only one the enforce lane admits.
   */
  readonly maturity?: string;
}

/** Why a given tier ceiling was assigned. Carried into rule YAML and gate output. */
export interface EligibilityDecision {
  readonly maxTier: ActionTier;
  readonly fpRatePct: number | null;
  readonly reason: string;
}

/**
 * True when a count and its denominator are both present and usable.
 *
 * Says nothing about completeness — `partial` is handled separately, because a
 * partial measurement that already found false positives is real evidence of
 * imprecision (the true rate can only be higher), while a partial measurement
 * that found none is evidence of nothing.
 */
export function hasCount(ev: FpEvidence): boolean {
  return (
    typeof ev.fpCount === "number" &&
    Number.isFinite(ev.fpCount) &&
    ev.fpCount >= 0 &&
    typeof ev.sampleCount === "number" &&
    Number.isFinite(ev.sampleCount) &&
    ev.sampleCount > 0
  );
}

/**
 * True when the evidence can support raising a rule above the observe tier.
 *
 * A partial run with zero hits cannot: the harness said out loud that it never
 * exercised some of the rule's conditions, so its silence is an unasked question,
 * not an answer. A partial run WITH hits can, and does — the hits happened.
 */
export function isMeasured(ev: FpEvidence): boolean {
  if (!hasCount(ev)) return false;
  return ev.partial !== true || (ev.fpCount as number) > 0;
}

/**
 * The policy: measured false-positive evidence -> highest action tier a rule may
 * declare.
 *
 * The two numeric lines are NOT chosen here. They are the two the project already
 * published, lifted unchanged:
 *
 *   <= 0.5%  the STABLE promotion ceiling (QUALITY-STANDARD.md, RFC-001 §3)
 *   >  2.0%  the STABLE automatic-demotion trigger (QUALITY-STANDARD.md)
 *
 * Mapping them onto blast radius:
 *
 *   no measurement        -> OBSERVE    absence of evidence is not evidence; a
 *                                       gate that cannot read a measurement must
 *                                       refuse, not pass. A PARTIAL run that found
 *                                       nothing lands here too — the harness said
 *                                       it never exercised some conditions, so its
 *                                       silence is an unasked question. A partial
 *                                       run that DID find hits is graded on them:
 *                                       the hits happened, and the true rate can
 *                                       only be higher
 *   > 2%                  -> OBSERVE    the standard's own demotion line: at this
 *                                       rate it would be pulled out of the
 *                                       blocking tier, so it does not keep
 *                                       blocking actions while it sits there
 *   0.5% - 2%             -> INTERRUPT  below the demotion line but above the
 *                                       production ceiling: a recoverable,
 *                                       per-operation denial is proportionate;
 *                                       session-wide state changes are not
 *   > 0 and <= 0.5%       -> DEGRADE    meets the production FP ceiling, yet
 *                                       demonstrably still wrong sometimes — a
 *                                       recoverable degradation is earned, an
 *                                       unrecoverable termination is not
 *   0 FP and maturity     -> TERMINATE  the only evidence level that earns an
 *   stable                              irreversible action; see below
 *
 * WHY TERMINATE NEEDS MORE THAN 0 FP ON THIS CORPUS
 *
 * Zero observed events in n trials does not mean zero rate. The rule of three
 * puts the 95% upper bound at 3/n: on 5,352 benign samples, a clean sweep only
 * certifies a true FP rate below roughly 0.056%. At an agent fleet's event
 * volume that is still a real number of destroyed sessions. The published ladder
 * already names the extra evidence needed to close that gap — `stable` requires
 * `wild_samples >= 1000`, `wild_fp_rate <= 0.5%`, `confidence >= 80` and two
 * maintainer approvals — and it is the same ladder that says STABLE is the tier
 * "safe for blocking actions in enterprise deployments" while EXPERIMENTAL is
 * "safe for evaluation and non-blocking alerting". So TERMINATE requires both: a
 * clean sweep of this corpus AND the maturity the standard reserves for
 * production blocking.
 */
export function maxTierFor(ev: FpEvidence): EligibilityDecision {
  if (!isMeasured(ev)) {
    return Object.freeze({
      maxTier: ACTION_TIERS.OBSERVE,
      fpRatePct: null,
      reason:
        ev.partial === true
          ? "0 FP but the measurement is incomplete — the harness reported conditions " +
            "it could not exercise, so the silence is an unasked question"
          : "no FP measurement on the benign corpus",
    });
  }

  const fp = ev.fpCount as number;
  const n = ev.sampleCount as number;
  const pct = (fp / n) * 100;
  const partialNote =
    ev.partial === true ? " (partial measurement — a lower bound)" : "";
  const shown = `${fp}/${n} = ${pct.toFixed(2)}%${partialNote}`;

  if (pct > DEMOTION_FP_PCT) {
    return Object.freeze({
      maxTier: ACTION_TIERS.OBSERVE,
      fpRatePct: pct,
      reason: `benign FP ${shown} exceeds the ${DEMOTION_FP_PCT}% automatic-demotion line`,
    });
  }
  if (pct > STABLE_FP_CEILING_PCT) {
    return Object.freeze({
      maxTier: ACTION_TIERS.INTERRUPT,
      fpRatePct: pct,
      reason: `benign FP ${shown} exceeds the ${STABLE_FP_CEILING_PCT}% production ceiling`,
    });
  }
  if (fp > 0) {
    return Object.freeze({
      maxTier: ACTION_TIERS.DEGRADE,
      fpRatePct: pct,
      reason: `benign FP ${shown} meets the ${STABLE_FP_CEILING_PCT}% ceiling but is not zero`,
    });
  }
  if (String(ev.maturity ?? "").trim() !== "stable") {
    return Object.freeze({
      maxTier: ACTION_TIERS.DEGRADE,
      fpRatePct: 0,
      reason: `0/${n} benign FP, but maturity is "${String(ev.maturity ?? "unset")}" — only stable is rated for irreversible actions`,
    });
  }
  return Object.freeze({
    maxTier: ACTION_TIERS.TERMINATE,
    fpRatePct: 0,
    reason: `0/${n} benign FP at maturity stable`,
  });
}

/** Actions in `actions` whose tier exceeds `maxTier`, in declaration order. */
export function ineligibleActions(
  actions: readonly string[],
  maxTier: ActionTier,
): readonly string[] {
  return Object.freeze(actions.filter((a) => actionTier(a) > maxTier));
}

/**
 * The eligible subset, order preserved.
 *
 * `alert` is appended when the filter would otherwise leave a rule with nothing
 * to do: a detection that reports nothing is worse than one that over-reports,
 * and OBSERVE-tier reporting is available at every evidence level by definition.
 */
export function eligibleActions(
  actions: readonly string[],
  maxTier: ActionTier,
): readonly string[] {
  const kept = actions.filter((a) => actionTier(a) <= maxTier);
  return Object.freeze(kept.length > 0 ? kept : ["alert"]);
}

/**
 * Content digest of the benign corpora a measurement was taken on.
 *
 * `detectionFingerprint` stops a rule drifting out from under its number. It
 * says nothing about the number, and the measurement file is committed — so in
 * review, editing `fp_count` from 2814 to 0 plus one `maturity` line handed a
 * rule that false-positives on 52.58% of the corpus a `kill_agent`, with the
 * whole suite still green. "Do not hand-edit" is a convention, not a control.
 *
 * This lives here, exported, so the producer and the gate cannot drift apart:
 * two copies of a hashing routine is exactly the shape of defect this policy
 * exists to close.
 *
 * WHAT THIS DOES NOT CLOSE, stated plainly because the gap is easy to miss:
 * editing `fp_count` does not touch the corpus, so the digest still matches and
 * the gate still passes. Verified by attack — 2814 -> 0 sails through. The
 * digest closes corpus drift (the measurement describing a corpus that has
 * since moved); it does nothing about number drift. Only regeneration closes
 * that, which is why .github/workflows/action-eligibility.yml re-measures on a
 * schedule and diffs the per-rule counts. Per-PR regeneration was considered
 * and rejected: 429 of 776 rules carry load-bearing numbers, so verifying them
 * is a full ~45-minute gate run, and a contributor cannot forge the file
 * without the scheduled diff surfacing it.
 */
export function corpusDigest(
  repoRoot: string,
  corpora: readonly string[],
  fs: {
    readonly existsSync: (p: string) => boolean;
    readonly readdirSync: (p: string) => string[];
    readonly statSync: (p: string) => { isDirectory(): boolean };
    readonly readFileSync: (p: string) => Buffer;
  },
  path: { readonly join: (...p: string[]) => string; readonly relative: (a: string, b: string) => string },
  createHash: (alg: string) => {
    update(d: string | Buffer): unknown;
    digest(enc: string): string;
  },
): string {
  const SEP = "\u0000";
  const walk = (dir: string): string[] => {
    const out: string[] = [];
    for (const e of [...fs.readdirSync(dir)].sort()) {
      const full = path.join(dir, e);
      if (fs.statSync(full).isDirectory()) out.push(...walk(full));
      else if (e.endsWith(".jsonl") || e.endsWith(".md")) out.push(full);
    }
    return out;
  };
  const h = createHash("sha256");
  for (const rel of [...corpora].sort()) {
    const dir = path.join(repoRoot, rel);
    if (!fs.existsSync(dir)) {
      h.update(rel + SEP + "MISSING" + SEP);
      continue;
    }
    for (const f of walk(dir)) {
      h.update(path.relative(repoRoot, f));
      h.update(SEP);
      h.update(fs.readFileSync(f));
      h.update(SEP);
    }
  }
  return h.digest("hex").slice(0, 32);
}

export const MEASUREMENT_CORPORA: readonly string[] = Object.freeze([
  "data/skill-benchmark/benign",
  "data/benign-corpus-extended",
  "data/benign-code",
]);
