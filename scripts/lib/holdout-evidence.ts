/**
 * holdout-evidence.ts — what a rule must show on holdout v1 to run in the
 * enforce lane, and the per-rule record that shows it.
 *
 * THE BAR
 *
 * docs/QUALITY-STANDARD.md sets STABLE at "wild FP rate <= 0.5%, measured on
 * >= 1,000 real samples", ">= 3 evasion tests", and (via scripts/gate-redos.py)
 * a 0.3 s backtracking budget. Those numbers are kept. What changes is where
 * the evidence comes from and how strictly it is read:
 *
 *   - FP is measured on holdout v1, a corpus no rule was written from and no
 *     merge gate uses, instead of the private wild corpus CI cannot reach.
 *   - The 0.5% is applied to the UPPER bound of the 95% Clopper-Pearson
 *     interval, not to the point estimate. 0 FP on 300 samples has a point
 *     estimate of 0% and an upper bound of 1.2%; it does not clear the bar.
 *   - A rule must also catch something: at least MIN_HOLDOUT_TP held-out
 *     attacks. A rule that fires on nothing has a perfect FP rate and no claim
 *     to a place in a lane whose job is to stop attacks.
 *
 * Nothing here decides a promotion. It produces the evidence and a verdict
 * against the bar; changing a rule's maturity stays a maintainer decision.
 */
import { rateWithCi, type RateWithCi } from "./binomial-ci.js";

export const ENFORCE_EVIDENCE_BAR = Object.freeze({
  /** QUALITY-STANDARD.md STABLE row, applied to the 95% upper bound. */
  maxFpRateUpper95: 0.005,
  /** QUALITY-STANDARD.md: "Measured on >= 1,000 real samples". */
  minBenignSamples: 1000,
  /** Held-out attacks the rule must detect. */
  minHoldoutTp: 3,
  /** QUALITY-STANDARD.md field table: evasion_tests >= 3 for STABLE. */
  minEvasionTests: 3,
  /** data/redos-baseline.json budget_seconds, in ms, for one 100,000-character field. */
  maxLongInputMs: 300,
});

export type EvidenceFailure =
  | "fp_upper_bound_above_bar"
  | "too_few_benign_samples"
  | "too_few_holdout_tp"
  | "too_few_evasion_tests"
  | "documented_evasion_contradicted"
  | "redos_baseline_entry"
  | "long_input_over_budget"
  | "unmeasurable_condition"
  | "embedding_confirm_dropped_in_enforce";

export interface RobustnessResult {
  /** Transform id. */
  readonly transform: string;
  /** Held-out true positives the transform was applied to. */
  readonly applied: number;
  /** Of those, still detected by this rule after the transform. */
  readonly retained: number;
}

export interface EvasionTestResult {
  readonly declared: number;
  /** Declared `expected: not_triggered` cases the rule now does trigger on. */
  readonly notTriggeredButTriggered: number;
  /** Declared `expected: triggered` cases the rule does not trigger on. */
  readonly triggeredButNotTriggered: number;
}

export interface RuleEvidenceInput {
  readonly id: string;
  readonly maturity: string;
  readonly severity: string;
  readonly tpIds: readonly string[];
  readonly fpIds: readonly string[];
  readonly attackN: number;
  readonly benignN: number;
  readonly tpBySlice: Readonly<Record<string, number>>;
  readonly fpBySlice: Readonly<Record<string, number>>;
  readonly evasion: EvasionTestResult;
  readonly robustness: readonly RobustnessResult[];
  readonly latency: { readonly p50: number; readonly p99: number; readonly max: number; readonly longInputMs: number };
  readonly redosBaselineEntries: readonly string[];
  readonly unmeasurableFields: readonly string[];
  readonly confirmEmbedding: boolean;
}

export interface RuleEvidence extends RuleEvidenceInput {
  readonly tp: RateWithCi;
  readonly fp: RateWithCi;
  readonly failures: readonly EvidenceFailure[];
  readonly meetsBar: boolean;
}

/** Why a rule does not meet the enforce bar. Empty when it does. */
export function evidenceFailures(e: RuleEvidenceInput, fp: RateWithCi): readonly EvidenceFailure[] {
  const bar = ENFORCE_EVIDENCE_BAR;
  const out: EvidenceFailure[] = [];
  if (e.benignN < bar.minBenignSamples) out.push("too_few_benign_samples");
  if (fp.ci95 === null || fp.ci95[1] > bar.maxFpRateUpper95) out.push("fp_upper_bound_above_bar");
  if (e.tpIds.length < bar.minHoldoutTp) out.push("too_few_holdout_tp");
  if (e.evasion.declared < bar.minEvasionTests) out.push("too_few_evasion_tests");
  if (e.evasion.triggeredButNotTriggered > 0) out.push("documented_evasion_contradicted");
  if (e.redosBaselineEntries.length > 0) out.push("redos_baseline_entry");
  if (e.latency.longInputMs > bar.maxLongInputMs) out.push("long_input_over_budget");
  if (e.unmeasurableFields.length > 0) out.push("unmeasurable_condition");
  if (e.confirmEmbedding) out.push("embedding_confirm_dropped_in_enforce");
  return Object.freeze(out);
}

export function ruleEvidence(e: RuleEvidenceInput): RuleEvidence {
  const tp = rateWithCi(e.tpIds.length, e.attackN);
  const fp = rateWithCi(e.fpIds.length, e.benignN);
  const failures = evidenceFailures(e, fp);
  return Object.freeze({ ...e, tp, fp, failures, meetsBar: failures.length === 0 });
}

/**
 * Failures a maintainer can clear without touching what the rule detects:
 * writing evasion tests from the measured bypasses. A rule whose only gap is
 * this is a promotion candidate pending those tests, not a demotion.
 */
export const DOCUMENTATION_ONLY: ReadonlySet<EvidenceFailure> = new Set(["too_few_evasion_tests"]);

export type Recommendation =
  | "keep"
  | "keep_after_evasion_tests"
  | "demote_fp"
  | "demote_no_holdout_tp"
  | "demote_cost"
  | "demote_unmeasurable"
  | "promote"
  | "promote_after_evasion_tests"
  | "stay";

/** What the evidence says to do with a rule. A proposal, never applied by this module. */
export function recommend(ev: RuleEvidence): Recommendation {
  const substantive = ev.failures.filter((f) => !DOCUMENTATION_ONLY.has(f));
  const stable = ev.maturity === "stable";
  if (substantive.length === 0) {
    if (stable) return ev.failures.length === 0 ? "keep" : "keep_after_evasion_tests";
    return ev.failures.length === 0 ? "promote" : "promote_after_evasion_tests";
  }
  if (!stable) return "stay";
  if (substantive.includes("fp_upper_bound_above_bar")) return "demote_fp";
  if (substantive.includes("redos_baseline_entry") || substantive.includes("long_input_over_budget")) return "demote_cost";
  if (substantive.includes("unmeasurable_condition") || substantive.includes("embedding_confirm_dropped_in_enforce")) {
    return "demote_unmeasurable";
  }
  return "demote_no_holdout_tp";
}

/** Nearest-rank percentile of a list of numbers; 0 for an empty list. */
export function percentile(values: readonly number[], q: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1));
  return sorted[rank]!;
}
