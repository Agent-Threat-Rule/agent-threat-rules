/**
 * ATR Quality Standard — Quality Gate
 *
 * Checks whether a rule meets the minimum quality bar for a target maturity
 * level. Used by TC crystallization pipeline to reject weak LLM-generated
 * rules before they enter the proposal pipeline.
 *
 * See docs/proposals/001-atr-quality-standard-rfc.md §3 for the required
 * metadata matrix.
 *
 * @module agent-threat-rules/quality/quality-gate
 */

import { isMeasuredFpRate, isMeasuredSampleCount } from "./wild-measurement.js";
import type {
  Maturity,
  Provenance,
  QualityGateResult,
  RuleMetadata,
} from "./types.js";

/**
 * Minimum requirements for each maturity level.
 *
 * RFC-001 v1.1 (effective 2026-04-12) splits the quality bar:
 * - experimental: 3/3/0 — low barrier for community contribution. OWASP,
 *   MITRE, evasion tests, and FP docs are encouraged but NOT required.
 *   The upgrade pipeline adds these during promotion to stable.
 * - stable: 5/5/3 — production-quality bar with verified provenance,
 *   OWASP + MITRE mapping, evasion tests, and wild validation.
 *
 * Rationale: VirusTotal doesn't reject "low quality" samples — everything
 * gets in. Sigma experimental is loose. A strict experimental gate kills
 * community contribution velocity. Data velocity > data purity at scale.
 *
 * See docs/proposals/001-atr-quality-standard-rfc.md §1 and §3.
 */
const REQUIREMENTS = {
  draft: {
    minConditions: 1,
    minTruePositives: 1,
    minTrueNegatives: 1,
    minEvasionTests: 0,
    requireOwasp: false,
    requireMitre: false,
    requireFalsePositiveDocs: false,
    requireHumanReviewedProvenance: false,
  },
  experimental: {
    minConditions: 1,
    minTruePositives: 3, // RFC-001 v1.1: lowered for community contribution velocity
    minTrueNegatives: 3,
    minEvasionTests: 0, // encouraged but not required — pipeline adds during upgrade
    requireOwasp: false, // pipeline adds during promotion to stable
    requireMitre: false, // pipeline adds during promotion to stable
    requireFalsePositiveDocs: false, // pipeline adds during promotion to stable
    requireHumanReviewedProvenance: false,
  },
  stable: {
    minConditions: 3,
    minTruePositives: 5,
    minTrueNegatives: 5,
    minEvasionTests: 3, // hard requirement
    requireOwasp: true,
    requireMitre: true,
    requireFalsePositiveDocs: true,
    requireHumanReviewedProvenance: true, // stable demands verified provenance
  },
} as const;

/**
 * RFC-001 v1.1 §1.1 — Single-Pattern Rule Exception threshold.
 *
 * A rule with fewer than `minConditions` for its target maturity level
 * is still accepted if it has been validated against at least this many
 * real-world samples with a measured false-positive rate of exactly 0.
 * Set to the size of the most recent ATR mega scan as of effective date,
 * which is the empirical evidence baseline the standard authors used.
 */
export const SINGLE_PATTERN_EXCEPTION_MIN_SAMPLES = 50_000;

/** Provenance values that count as "verified" for stable promotion */
const VERIFIED_PROVENANCE: readonly Provenance[] = [
  "human-reviewed",
  "community-contributed",
];

/**
 * Validate a rule against the quality bar for a target maturity level.
 *
 * @param rule - Rule metadata
 * @param target - Target maturity level to validate against (default: rule.maturity)
 * @returns Gate result with passed/failed and human-readable issues
 */
export function validateRuleMeetsStandard(
  rule: RuleMetadata,
  target?: Maturity,
): QualityGateResult {
  const level = target ?? rule.maturity;

  // Deprecated rules are always valid (they're being retired, not used)
  if (level === "deprecated") {
    return { passed: true, issues: [], warnings: [] };
  }

  const req = REQUIREMENTS[level];
  const issues: string[] = [];
  const warnings: string[] = [];

  // RFC-001 v1.1 §1.1 — Single-Pattern Rule Exception.
  //
  // A rule with fewer than the default minimum number of detection conditions
  // MAY still pass the experimental gate if it has been wild-validated to a
  // very high standard. Empirically (see ATR-2026-00139, 00146, etc.) some
  // attack categories — casual social engineering, single-token homoglyph
  // injection, ChatML system-token spoofing — are best caught by exactly one
  // narrow regex; padding with additional conditions only adds false-positive
  // surface without improving recall.
  //
  // Eligibility for the exception:
  //   - wild_samples >= SINGLE_PATTERN_EXCEPTION_MIN_SAMPLES
  //   - wild_fp_rate === 0 (must be exactly zero, not <= 0.5%)
  //   - rule still has >= 1 condition (true zero-condition rules are invalid)
  //
  // The exception is intentionally narrow: it costs the rule author a hard
  // empirical claim (wild_fp_rate exactly 0% on >=N samples). Authors who
  // cannot meet this bar must add more detection conditions OR keep the rule
  // at maturity `draft` until they can.
  // `isMeasuredFpRate(...) && === 0` rather than a bare `=== 0`: the exception
  // is priced as a hard empirical claim, so it must be bought with a real
  // measurement. An omitted rate already fails `=== 0`; the explicit predicate
  // states the requirement instead of relying on that coincidence, and keeps a
  // future `null`/`"0"` from buying the exception for free. See
  // src/quality/wild-measurement.ts.
  const meetsSinglePatternException =
    level === "experimental" &&
    rule.conditions >= 1 &&
    isMeasuredSampleCount(rule.wildSamples) &&
    rule.wildSamples >= SINGLE_PATTERN_EXCEPTION_MIN_SAMPLES &&
    isMeasuredFpRate(rule.wildFpRate) &&
    rule.wildFpRate === 0;

  if (rule.conditions < req.minConditions) {
    if (meetsSinglePatternException) {
      warnings.push(
        `only ${rule.conditions} detection condition(s) — accepted under RFC-001 v1.1 §1.1 single-pattern exception (wild_samples=${rule.wildSamples}, wild_fp_rate=0%)`,
      );
    } else {
      issues.push(
        `only ${rule.conditions} detection condition(s) (need ${req.minConditions}+, or wild_samples >= ${SINGLE_PATTERN_EXCEPTION_MIN_SAMPLES} with wild_fp_rate = 0% for the single-pattern exception)`,
      );
    }
  }
  if (rule.truePositives < req.minTruePositives) {
    issues.push(
      `only ${rule.truePositives} true_positive(s) (need ${req.minTruePositives}+)`,
    );
  }
  if (rule.trueNegatives < req.minTrueNegatives) {
    issues.push(
      `only ${rule.trueNegatives} true_negative(s) (need ${req.minTrueNegatives}+)`,
    );
  }
  if (req.minEvasionTests > 0 && rule.evasionTests < req.minEvasionTests) {
    issues.push(
      `only ${rule.evasionTests} evasion_test(s) (need ${req.minEvasionTests}+)`,
    );
  } else if (rule.evasionTests < 3 && level === "experimental") {
    warnings.push(
      `only ${rule.evasionTests} evasion_test(s) — recommend 3+ for stable promotion`,
    );
  }
  if (req.requireOwasp && !rule.hasOwaspRef) {
    issues.push("missing OWASP reference (LLM Top 10 or Agentic Top 10)");
  }
  if (req.requireMitre && !rule.hasMitreRef) {
    issues.push("missing MITRE reference (ATLAS or ATT&CK)");
  }
  if (req.requireFalsePositiveDocs && !rule.hasFalsePositiveDocs) {
    issues.push("missing false_positives documentation");
  }

  // Stable promotion requires human-verified provenance on key fields
  if (req.requireHumanReviewedProvenance) {
    const p = rule.provenance ?? {};
    const mitreProvenance = p.mitre_atlas ?? p.mitre_attack;
    const owaspProvenance = p.owasp_llm ?? p.owasp_agentic;

    if (rule.hasMitreRef && mitreProvenance && !isVerified(mitreProvenance)) {
      issues.push(
        `MITRE reference is "${mitreProvenance}" — stable requires human-reviewed or community-contributed`,
      );
    }
    if (rule.hasOwaspRef && owaspProvenance && !isVerified(owaspProvenance)) {
      issues.push(
        `OWASP reference is "${owaspProvenance}" — stable requires human-reviewed or community-contributed`,
      );
    }
  } else {
    // experimental/draft: surface provenance as warning so consumers can see it
    const p = rule.provenance ?? {};
    const autoFields: string[] = [];
    if (p.mitre_atlas === "auto-generated") autoFields.push("mitre_atlas");
    if (p.owasp_llm === "auto-generated") autoFields.push("owasp_llm");
    if (p.owasp_agentic === "auto-generated") autoFields.push("owasp_agentic");
    if (autoFields.length > 0) {
      warnings.push(
        `auto-generated provenance on: ${autoFields.join(", ")} — needs human review for stable`,
      );
    }
  }

  return {
    passed: issues.length === 0,
    issues,
    warnings,
  };
}

function isVerified(p: Provenance): boolean {
  return VERIFIED_PROVENANCE.includes(p);
}

/**
 * Public accessor for the requirements table.
 * Useful for documentation generators and UIs that display the quality bar.
 */
export function getRequirements(): typeof REQUIREMENTS {
  return REQUIREMENTS;
}
