/**
 * ATR Quality Standard — Public API
 *
 * Vendor-neutral library for scoring and validating AI agent threat detection
 * rules. See docs/proposals/001-atr-quality-standard-rfc.md for the RFC.
 *
 * @example Compute a confidence score for an ATR rule
 * ```typescript
 * import { parseATRRule, computeConfidence } from 'agent-threat-rules/quality';
 * import { readFileSync } from 'node:fs';
 *
 * const yaml = readFileSync('rules/prompt-injection/ATR-2026-00001.yaml', 'utf-8');
 * const rule = parseATRRule(yaml);
 * const score = computeConfidence(rule);
 * console.log(`Confidence: ${score.total}/100`);
 * ```
 *
 * @example Run a rule through the quality gate
 * ```typescript
 * import { parseATRRule, validateRuleMeetsStandard } from 'agent-threat-rules/quality';
 *
 * const rule = parseATRRule(yamlContent);
 * const gate = validateRuleMeetsStandard(rule, 'experimental');
 * if (!gate.passed) {
 *   console.error('Rule rejected:', gate.issues);
 * }
 * ```
 *
 * @module agent-threat-rules/quality
 */

// Types
export type {
  Maturity,
  RuleMetadata,
  ConfidenceScore,
  QualityGateResult,
  PromotionDecision,
  DemotionDecision,
  FpReport,
  DeploymentRecommendation,
} from "./types.js";

// Scoring
export {
  computeConfidence,
  deploymentFor,
  applyCrossContextPenalty,
} from "./compute-confidence.js";

// Validation
export { validateRuleMeetsStandard, getRequirements } from "./quality-gate.js";

// Maturity transitions
export {
  canPromote,
  shouldDemote,
  getMaturityThresholds,
} from "./validate-maturity.js";

// Wild-validation measurement provenance
export {
  WILD_MEASUREMENT_FIELDS,
  isMeasuredFpRate,
  isMeasuredSampleCount,
  unmeasuredFpReason,
  deriveWildFpRate,
} from "./wild-measurement.js";
export type { WildScanHit, WildRateDerivation } from "./wild-measurement.js";

// Adapters
export { parseATRRule, atrRuleToMetadata } from "./adapters/atr.js";
