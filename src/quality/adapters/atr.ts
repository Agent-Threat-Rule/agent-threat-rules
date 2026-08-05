/**
 * ATR Quality Standard — ATR YAML Adapter
 *
 * Parses an ATR YAML rule (either as raw string or pre-parsed object) and
 * produces RuleMetadata that the quality gate and scoring functions
 * understand.
 *
 * @module agent-threat-rules/quality/adapters/atr
 */

import { load as parseYaml } from "js-yaml";
import {
  isMeasuredFpRate,
  isMeasuredSampleCount,
} from "../wild-measurement.js";
import type {
  MetadataProvenance,
  Maturity,
  Provenance,
  RuleMetadata,
} from "../types.js";

/**
 * Loose shape of an ATR rule file — matches what actually appears in
 * rules/**\/*.yaml, not the strict type. This lets us adapt rules even if
 * they're missing optional fields.
 */
interface RawATRRule {
  id?: string;
  title?: string;
  status?: string;
  maturity?: string;
  detection?: {
    conditions?: unknown;
    false_positives?: unknown[];
  };
  test_cases?: {
    true_positives?: unknown[];
    true_negatives?: unknown[];
  };
  evasion_tests?: unknown[];
  references?: {
    owasp_llm?: unknown[];
    owasp_agentic?: unknown[];
    mitre_atlas?: unknown[];
    mitre_attack?: unknown[];
  };
  author?: string;
  wild_samples?: number;
  wild_fp_rate?: number;
  wild_validated?: string;
  metadata_provenance?: {
    mitre_atlas?: string;
    mitre_attack?: string;
    owasp_llm?: string;
    owasp_agentic?: string;
    test_cases?: string;
    evasion_tests?: string;
    false_positives?: string;
  };
}

/**
 * Parse an ATR YAML rule string into RuleMetadata.
 *
 * @param yamlContent - Raw YAML content
 * @returns RuleMetadata (throws if YAML is invalid or missing required fields)
 */
export function parseATRRule(yamlContent: string): RuleMetadata {
  const parsed = parseYaml(yamlContent) as RawATRRule | null | undefined;
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Invalid YAML: not an object");
  }
  return atrRuleToMetadata(parsed);
}

/**
 * Convert a parsed ATR rule object into RuleMetadata.
 *
 * Accepts the loose shape returned by yaml.load() so callers that already
 * have a parsed object don't need to re-serialize.
 */
export function atrRuleToMetadata(rule: RawATRRule): RuleMetadata {
  const id = rule.id ?? "<unknown>";
  const title = rule.title ?? "<untitled>";
  // Prefer `maturity` field; fall back to `status` if maturity is absent.
  // Normalize common aliases: `test` -> `experimental`, anything unknown -> `draft`.
  const rawMaturity = (rule.maturity ?? rule.status ?? "draft").toLowerCase();
  const maturity: Maturity = normalizeMaturity(rawMaturity);

  const conditions = countConditions(rule.detection?.conditions);
  const truePositives = Array.isArray(rule.test_cases?.true_positives)
    ? rule.test_cases.true_positives.length
    : 0;
  const trueNegatives = Array.isArray(rule.test_cases?.true_negatives)
    ? rule.test_cases.true_negatives.length
    : 0;
  const evasionTests = Array.isArray(rule.evasion_tests)
    ? rule.evasion_tests.length
    : 0;

  const hasOwaspRef =
    hasAnyArrayItem(rule.references?.owasp_llm) ||
    hasAnyArrayItem(rule.references?.owasp_agentic);
  const hasMitreRef =
    hasAnyArrayItem(rule.references?.mitre_atlas) ||
    hasAnyArrayItem(rule.references?.mitre_attack);
  const hasFalsePositiveDocs =
    Array.isArray(rule.detection?.false_positives) &&
    rule.detection.false_positives.length > 0;

  // LLM-generated detection: author contains "Crystallization" or "LLM"
  const author = (rule.author ?? "").toLowerCase();
  const llmGenerated =
    author.includes("crystallization") ||
    author.includes("llm") ||
    author.includes("mirofish");

  const provenance = extractProvenance(rule.metadata_provenance);

  return {
    id,
    title,
    maturity,
    conditions,
    truePositives,
    trueNegatives,
    evasionTests,
    hasOwaspRef,
    hasMitreRef,
    hasFalsePositiveDocs,
    // Only carry a wild measurement forward when it IS one. A `null` or a
    // numeric string survives `!== undefined` but reaches every downstream
    // comparison (`rate > threshold`) as false, which reads to a gate as a
    // perfect score — see src/quality/wild-measurement.ts. Dropping it here
    // makes it `undefined`, the one encoding the gates refuse.
    ...(isMeasuredSampleCount(rule.wild_samples)
      ? { wildSamples: rule.wild_samples }
      : {}),
    ...(isMeasuredFpRate(rule.wild_fp_rate)
      ? { wildFpRate: rule.wild_fp_rate }
      : {}),
    ...(rule.wild_validated ? { wildValidatedAt: rule.wild_validated } : {}),
    ...(llmGenerated ? { llmGenerated: true } : {}),
    ...(provenance ? { provenance } : {}),
  };
}

/** Parse metadata_provenance field and normalize values to Provenance enum */
function extractProvenance(
  raw: RawATRRule["metadata_provenance"],
): MetadataProvenance | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const result: MetadataProvenance = {
    ...(raw.mitre_atlas
      ? { mitre_atlas: normalizeProvenance(raw.mitre_atlas) }
      : {}),
    ...(raw.mitre_attack
      ? { mitre_attack: normalizeProvenance(raw.mitre_attack) }
      : {}),
    ...(raw.owasp_llm ? { owasp_llm: normalizeProvenance(raw.owasp_llm) } : {}),
    ...(raw.owasp_agentic
      ? { owasp_agentic: normalizeProvenance(raw.owasp_agentic) }
      : {}),
    ...(raw.test_cases
      ? { test_cases: normalizeProvenance(raw.test_cases) }
      : {}),
    ...(raw.evasion_tests
      ? { evasion_tests: normalizeProvenance(raw.evasion_tests) }
      : {}),
    ...(raw.false_positives
      ? { false_positives: normalizeProvenance(raw.false_positives) }
      : {}),
  };
  return Object.keys(result).length > 0 ? result : undefined;
}

function normalizeProvenance(raw: string): Provenance {
  const v = raw.toLowerCase().trim();
  if (v === "human-reviewed" || v === "human") return "human-reviewed";
  if (v === "community-contributed" || v === "community")
    return "community-contributed";
  if (v === "auto-generated" || v === "auto") return "auto-generated";
  if (v === "llm-generated" || v === "llm") return "llm-generated";
  // Unknown value — treat as auto-generated (conservative)
  return "auto-generated";
}

/**
 * ATR rules use two different condition formats:
 *  - Array: `conditions: [{ field, operator, value }, ...]`
 *  - Named map: `conditions: { name1: {...}, name2: {...} }`
 *
 * Count layers in either format.
 */
function countConditions(conditions: unknown): number {
  if (Array.isArray(conditions)) return conditions.length;
  if (conditions !== null && typeof conditions === "object") {
    return Object.keys(conditions as Record<string, unknown>).length;
  }
  return 0;
}

function hasAnyArrayItem(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0;
}

function normalizeMaturity(raw: string): Maturity {
  switch (raw) {
    case "draft":
      return "draft";
    case "experimental":
    case "test": // ATR legacy alias
      return "experimental";
    case "stable":
      return "stable";
    case "deprecated":
      return "deprecated";
    default:
      return "draft";
  }
}
