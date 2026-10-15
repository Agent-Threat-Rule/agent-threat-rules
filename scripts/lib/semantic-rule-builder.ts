/**
 * Rule construction for the semantic (T2) lane: scaffold a valid YAML rule,
 * then inject the LLM-authored narrow fallback and judge prompt, the
 * normalised OWASP references and the template compliance block, and stamp
 * experimental/test.
 *
 * Only call this for a draft scripts/lib/semantic-gate.ts passed. The split of
 * cluster true positives below uses the gate's own compile and match, so every
 * declared true_positive is one the fallback catches, and the rest are
 * recorded as judge-only evasion tests.
 */
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { RuleScaffolder } from "../../src/rule-scaffolder.js";
import { ineligibleActions, maxTierFor } from "../../src/quality/action-eligibility.js";
import { loadOwaspAllowlists, normalizeReferences, type OwaspAllowlists } from "./normalize-references.js";
import { buildComplianceTemplate } from "./semantic-compliance.js";
import type { ClusterCandidate } from "./semantic-clusters.js";
import { compileFallback, splitTruePositives, type SemanticDraft } from "./semantic-gate.js";

const DEFAULT_REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Model used when ATR_AUTHOR_MODEL is unset; recorded in _semantic_authored. */
export const DEFAULT_AUTHOR_MODEL = "claude-haiku-4-5-20251001";

/**
 * How an authored rule is written to disk. The engine-level gate measures the
 * rule after a dump/load round trip with these same options, so what it judged
 * is what the file holds.
 */
export const RULE_YAML_OPTIONS = Object.freeze({ lineWidth: 120, noRefs: true });

// Caps on what one rule declares. Hits beyond the cap add size, not evidence.
const MAX_RULE_TPS = 8;
const MAX_JUDGE_ONLY_TESTS = 8;

/**
 * The declared actions an authored rule may keep: those at or below the tier the
 * shared action-eligibility contract grants a rule with no FP measurement.
 * Declaration order is kept; if nothing survives, the rule still alerts.
 */
export function earnedActions(actions: readonly string[], maturity: string): string[] {
  const ceiling = maxTierFor({ maturity }).maxTier;
  const unearned = new Set(ineligibleActions(actions, ceiling));
  const kept = actions.filter((a) => !unearned.has(a));
  return kept.length > 0 ? kept : ["alert"];
}

const JUDGE_ONLY_NOTE =
  "Cluster attack sample the narrow regex fallback does not match; only the semantic judge detects it. " +
  "Kept out of true_positives so the no-judge fallback is not credited with it.";

const MAPPINGS_NOTE =
  "references.owasp_* were normalised against data/compliance-frameworks (bare ids, category default when none " +
  "survived) and the compliance block is an automatic template (EU AI Act 15/9, NIST AI RMF MP.5.1/MG.3.2, " +
  "ISO/IEC 42001 8.1/8.3). Both need human review before this rule is promoted to stable.";

/** Return a new object with `key` placed right after `anchor` (or last). */
function insertAfter(obj: Record<string, unknown>, anchor: string, key: string, value: unknown): Record<string, unknown> {
  const entries = Object.entries(obj).filter(([k]) => k !== key);
  const at = entries.findIndex(([k]) => k === anchor);
  const pos = at < 0 ? entries.length : at + 1;
  return Object.fromEntries([...entries.slice(0, pos), [key, value], ...entries.slice(pos)]);
}

type TruePositiveSplit = { readonly hits: string[]; readonly misses: string[] };

const DEFAULT_MITRE = ["AML.T0051 - LLM Prompt Injection"];

function scaffoldBase(
  c: ClusterCandidate,
  draft: SemanticDraft,
  split: TruePositiveSplit,
  owaspLlm: string[],
): Record<string, unknown> {
  const judgeOnly = split.misses.slice(0, MAX_JUDGE_ONLY_TESTS).map((input) => ({
    input,
    expected: "not_triggered" as const,
    bypass_technique: "judge_only",
    notes: JUDGE_ONLY_NOTE,
  }));
  const paraphrases = (draft.paraphrase_tests ?? []).map((p) => ({
    input: p,
    expected: "triggered" as const,
    bypass_technique: "semantic_paraphrase",
    notes: "Judge should catch this reworded variant; narrow regex fallback may miss it.",
  }));
  const result = new RuleScaffolder({ author: "ATR Community (semantic-authored)" }).scaffoldSemantic({
    title: c.title,
    category: c.category,
    severity: c.severity,
    attackDescription: draft.attack_definition!,
    notDetectedDescription: draft.not_detected,
    // Only the samples the fallback catches are declared as true positives:
    // CI requires every declared TP to fire on the fallback.
    examplePayloads: split.hits.slice(0, MAX_RULE_TPS),
    negativePayloads: c.trueNegatives.slice(0, 8),
    evasionTests: [...judgeOnly, ...paraphrases],
    falsePositiveScenarios: draft.false_positive_scenarios,
    owaspRefs: owaspLlm,
    mitreRefs: c.mitreRefs.length > 0 ? c.mitreRefs : DEFAULT_MITRE,
    detectionMethod: "semantic",
    semantic: { threshold: 0.7, includePatternFallback: true, judgeModelClass: "gpt-4-class" },
  });
  return yaml.load(result.yaml) as Record<string, unknown>;
}

/**
 * Replace the scaffolder's brittle EXACT-match fallback with the LLM-authored
 * narrow generalized fallback, and its default judge with the authored one.
 */
function authoredDetection(
  detection: Record<string, unknown>,
  fallback: string,
  draft: SemanticDraft,
): Record<string, unknown> {
  return {
    ...detection,
    conditions: [
      {
        field: "user_input",
        operator: "regex",
        value: fallback,
        description: draft.fallback_description ?? "Narrow generalized fallback (anchor + redirect)",
      },
    ],
    condition: "any",
    semantic: {
      ...(detection.semantic as Record<string, unknown>),
      prompt_template: draft.judge_prompt,
      fallback_method: "pattern",
    },
  };
}

/**
 * The scaffolder picks actions from severity alone; an unmeasured rule is
 * capped at the observe tier by the action-eligibility contract.
 */
function earnedResponse(response: Record<string, unknown>, maturity: string): Record<string, unknown> {
  const declared = Array.isArray(response.actions)
    ? response.actions.filter((a): a is string => typeof a === "string")
    : [];
  return { ...response, actions: earnedActions(declared, maturity) };
}

function provenance(c: ClusterCandidate, split: TruePositiveSplit): Record<string, unknown> {
  return {
    model: process.env.ATR_AUTHOR_MODEL || DEFAULT_AUTHOR_MODEL,
    source_cluster: c.proposalRel,
    family: c.family ?? null,
    fallback_coverage: `${split.hits.length} of ${split.hits.length + split.misses.length} cluster true_positives`,
    note:
      "Generation-time LLM authoring of judge prompt + narrow fallback; verified by a deterministic 0-FP gate. " +
      "Runtime primary detector is the semantic judge; the regex is a no-judge fallback. Human review required before promotion.",
    mappings: MAPPINGS_NOTE,
  };
}

export function buildSemanticRule(
  c: ClusterCandidate,
  draft: SemanticDraft,
  id: string,
  allowlists: OwaspAllowlists = loadOwaspAllowlists(DEFAULT_REPO_ROOT),
): Record<string, unknown> {
  const fallback = (draft.fallback_regex ?? "").trim();
  const compiled = compileFallback(fallback);
  if (!compiled.ok) throw new Error(`buildSemanticRule(${id}): ${compiled.reason}`);
  const split = splitTruePositives(compiled.regex, c.truePositives);
  const refs = normalizeReferences(
    { category: c.category, owaspLlm: c.owaspRefs, owaspAgentic: c.owaspAgenticRefs },
    allowlists,
  );
  const base = scaffoldBase(c, draft, split, refs.owasp_llm);
  const maturity = "test";
  const response = base.response as Record<string, unknown> | undefined;
  const rule: Record<string, unknown> = {
    ...base,
    id,
    // Task spec: status=experimental, maturity=test.
    status: "experimental",
    maturity,
    detection_tier: "semantic",
    references: {
      owasp_llm: refs.owasp_llm,
      owasp_agentic: refs.owasp_agentic,
      mitre_atlas: c.mitreRefs.length > 0 ? c.mitreRefs : DEFAULT_MITRE,
    },
    ...(response ? { response: earnedResponse(response, maturity) } : {}),
    detection: authoredDetection(base.detection as Record<string, unknown>, fallback, draft),
    _semantic_authored: provenance(c, split),
  };
  return insertAfter(rule, "references", "compliance", buildComplianceTemplate(c.title, c.category));
}
