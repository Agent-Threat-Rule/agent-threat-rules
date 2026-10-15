/**
 * The `compliance:` block a machine-authored semantic rule ships with.
 *
 * WHY A TEMPLATE
 *   audit:mappings --require-full fails the corpus for every rule missing one
 *   of eu_ai_act / nist_ai_rmf / iso_42001, and the semantic lane emitted none
 *   (rolling PR #632 sat at 825/833). The controls below are the shape
 *   scripts/fn-mine-llm.ts already gets through validate:compliance for a
 *   detection rule: EU AI Act 15 + 9, NIST AI RMF MP.5.1 + MG.3.2, ISO/IEC
 *   42001 8.1 + 8.3. Field layout follows spec/atr-schema.yaml (`compliance`)
 *   and the existing corpus: identifier field, auditor-readable `context`,
 *   `strength`.
 *
 * WHAT IT IS NOT
 *   A per-rule judgment. Every semantic rule gets the same controls with its
 *   own title and category in the prose, and _semantic_authored records that
 *   the mapping is an automatic template a human must review before the rule
 *   is promoted to stable. The contexts state detection EVIDENCE, never
 *   compliance, per spec/compliance-metadata.md.
 */

export type ComplianceStrength = "primary" | "secondary";

export interface EuAiActItem {
  readonly article: string;
  readonly context: string;
  readonly strength: ComplianceStrength;
}

export interface NistAiRmfItem {
  readonly subcategory: string;
  readonly context: string;
  readonly strength: ComplianceStrength;
}

export interface Iso42001Item {
  readonly clause: string;
  readonly context: string;
  readonly strength: ComplianceStrength;
}

export interface SemanticComplianceBlock {
  readonly eu_ai_act: EuAiActItem[];
  readonly nist_ai_rmf: NistAiRmfItem[];
  readonly iso_42001: Iso42001Item[];
}

function euAiAct(technique: string): EuAiActItem[] {
  return [
    {
      article: "15",
      context:
        "Article 15 (accuracy, robustness and cybersecurity) requires high-risk AI systems to resist " +
        `unauthorised attempts to alter their use, outputs or performance; this rule provides runtime detection evidence by flagging ${technique}.`,
      strength: "primary",
    },
    {
      article: "9",
      context:
        "Article 9 (risk management system) requires identified risks to be addressed by appropriate measures; " +
        `this rule is a runtime risk-treatment control that detects ${technique}.`,
      strength: "secondary",
    },
  ];
}

function nistAiRmf(technique: string): NistAiRmfItem[] {
  return [
    {
      subcategory: "MP.5.1",
      context:
        "NIST AI RMF MAP 5.1 requires the likelihood and magnitude of impacts to be identified; detections of " +
        `${technique} give a measured record of how often this adversarial input class reaches the agent.`,
      strength: "primary",
    },
    {
      subcategory: "MG.3.2",
      context:
        "NIST AI RMF MANAGE 3.2 (pre-trained models monitored as part of maintenance) is supported where this rule " +
        `monitors the deployed model's inputs for ${technique}.`,
      strength: "secondary",
    },
  ];
}

function iso42001(technique: string): Iso42001Item[] {
  return [
    {
      clause: "8.1",
      context:
        "ISO/IEC 42001 Clause 8.1 (operational planning and control) is operationalised by this rule's runtime " +
        `detection of ${technique}.`,
      strength: "primary",
    },
    {
      clause: "8.3",
      context:
        "ISO/IEC 42001 Clause 8.3 (AI risk treatment) is supported by this rule, which implements runtime detection of " +
        `${technique} as a treatment control.`,
      strength: "secondary",
    },
  ];
}

/** Fresh objects on every call; callers may serialise or extend them freely. */
export function buildComplianceTemplate(title: string, category: string): SemanticComplianceBlock {
  const technique = `the ${category} technique (${title})`;
  return { eu_ai_act: euAiAct(technique), nist_ai_rmf: nistAiRmf(technique), iso_42001: iso42001(technique) };
}
