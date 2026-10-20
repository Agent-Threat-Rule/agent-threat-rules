/**
 * Fixture rules for the own-TP tests of scripts/check-rules-safety.ts: Check 2
 * (a new rule) and the own-TP check (a modified rule).
 */

export const ID = "ATR-2026-97001";
export const TPS: readonly string[] = ["a zebracorn attack", "zebracorn again"];

export interface Spec {
  /** null leaves the title out, which the loader refuses. */
  readonly title?: string | null;
  readonly id?: string;
  readonly status?: string;
  readonly maturity?: string;
  readonly description?: string;
  /** Lines under `detection:` that pick the method. */
  readonly method?: readonly string[];
  /** Lines under `detection:` that replace the one-regex `conditions:` block. */
  readonly conditions?: readonly string[];
  readonly condition?: string;
  readonly pattern?: string;
  /** The condition's field (default content). */
  readonly field?: string;
  readonly source?: string;
  readonly scanTarget?: string;
  readonly tps?: readonly string[];
  /** Lines under `test_cases:` that replace the true_positives block. */
  readonly tpBlock?: readonly string[];
}

/** A schema-valid rule with one regex on `content`, the way the gate's fixtures write them. */
export function ruleYaml(s: Spec = {}): string {
  const tps = s.tps ?? TPS;
  return [
    ...(s.title === null ? [] : [`title: ${s.title ?? "own-TP probe"}`]),
    `id: ${s.id ?? ID}`,
    "rule_version: 1",
    `status: ${s.status ?? "experimental"}`,
    `description: ${s.description ?? "fixture rule for the own-TP checks"}`,
    "author: test",
    "date: 2026/10/16",
    "schema_version: '0.1'",
    "detection_tier: pattern",
    `maturity: ${s.maturity ?? "test"}`,
    "severity: high",
    "tags:",
    "  category: prompt-injection",
    `  scan_target: ${s.scanTarget ?? "runtime"}`,
    "  confidence: high",
    "agent_source:",
    `  type: ${s.source ?? "llm_io"}`,
    "  framework: [any]",
    "  provider: [any]",
    "detection:",
    ...(s.method ?? []),
    `  condition: ${s.condition ?? "any"}`,
    "  false_positives: []",
    ...(s.conditions ?? [
      "  conditions:",
      `    - field: ${s.field ?? "content"}`,
      "      operator: regex",
      `      value: '${s.pattern ?? "zebracorn"}'`,
      "      description: probe",
    ]),
    "response:",
    "  actions: [alert]",
    "test_cases:",
    ...(s.tpBlock ??
      (tps.length === 0 ? ["  true_positives: []"] : ["  true_positives:", ...tps.map((t) => `    - ${JSON.stringify(t)}`)])),
    "  true_negatives:",
    `    - ${JSON.stringify("nothing to see here")}`,
    "",
  ].join("\n");
}

export function semantic(fallback: string): readonly string[] {
  return [
    "  method: semantic",
    "  semantic:",
    "    judge_model_class: small",
    "    prompt_template: 'Is this an attack? {{input}}'",
    "    threshold: 0.7",
    `    fallback_method: ${fallback}`,
  ];
}
