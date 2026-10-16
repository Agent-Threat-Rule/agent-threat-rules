/**
 * A rule's own true positives, read and run the way `atr test` runs a test case
 * (src/cli.ts). scripts/check-rules-safety.ts runs a modified rule's true
 * positives with it (the own-TP check).
 *
 * A case is read whole: a bare string is shorthand for { input }, and every key
 * buildEventFromTestCase() (src/testcase-event.ts) reads is honoured, so a case
 * that carries its payload in tool_response, tool_args or an object input is
 * run. It is run on both paths `atr test` tries: the event
 * buildEventFromTestCase() builds for the rule's agent_source.type, through
 * evaluate(), and the case's text through scanSkill().
 */
import { ATREngine, WITHHELD_SOURCE_TYPES } from "../../src/engine.js";
import { asTestedRule, buildEventFromTestCase } from "../../src/testcase-event.js";
import { normalizeMaturity } from "../../src/quality/rule-contract.js";
import type { AgentEvent, ATRRule } from "../../src/types.js";

/** A declared test case as `atr test` reads it; a bare string is shorthand for { input }. */
export function testCaseObject(tc: unknown): Record<string, unknown> | null {
  if (typeof tc === "string") return tc.trim() === "" ? null : { input: tc };
  return tc !== null && typeof tc === "object" && !Array.isArray(tc)
    ? (tc as Record<string, unknown>)
    : null;
}

/** The true positives a rule declares, or null when the key holds something other than a list. */
export function declaredTruePositives(doc: Record<string, unknown>): Record<string, unknown>[] | null {
  const testCases = doc["test_cases"];
  const raw =
    testCases !== null && typeof testCases === "object"
      ? (testCases as Record<string, unknown>)["true_positives"]
      : undefined;
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) return null;
  return raw.map(testCaseObject).filter((c): c is Record<string, unknown> => c !== null);
}

export const methodOf = (rule: Record<string, unknown>): unknown =>
  (rule["detection"] as { method?: unknown } | undefined)?.method ?? "pattern";

/**
 * An agent_source.type the engine runs on no typed event (WITHHELD_SOURCE_TYPES
 * in src/engine.ts). `atr test` reports such a rule's cases as unevaluable.
 */
export const isWithheld = (rule: Record<string, unknown>): boolean => {
  const type = (rule["agent_source"] as { type?: unknown } | undefined)?.type;
  return typeof type === "string" && Object.hasOwn(WITHHELD_SOURCE_TYPES, type);
};

/**
 * One version of a rule the way `atr test` holds it (asTestedRule in
 * src/testcase-event.ts): status set aside, agent_source.type as declared, since
 * the engine maps an extended type itself (RUNTIME_SOURCE_TYPE in
 * src/engine.ts). A deprecated maturity is set aside too, which `atr test` does
 * not do: what is measured is the detection, not the deployment decision, and a
 * status or maturity change is its own line in the diff for a reviewer.
 */
export function asTestCaseRule(rule: Record<string, unknown>): Record<string, unknown> {
  const tested = asTestedRule(rule as unknown as ATRRule) as unknown as Record<string, unknown>;
  return normalizeMaturity(rule["maturity"]) === "deprecated" ? { ...tested, maturity: "experimental" } : tested;
}

/**
 * An engine holding exactly these rules, each as `atr test` holds it
 * (asTestCaseRule). No loadRules(): with no rulesDir it would load the bundled
 * rule tree as well.
 */
export function testCaseEngine(rules: readonly Record<string, unknown>[]): ATREngine {
  const engine = new ATREngine();
  for (const rule of rules) engine.addRule(asTestCaseRule(rule) as unknown as ATRRule);
  return engine;
}

/** Whether one test case matched on each path `atr test` tries. */
export interface CaseHits {
  /** evaluate() on the event the case describes: the runtime hook's path. */
  readonly evaluate: boolean;
  /** scanSkill() on the case's text: the SKILL.md path. */
  readonly skill: boolean;
}

export const NO_HITS: CaseHits = Object.freeze({ evaluate: false, skill: false });

/** `atr test` passes a case that matches on either path (src/cli.ts). */
export const matches = (h: CaseHits): boolean => h.evaluate || h.skill;

/**
 * One test case run on both paths `atr test` tries. The event is passed in, so
 * a case declared at base can be replayed to a modified rule exactly as the
 * base rule received it. Both paths are kept apart, unlike `atr test`'s single
 * verdict: a rule with scan_target both that a change re-routes away from its
 * runtime events still matches its cases on scanSkill(), and that is a loss.
 */
export function caseHits(
  engine: ATREngine,
  ruleId: string,
  tc: Record<string, unknown>,
  event: AgentEvent | null,
): CaseHits {
  const evaluate = event !== null && engine.evaluate(event).some((m) => m.rule.id === ruleId);
  const text = String(tc["input"] ?? tc["tool_response"] ?? tc["agent_output"] ?? "");
  const skill = text !== "" && engine.scanSkill(text).some((m) => m.rule.id === ruleId);
  return { evaluate, skill };
}

/** buildEventFromTestCase, or null when the case cannot be turned into an event. */
export function eventFor(tc: Record<string, unknown>, routing: Record<string, unknown>): AgentEvent | null {
  try {
    return buildEventFromTestCase(tc, routing as unknown as ATRRule);
  } catch {
    return null;
  }
}

export const caseSnippet = (tc: Record<string, unknown>): string => {
  const v = tc["input"] ?? tc["tool_response"] ?? tc["tool_args"] ?? tc["agent_output"] ?? tc;
  return (typeof v === "string" ? v : JSON.stringify(v)).slice(0, 60).replace(/\s+/g, " ");
};
