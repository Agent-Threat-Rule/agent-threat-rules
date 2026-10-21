/**
 * A rule's own true positives, read and run the way `atr test` runs a test case
 * (src/cli.ts).
 *
 * Three callers, one reading. scripts/check-rules-safety.ts runs a new rule's
 * true positives (Check 2) and a modified rule's (the own-TP check) with it, and
 * scripts/lib/semantic-engine-gate.ts runs Check 2 on each draft before the
 * semantic lane writes it, so a draft that check-rules-safety would fail is
 * routed to human review instead of failing the whole run at the pre-push
 * backstop. A copy of this reading would drift the moment one side is edited.
 *
 * A case is read whole: a bare string is shorthand for { input }, and every key
 * buildEventFromTestCase() (src/testcase-event.ts) reads is honoured, so a case
 * that carries its payload in tool_response, tool_args or an object input is
 * run. It is run on both paths `atr test` tries: the event
 * buildEventFromTestCase() builds for the rule's agent_source.type, through
 * evaluate(), and the case's text through scanSkill().
 *
 * Check 2 also runs each case's text on the corpus shapes the benign checks
 * charge a rule on (matchesOnCorpusShapes), so what fires on a rule's own
 * attacks is what those checks measure, and refuses beforehand a rule those
 * checks cannot measure at all (corpusBlindReason).
 */
import { ATREngine, WITHHELD_SOURCE_TYPES } from "../../src/engine.js";
import { asTestedRule, buildEventFromTestCase } from "../../src/testcase-event.js";
import { normalizeMaturity } from "../../src/quality/rule-contract.js";
import type { AgentEvent, ATRRule } from "../../src/types.js";
import {
  BEHAVIORAL_FIELD_PREFIX,
  TRACE_FIELD_PREFIX,
  UNMEASURABLE_FIELDS,
  conditionFields,
  isMeasurableField,
  matchedRuleIds,
  type RuleLike,
} from "./corpus-event.js";

/**
 * A declared test case, a bare string read as { input }. The schema allows only
 * mappings, and `atr test` reads a bare string as an empty case; no rule has one.
 */
export function testCaseObject(tc: unknown): Record<string, unknown> | null {
  if (typeof tc === "string") return tc.trim() === "" ? null : { input: tc };
  return tc !== null && typeof tc === "object" && !Array.isArray(tc)
    ? (tc as Record<string, unknown>)
    : null;
}

/** test_cases.true_positives as written: [] when absent, null when it holds something other than a list. */
function rawTruePositives(doc: Record<string, unknown>): readonly unknown[] | null {
  const testCases = doc["test_cases"];
  const raw =
    testCases !== null && typeof testCases === "object"
      ? (testCases as Record<string, unknown>)["true_positives"]
      : undefined;
  if (raw === undefined || raw === null) return [];
  return Array.isArray(raw) ? raw : null;
}

/** The true positives a rule declares, or null when the key holds something other than a list. */
export function declaredTruePositives(doc: Record<string, unknown>): Record<string, unknown>[] | null {
  const raw = rawTruePositives(doc);
  if (raw === null) return null;
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

/**
 * Why a rule's true positives cannot be run at all, or null when they can:
 * true_positives is not a list or is empty, an entry is neither text nor a
 * test case, the rule is method: behavioral, which the synchronous path
 * cannot run (`atr test` skips it too), or its agent_source.type is one the
 * engine withholds from typed events (isWithheld; `atr test` reports its cases
 * as unevaluable). Each would otherwise leave nothing to match, which reads as
 * nothing unmatched.
 */
export function truePositiveObstacle(rule: Record<string, unknown>): string | null {
  const raw = rawTruePositives(rule);
  if (raw === null) return "test_cases.true_positives is not a list, so its true positives cannot be run";
  if (raw.length === 0) return "the rule declares no true positive, so nothing shows that it fires";
  const unreadable = raw.flatMap((tc, i) => (testCaseObject(tc) === null ? [i + 1] : []));
  if (unreadable.length > 0) {
    return (
      `true positive(s) ${unreadable.join(", ")} of ${raw.length} are neither text nor a test case, ` +
      `so they cannot be run`
    );
  }
  if (methodOf(rule) === "behavioral") {
    return (
      "method: behavioral cannot be run on the synchronous path (`atr test` skips it too), " +
      "so its true positives cannot be checked"
    );
  }
  if (isWithheld(rule)) {
    const type = String((rule["agent_source"] as { type?: unknown }).type);
    return (
      `agent_source.type ${type} does not run on typed events yet (WITHHELD_SOURCE_TYPES in ` +
      `src/engine.ts; \`atr test\` reports its cases as unevaluable), so its true positives ` +
      `cannot be checked the way \`atr test\` runs them; it needs a human review`
    );
  }
  return null;
}

/** Case keys that carry payload. A tool name is an identifier, not text, and the corpus shapes pin it. */
const PAYLOAD_KEYS: readonly string[] = Object.freeze([
  "input",
  "user_input",
  "tool_args",
  "tool_response",
  "agent_output",
  "agent_message",
  "content",
  "tool_description",
  "tool_call",
]);

const NAME_KEYS: ReadonlySet<string> = new Set(["tool_name", "name"]);

const asText = (v: unknown): string => (typeof v === "string" ? v : JSON.stringify(v));

const present = (v: unknown): boolean => v !== undefined && v !== null && v !== "";

/**
 * The text a case carries, as the benign checks would be handed it: each
 * payload value (an object's own values as well, but not a tool name), and all
 * of them joined, so a condition on one field and a condition on another can
 * both find their part.
 */
export function payloadTexts(tc: Record<string, unknown>): readonly string[] {
  const parts = PAYLOAD_KEYS.flatMap((key) => {
    const v = tc[key];
    if (!present(v)) return [];
    if (typeof v !== "object" || Array.isArray(v)) return [asText(v)];
    const values = Object.entries(v as Record<string, unknown>)
      .filter(([k, x]) => !NAME_KEYS.has(k) && present(x))
      .map(([, x]) => asText(x));
    return [...values, asText(v)];
  });
  const unique = [...new Set(parts)];
  return unique.length > 1 ? [...unique, unique.join("\n")] : unique;
}

/**
 * Whether a case also matches on the corpus shapes Checks 3 to 5 charge a rule
 * on (matchedRuleIds: the text in every field, tool_name pinned to a
 * placeholder, plus scanSkill). A case that matches the `atr test` way but not
 * here matches only through what no benign sample can exercise, a tool name or
 * a structure no text carries, so those checks do not measure what fires on
 * it.
 */
export function matchesOnCorpusShapes(
  engine: ATREngine,
  ruleId: string,
  tc: Record<string, unknown>,
): boolean {
  return payloadTexts(tc).some((text) => matchedRuleIds(engine, text).has(ruleId));
}

const SYNC_BLIND_METHODS: ReadonlySet<string> = new Set(["trace", "behavioral", "signature"]);

/** A field name the engine knows how to resolve; any other one is read from event metadata. */
const isKnownField = (field: string): boolean =>
  UNMEASURABLE_FIELDS.has(field) ||
  field.startsWith(TRACE_FIELD_PREFIX) ||
  field.startsWith(BEHAVIORAL_FIELD_PREFIX);

const describeField = (field: string): string =>
  isKnownField(field) ? field : `${field}, a field name read from event metadata`;

/**
 * Why Checks 3 to 5 of scripts/check-rules-safety.ts cannot run a new rule at
 * all, or null. Such a rule matches no benign sample whatever its patterns say,
 * so it would clear every corpus check with nothing measured.
 *
 *   deprecated, by status or by maturity (which the lane gate reads trimmed):
 *     no lane evaluates the rule.
 *   method trace, behavioral or signature: the engine cannot run it on a text
 *     sample.
 *
 * The old Check 2 failed these only because it could not match their cases
 * either. Run the `atr test` way, their cases match: status and maturity set
 * aside, a trace parsed into event.trace. A rule whose conditions no corpus
 * shape reaches, a tool_name in an `all` rule say, is left to Check 2, which
 * then matches none of its cases on the corpus shapes (truePositiveMisses).
 * Those shapes include the SKILL.md path, where every field resolves to the
 * document, so they reach some such rules, as the benign checks do.
 */
export function corpusBlindReason(rule: Record<string, unknown>): string | null {
  const retiredBy =
    rule["status"] === "deprecated"
      ? "status: deprecated"
      : normalizeMaturity(rule["maturity"]) === "deprecated"
        ? "maturity: deprecated"
        : null;
  if (retiredBy !== null) {
    return (
      `${retiredBy}: no lane evaluates this rule, so the benign-corpus and cross-rule checks ` +
      `would pass it with nothing measured; add a new rule as draft or experimental`
    );
  }
  const method = methodOf(rule);
  if (typeof method === "string" && SYNC_BLIND_METHODS.has(method)) {
    return (
      `method: ${method}: the engine cannot run this rule on a text sample, so the ` +
      `benign-corpus and cross-rule checks would pass it with nothing measured; it needs a ` +
      `human review`
    );
  }
  return null;
}

/**
 * What a case that matches only off the corpus shapes matched through, for the
 * failure line: the fields its conditions read that no corpus shape fills
 * (src/corpus-event.ts isMeasurableField), when there are any.
 */
export function offCorpusPath(rule: Record<string, unknown>): string {
  const fields = conditionFields(rule as unknown as RuleLike).filter((f) => !isMeasurableField(f));
  return fields.length > 0
    ? `${fields.map(describeField).join("; ")}, which no benign sample fills`
    : "the event built from the case, which no benign text reproduces";
}

/** A true positive Check 2 charges, and why. */
export interface TruePositiveMiss {
  readonly testCase: Record<string, unknown>;
  /**
   * unmatched: the rule does not match the case the way `atr test` runs it.
   * unmeasured: it does, but not on the corpus shapes the benign checks use.
   */
  readonly kind: "unmatched" | "unmeasured";
}

/**
 * Check 2's verdict on each true positive a rule declares. A case must match
 * the way `atr test` runs it: the event buildEventFromTestCase() builds for the
 * case from the rule's own routing, through evaluate(), and the case's text
 * through scanSkill(); either one matching is a match. It must also match on
 * the corpus shapes (matchesOnCorpusShapes), which is all the old Check 2
 * asked, of a case's input alone. `engine` holds the rule as testCaseEngine()
 * holds it. Check truePositiveObstacle() first: a rule whose cases cannot be
 * run has no miss here.
 */
export function truePositiveMisses(
  engine: ATREngine,
  rule: Record<string, unknown>,
): readonly TruePositiveMiss[] {
  const id = String(rule["id"]);
  return (declaredTruePositives(rule) ?? []).flatMap((tc): TruePositiveMiss[] => {
    if (!matches(caseHits(engine, id, tc, eventFor(tc, rule)))) return [{ testCase: tc, kind: "unmatched" }];
    return matchesOnCorpusShapes(engine, id, tc) ? [] : [{ testCase: tc, kind: "unmeasured" }];
  });
}
