/**
 * ATR-to-numbat converter
 *
 * Exports ATR rules as numbat operator rules: one YAML rule file per ATR rule,
 * plus a companion `_tests.yaml` built from the rule's own test cases, so
 * `numbat rules check --rules-dir <dir>` runs ATR's true positives and true
 * negatives through numbat's RE2 matcher.
 *
 * Field mapping (numbat event model, schema 0.5.0):
 *   user_input     -> prompt.user content, and tool_result of a tool result
 *   agent_output   -> message.assistant content, and tool_result of a tool
 *                     result (the ATR engine reads both on tool output, so
 *                     indirect injection riding in on a tool result is seen)
 *   tool_args      -> tool_input of a tool request (tool.call, command.exec,
 *                     file.*, network.indicator)
 *   tool_response  -> tool_result of a tool result (tool.result, command.result)
 *   tool_name      -> tool_name of a tool request or result
 *   content        -> the event's own text: content on prompt.user and
 *                     message.assistant, tool_input on a request, tool_result
 *                     on a result
 *
 * What does not carry over:
 *   - Conditions on other fields, and patterns RE2 cannot express, are
 *     dropped. A rule whose detection is "all" loses its meaning if any
 *     condition is dropped, so it is skipped; an "any" rule keeps the
 *     conditions that convert.
 *   - The ATR engine folds Unicode confusables and normalizes NFKC/NFC before
 *     matching; numbat matches the raw text, so obfuscated input can match in
 *     ATR and not here.
 *   - JavaScript and RE2 differ in a few classes: JS `\s` also matches NBSP,
 *     U+2028 and the BOM, JS `.` excludes `\r`, and a JS pattern without the
 *     `u` flag counts an astral character as two. The companion tests catch
 *     a difference only where a test case exercises it.
 *   - Rules are monitor-only (`enforce: false`); blocking is an operator
 *     decision in numbat.
 *
 * @module agent-threat-rules/converters/numbat
 */

import yaml from 'js-yaml';
import type { ATRArrayCondition, ATRRule } from '../types.js';
import { regexConditionSpec } from '../regex-dialect.js';
import { toRe2 } from '../re2.js';
import { laneAllows, requiresConfirm, type Lane } from '../quality/rule-contract.js';

const REQUEST_TYPES = ['tool.call', 'command.exec', 'file.read', 'file.write', 'file.delete', 'network.indicator'];
const RESULT_TYPES = ['tool.result', 'command.result'];

/** numbat field name and the event types it is read on, per ATR field. */
const FIELD_TARGETS: Readonly<Record<string, readonly (readonly [string, readonly string[]])[]>> = {
  user_input: [
    ['content', ['prompt.user']],
    ['tool_result', RESULT_TYPES],
  ],
  agent_output: [
    ['content', ['message.assistant']],
    ['tool_result', RESULT_TYPES],
  ],
  tool_args: [['tool_input', REQUEST_TYPES]],
  tool_response: [['tool_result', RESULT_TYPES]],
  tool_name: [['tool_name', [...REQUEST_TYPES, ...RESULT_TYPES]]],
  content: [
    ['content', ['prompt.user', 'message.assistant']],
    ['tool_input', REQUEST_TYPES],
    ['tool_result', RESULT_TYPES],
  ],
};

const SEVERITY: Readonly<Record<string, string>> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  informational: 'info',
  info: 'info',
};

export interface NumbatExportOptions {
  /** Which ATR rules to export, by maturity lane. Default `enforce` (stable rules). */
  readonly lane?: Lane;
}

export interface NumbatRuleFile {
  readonly ruleId: string;
  /** File stem, e.g. `atr-2026-00432`; write `<stem>.yaml` and `<stem>_tests.yaml`. */
  readonly stem: string;
  readonly rule: string;
  /** Null when no test case maps onto a numbat event. */
  readonly tests: string | null;
  /** ATR conditions that could not be converted, by index. */
  readonly droppedConditions: readonly number[];
  /** ATR true positives (1-based) the converted rule does not match, left out of the companion. */
  readonly uncoveredTruePositives: readonly number[];
  /** ATR test cases (labelled tp-N / tn-N) with no field that maps onto a numbat event. */
  readonly unmappedCases: readonly string[];
}

export interface NumbatSkip {
  readonly ruleId: string;
  readonly reason: string;
}

export interface NumbatExport {
  readonly files: readonly NumbatRuleFile[];
  readonly skipped: readonly NumbatSkip[];
}

/** numbat rule id for an ATR id: `atr.atr-2026-00432`. */
export function numbatRuleId(atrId: string): string {
  return `atr.${atrId.toLowerCase()}`;
}

/** A CEL double-quoted string literal. */
function celString(s: string): string {
  const escaped = s
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
  return `"${escaped}"`;
}

function typeTest(types: readonly string[]): string {
  return types.length === 1
    ? `event.event_type == ${celString(types[0]!)}`
    : `event.event_type in [${types.map(celString).join(', ')}]`;
}

interface ConvertedCondition {
  readonly cel: string;
  readonly targets: readonly (readonly [string, readonly string[]])[];
  /** The same pattern as a JavaScript RegExp, to check which test cases still match. */
  readonly js: RegExp;
}

/** One ATR regex condition as CEL, or null when it cannot be converted. */
function convertCondition(cond: ATRArrayCondition): ConvertedCondition | null {
  const targets = FIELD_TARGETS[cond.field];
  if (!targets || cond.operator !== 'regex' || !cond.value) return null;
  const spec = regexConditionSpec(cond.value);
  const source = toRe2(spec.source);
  if (source === null) return null;
  let js: RegExp;
  try {
    js = new RegExp(spec.source, spec.flags);
  } catch {
    return null; // the ATR engine cannot compile it either
  }
  // SPEC §6.4: every condition matches case-insensitively.
  const pattern = celString(`(?i)${source}`);
  const branches = targets.map(([field, types]) => `(${typeTest(types)} && event.${field}.matches(${pattern}))`);
  return {
    cel: branches.length === 1 ? branches[0]! : `(${branches.join(' || ')})`,
    targets,
    js,
  };
}

/** Does a converted condition match this test event? */
function conditionMatches(cond: ConvertedCondition, event: TestEvent): boolean {
  return cond.targets.some(([field, types]) => {
    const value = event[field];
    return types.includes(String(event['event_type'])) && typeof value === 'string' && cond.js.test(value);
  });
}

/** Is there one numbat event type that every condition can read? */
function shareAnEventType(conditions: readonly ConvertedCondition[]): boolean {
  const typesOf = (c: ConvertedCondition): Set<string> => new Set(c.targets.flatMap(([, types]) => types));
  const [first, ...rest] = conditions.map(typesOf);
  return [...(first ?? [])].some((t) => rest.every((types) => types.has(t)));
}

function arrayConditions(rule: ATRRule): readonly ATRArrayCondition[] | null {
  return Array.isArray(rule.detection.conditions) ? rule.detection.conditions : null;
}

const utf8Bytes = (s: string): number => Buffer.byteLength(s, 'utf8');

type TestEvent = Record<string, string | number>;

/**
 * The event a plain-text test case stands for. ATR's `input` key is the text
 * of whatever the rule reads, so a rule that reads only tool output gets a
 * tool result, and one that reads only tool arguments gets a tool call.
 */
function plainTextEventType(fields: ReadonlySet<string>): string {
  // A named field says which event the text belongs to; `content` alone does not.
  if (fields.has('tool_response')) return 'tool.result';
  if (fields.has('tool_args')) return 'tool.call';
  if (fields.has('user_input')) return 'prompt.user';
  if (fields.has('agent_output')) return 'message.assistant';
  return 'prompt.user';
}

/** One numbat test event per ATR test case, or null when the case has no mappable field. */
function testEvent(tc: Record<string, unknown>, fields: ReadonlySet<string>): TestEvent | null {
  const str = (v: unknown): string => (typeof v === 'string' ? v : JSON.stringify(v));
  const name = typeof tc['tool_name'] === 'string' ? (tc['tool_name'] as string) : 'atr-test-tool';
  if (tc['tool_args'] !== undefined) {
    const input = str(tc['tool_args']);
    return { event_type: 'tool.call', tool_name: name, tool_input: input, tool_input_bytes: utf8Bytes(input) };
  }
  if (tc['tool_response'] !== undefined) {
    const result = str(tc['tool_response']);
    return { event_type: 'tool.result', tool_name: name, tool_result: result, tool_result_bytes: utf8Bytes(result) };
  }
  const message = (type: string, text: string) => ({ event_type: type, content: text, content_bytes: utf8Bytes(text) });
  if (typeof tc['agent_output'] === 'string') return message('message.assistant', tc['agent_output']);
  const text = tc['user_input'] ?? tc['input'] ?? tc['content'];
  if (typeof text !== 'string') return null;
  const type = plainTextEventType(fields);
  if (type === 'tool.result') return { event_type: type, tool_name: name, tool_result: text, tool_result_bytes: utf8Bytes(text) };
  if (type === 'tool.call') return { event_type: type, tool_name: name, tool_input: text, tool_input_bytes: utf8Bytes(text) };
  return message(type, text);
}

interface CompanionTests {
  readonly yaml: string | null;
  /** True positives (1-based) the converted rule does not match, so they are not in the companion. */
  readonly uncovered: readonly number[];
  readonly unmapped: readonly string[];
}

/**
 * The companion test file. A true positive that only a dropped condition
 * caught would fail in numbat, so it is left out and reported instead.
 */
function companionTests(rule: ATRRule, id: string, converted: readonly ConvertedCondition[], logic: string): CompanionTests {
  const fields = new Set(arrayConditions(rule)?.map((c) => c.field) ?? []);
  const cases: Record<string, unknown>[] = [];
  const uncovered: number[] = [];
  const unmapped: string[] = [];
  const matches = (event: TestEvent): boolean =>
    logic === 'all' ? converted.every((c) => conditionMatches(c, event)) : converted.some((c) => conditionMatches(c, event));
  const add = (list: unknown, expect: 'match' | 'no_match', label: string): void => {
    if (!Array.isArray(list)) return;
    list.forEach((tc, i) => {
      const event = tc && typeof tc === 'object' ? testEvent(tc as Record<string, unknown>, fields) : null;
      if (!event) {
        unmapped.push(`${expect === 'match' ? 'tp' : 'tn'}-${i + 1}`);
        return;
      }
      if (expect === 'match' && !matches(event)) {
        uncovered.push(i + 1);
        return;
      }
      cases.push({ name: `${label}-${i + 1}`, expect, events: [event] });
    });
  };
  add(rule.test_cases?.true_positives, 'match', 'atr-true-positive');
  add(rule.test_cases?.true_negatives, 'no_match', 'atr-true-negative');
  return {
    yaml: cases.length === 0 ? null : yaml.dump({ rule_id: id, cases }, { lineWidth: -1, noRefs: true }),
    uncovered,
    unmapped,
  };
}

/** Convert one ATR rule, or say why it cannot be converted. */
export function ruleToNumbat(rule: ATRRule): NumbatRuleFile | NumbatSkip {
  const conditions = arrayConditions(rule);
  if (!conditions) return { ruleId: rule.id, reason: 'named-format conditions are not supported' };

  const converted: ConvertedCondition[] = [];
  const dropped: number[] = [];
  conditions.forEach((cond, i) => {
    const c = convertCondition(cond);
    if (c === null) dropped.push(i);
    else converted.push(c);
  });

  const logic = String(rule.detection.condition ?? 'any').trim().toLowerCase();
  if (logic !== 'any' && logic !== 'all') return { ruleId: rule.id, reason: `detection condition "${logic}" is not supported` };
  if (converted.length === 0) return { ruleId: rule.id, reason: 'no condition converts (fields or RE2)' };
  if (logic === 'all' && dropped.length > 0) {
    return { ruleId: rule.id, reason: 'an "all" rule with an unconvertible condition would change meaning' };
  }
  if (logic === 'all' && !shareAnEventType(converted)) {
    return { ruleId: rule.id, reason: 'an "all" rule whose conditions read different numbat events can never match' };
  }
  if (!/^ATR-\d{4}-\d{5}$/.test(rule.id)) return { ruleId: rule.id, reason: 'rule id is not in ATR-YYYY-NNNNN form' };

  const id = numbatRuleId(rule.id);
  const doc = {
    id,
    version: String(rule.rule_version ?? 1),
    title: rule.title,
    severity: SEVERITY[rule.severity] ?? 'medium',
    description: `${String(rule.description ?? '').trim()}\n\nConverted from Agent Threat Rules ${rule.id} (https://github.com/Agent-Threat-Rule/agent-threat-rules).`.trim(),
    enabled: true,
    enforce: false,
    tags: ['atr', `atr:${rule.id}`, `atr-category:${rule.tags.category}`],
    expr: converted.map((c) => c.cel).join(logic === 'all' ? ' &&\n' : ' ||\n'),
  };
  const tests = companionTests(rule, id, converted, logic);
  return {
    ruleId: rule.id,
    stem: rule.id.toLowerCase(),
    rule: yaml.dump(doc, { lineWidth: -1, noRefs: true }),
    tests: tests.yaml,
    droppedConditions: dropped,
    uncoveredTruePositives: tests.uncovered,
    unmappedCases: tests.unmapped,
  };
}

/** Convert the rules in `lane` (default `enforce`). Embedding-confirmed rules are left out of enforce and alert. */
export function rulesToNumbat(rules: readonly ATRRule[], options: NumbatExportOptions = {}): NumbatExport {
  const lane = options.lane ?? 'enforce';
  const files: NumbatRuleFile[] = [];
  const skipped: NumbatSkip[] = [];
  for (const rule of rules) {
    if (rule.status === 'draft' || rule.status === 'deprecated') continue;
    if (!laneAllows(rule.maturity, lane)) continue;
    if (lane !== 'hunt' && requiresConfirm(rule)) {
      skipped.push({ ruleId: rule.id, reason: 'needs embedding confirmation, which numbat does not run' });
      continue;
    }
    const out = ruleToNumbat(rule);
    if ('reason' in out) skipped.push(out);
    else files.push(out);
  }
  return { files, skipped };
}
