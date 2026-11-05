/**
 * ATR-to-Quarry converter
 *
 * Exports ATR rules as Project Quarry rules (Cisco AI Defense, DSL 0.1): one
 * `.rule` file per ATR rule, a `quarry.yaml` that loads them, and one test
 * file per rule built from the rule's own test cases as OpenAI-shaped
 * conversations. `check_atr_tests.py`, written next to them, runs those
 * conversations through Quarry's scanner, so a JS/RE2 difference that a test
 * case exercises shows up as a failing case.
 *
 * Field mapping (Quarry data surfaces):
 *   user_input       -> user_messages.content, and tool_responses.content
 *   agent_output     -> assistant_messages.content, and tool_responses.content
 *                       (the ATR engine reads both on tool output, so
 *                       indirect injection riding in on a tool result is seen)
 *   tool_args        -> tool_calls.raw_arguments
 *   tool_response    -> tool_responses.content
 *   tool_name        -> tool_calls.name and tool_responses.name
 *   tool_description -> tools.description
 *   content          -> the text of user and assistant messages, tool call
 *                       arguments and tool results. System and developer
 *                       messages are not read: the ATR engine sees them only
 *                       when a producer sends them as user input.
 *
 * What does not carry over:
 *   - Conditions on other fields, and patterns RE2 cannot express, are
 *     dropped. A rule whose detection is "all" loses its meaning if any
 *     condition is dropped, so it is skipped; an "any" rule keeps the
 *     conditions that convert. The ATR engine tests an "all" rule's
 *     conditions on one event, so here they must hold on one item of one
 *     surface; a rule whose conditions share no surface is skipped.
 *   - The ATR engine folds Unicode confusables and normalizes NFKC/NFC before
 *     matching; Quarry matches the raw text, so obfuscated input can match in
 *     ATR and not here.
 *   - JavaScript and RE2 differ in a few classes: JS `\s` also matches `\v`,
 *     NBSP, the other Unicode spaces and the BOM (RE2's is ASCII only), JS `.` excludes `\r`, and a JS pattern without the
 *     `u` flag counts an astral character as two. RE2's case folding also
 *     maps U+017F to `s` and U+212A to `k`. The tests catch a
 *     difference only where a test case exercises it.
 *   - Quarry reports matches; the rules carry the ATR severity as metadata
 *     and blocking is the application's decision.
 *
 * @module agent-threat-rules/converters/quarry
 */

import type { ATRArrayCondition, ATRRule } from '../types.js';
import { regexConditionSpec } from '../regex-dialect.js';
import { toRe2 } from '../re2.js';
import { laneAllows, requiresConfirm, type Lane } from '../quality/rule-contract.js';

type Surface = 'user_messages' | 'assistant_messages' | 'tool_calls' | 'tool_responses' | 'tools';
type Target = readonly [Surface, string];

/** Quarry surface and item field read, per ATR field. */
const FIELD_TARGETS: Readonly<Record<string, readonly Target[]>> = {
  user_input: [
    ['user_messages', 'content'],
    ['tool_responses', 'content'],
  ],
  agent_output: [
    ['assistant_messages', 'content'],
    ['tool_responses', 'content'],
  ],
  tool_args: [['tool_calls', 'raw_arguments']],
  tool_response: [['tool_responses', 'content']],
  tool_name: [
    ['tool_calls', 'name'],
    ['tool_responses', 'name'],
  ],
  tool_description: [['tools', 'description']],
  content: [
    ['user_messages', 'content'],
    ['assistant_messages', 'content'],
    ['tool_calls', 'raw_arguments'],
    ['tool_responses', 'content'],
  ],
};

const SURFACES: readonly Surface[] = ['user_messages', 'assistant_messages', 'tool_calls', 'tool_responses', 'tools'];

export interface QuarryExportOptions {
  /** Which ATR rules to export, by maturity lane. Default `enforce` (stable rules). */
  readonly lane?: Lane;
}

export interface QuarryTestCase {
  readonly name: string;
  readonly expect: 'match' | 'no_match';
  readonly conversation: Conversation;
}

export interface QuarryRuleFile {
  readonly ruleId: string;
  /** File stem, e.g. `atr-2026-00432`; write `rules/<stem>.rule` and `tests/<stem>.json`. */
  readonly stem: string;
  readonly rule: string;
  /** Empty when no test case maps onto a conversation. */
  readonly tests: readonly QuarryTestCase[];
  /** ATR conditions that could not be converted, by index. */
  readonly droppedConditions: readonly number[];
  /** ATR true positives (1-based) the converted rule does not match, left out of the tests. */
  readonly uncoveredTruePositives: readonly number[];
  /** ATR test cases (labelled tp-N / tn-N) with no field that maps onto a conversation. */
  readonly unmappedCases: readonly string[];
}

export interface QuarrySkip {
  readonly ruleId: string;
  readonly reason: string;
}

export interface QuarryExport {
  readonly files: readonly QuarryRuleFile[];
  readonly skipped: readonly QuarrySkip[];
}

/**
 * A Quarry string literal. Quarry decodes it with Python string escapes, so
 * every backslash is doubled and the pattern reaches RE2 unchanged.
 */
function quarryString(s: string): string {
  const escaped = s
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    // literal_eval rejects a raw NUL, and other control characters read better escaped.
    .replace(/[\x00-\x1f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
  return `"${escaped}"`;
}

/**
 * A Quarry `regex` declaration. Quarry hands the text between the quotes to
 * RE2 without decoding escapes, so escape pairs are copied as they are and
 * only a bare quote or a line break is escaped (RE2 reads `\"`, `\n`, `\r`
 * and `\t` as those characters).
 */
function quarryRegexString(pattern: string): string {
  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === '\\' && i + 1 < pattern.length) {
      // A backslash before a line break is an identity escape in JS; RE2 reads `\n` the same way.
      const next = pattern[i + 1]!;
      out += next === '\n' ? '\\n' : next === '\r' ? '\\r' : next === '\t' ? '\\t' : ch + next;
      i++;
    } else if (ch === '"') out += '\\"';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else out += ch;
  }
  return `"${out}"`;
}

interface ConvertedCondition {
  readonly re2: string;
  readonly targets: readonly Target[];
  /** The same pattern as a JavaScript RegExp, to check which test cases still match. */
  readonly js: RegExp;
}

/** One ATR regex condition, or null when it cannot be converted. */
function convertCondition(cond: ATRArrayCondition): ConvertedCondition | null {
  const targets = FIELD_TARGETS[cond.field];
  if (!targets || cond.operator !== 'regex' || !cond.value) return null;
  const spec = regexConditionSpec(cond.value);
  const re2 = toRe2(spec.source);
  if (re2 === null) return null;
  try {
    return { re2, targets, js: new RegExp(spec.source, spec.flags) };
  } catch {
    return null; // the ATR engine cannot compile it either
  }
}

const fieldOn = (c: ConvertedCondition, surface: Surface): string | undefined =>
  c.targets.find(([s]) => s === surface)?.[1];

/** Surfaces on which every condition reads a field. */
function sharedSurfaces(conditions: readonly ConvertedCondition[]): Surface[] {
  return SURFACES.filter((s) => conditions.every((c) => fieldOn(c, s) !== undefined));
}

/**
 * The rule's `condition:` expression, one comprehension per surface (Quarry
 * warns on rules with many). Condition i is declared as `$p<i>`.
 */
function conditionExpression(conditions: readonly ConvertedCondition[], logic: 'any' | 'all'): string {
  const surfaces = logic === 'all' ? sharedSurfaces(conditions) : SURFACES;
  const clauses = surfaces.flatMap((s) => {
    const tests = conditions.flatMap((c, i) => {
      const field = fieldOn(c, s);
      return field === undefined ? [] : [`($p${i} in x.${field})`];
    });
    if (tests.length === 0) return [];
    const body = tests.length === 1 ? tests[0] : `(${tests.join(logic === 'all' ? ' and ' : ' or ')})`;
    return [`(any x in ${s} where ${body})`];
  });
  return clauses.join('\n    or ');
}

// --- Test conversations ---

interface ToolCall {
  readonly id: string;
  readonly type: 'function';
  readonly function: { readonly name: string; readonly arguments: string };
}

type Message =
  | { readonly role: 'user'; readonly content: string }
  | { readonly role: 'assistant'; readonly content: string | null; readonly tool_calls?: readonly ToolCall[] }
  | { readonly role: 'tool'; readonly tool_call_id: string; readonly content: string };

interface ToolDefinition {
  readonly type: 'function';
  readonly function: {
    readonly name: string;
    readonly description: string;
    readonly parameters: { readonly type: 'object'; readonly properties: Record<string, never> };
  };
}

export interface Conversation {
  readonly messages: readonly Message[];
  readonly tools?: readonly ToolDefinition[];
}

const CALL_ID = 'call_atr_1';
const DEFAULT_TOOL = 'atr_test_tool';

/**
 * Where a plain-text test case goes. ATR's `input` key is the text of
 * whatever the rule reads, so a rule that reads only tool output gets a tool
 * result, and one that reads only tool arguments gets a tool call.
 */
function plainTextKey(fields: ReadonlySet<string>): string {
  // A named field says where the text belongs; `content` alone does not.
  for (const f of ['tool_response', 'tool_args', 'user_input', 'agent_output', 'tool_description']) {
    if (fields.has(f)) return f;
  }
  return 'user_input';
}

/**
 * Tool-call argument text Quarry accepts: the text itself when it is a JSON
 * object, else `{"input": <text>}`. The wrapped text is JSON-escaped, so a
 * pattern that relies on a quote, backslash or control character in it can
 * miss; the coverage check then reports that true positive.
 */
function asJsonObjectText(text: string): string {
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) return text;
  } catch {
    // not JSON
  }
  return JSON.stringify({ input: text });
}

/** The conversation for one ATR test case, or null when the case has no mappable field. */
function testConversation(tc: Record<string, unknown>, fields: ReadonlySet<string>): Conversation | null {
  const str = (v: unknown): string => (typeof v === 'string' ? v : JSON.stringify(v));
  const parts: Record<string, string> = {};
  for (const key of ['user_input', 'agent_output', 'tool_args', 'tool_response', 'tool_description']) {
    if (tc[key] !== undefined && tc[key] !== null) parts[key] = str(tc[key]);
  }
  const plain = tc['input'] ?? tc['content'];
  if (typeof plain === 'string') {
    const key = plainTextKey(fields);
    parts[key] ??= plain;
  }
  const name = typeof tc['tool_name'] === 'string' && tc['tool_name'] ? (tc['tool_name'] as string) : undefined;
  if (Object.keys(parts).length === 0 && name === undefined) return null;

  const tool = name ?? DEFAULT_TOOL;
  const messages: Message[] = [];
  if (parts['user_input'] !== undefined) messages.push({ role: 'user', content: parts['user_input'] });
  // Quarry requires tool-call arguments to be a JSON object, so other text is wrapped as one.
  const args = parts['tool_args'] === undefined ? undefined : asJsonObjectText(parts['tool_args']);
  const calls = parts['tool_args'] !== undefined || parts['tool_response'] !== undefined || name !== undefined;
  if (calls) {
    messages.push({
      role: 'assistant',
      content: null,
      tool_calls: [{ id: CALL_ID, type: 'function', function: { name: tool, arguments: args ?? '{}' } }],
    });
    if (parts['tool_response'] !== undefined) messages.push({ role: 'tool', tool_call_id: CALL_ID, content: parts['tool_response'] });
  }
  if (parts['agent_output'] !== undefined) messages.push({ role: 'assistant', content: parts['agent_output'] });
  const description = parts['tool_description'];
  if (messages.length === 0) messages.push({ role: 'user', content: '' });
  return description === undefined
    ? { messages }
    : { messages, tools: [{ type: 'function', function: { name: tool, description, parameters: { type: 'object', properties: {} } } }] };
}

/** The items of each surface in a conversation, as Quarry exposes them. */
function surfaceItems(conv: Conversation): Record<Surface, Record<string, string>[]> {
  const items: Record<Surface, Record<string, string>[]> = {
    user_messages: [],
    assistant_messages: [],
    tool_calls: [],
    tool_responses: [],
    tools: [],
  };
  const callNames = new Map<string, string>();
  for (const m of conv.messages) {
    if (m.role === 'user') items.user_messages.push({ content: m.content });
    if (m.role === 'assistant') {
      items.assistant_messages.push({ content: m.content ?? '' });
      for (const call of m.tool_calls ?? []) {
        callNames.set(call.id, call.function.name);
        items.tool_calls.push({ name: call.function.name, raw_arguments: call.function.arguments });
      }
    }
    if (m.role === 'tool') items.tool_responses.push({ content: m.content, name: callNames.get(m.tool_call_id) ?? '' });
  }
  for (const t of conv.tools ?? []) items.tools.push({ name: t.function.name, description: t.function.description });
  return items;
}

/** Does the converted rule match this conversation, judged with the JS patterns? */
function ruleMatches(conditions: readonly ConvertedCondition[], logic: 'any' | 'all', conv: Conversation): boolean {
  const items = surfaceItems(conv);
  const hit = (c: ConvertedCondition, item: Record<string, string>, field: string): boolean => {
    const value = item[field];
    c.js.lastIndex = 0;
    return typeof value === 'string' && c.js.test(value);
  };
  if (logic === 'all') {
    return sharedSurfaces(conditions).some((s) =>
      items[s].some((item) => conditions.every((c) => hit(c, item, fieldOn(c, s)!))),
    );
  }
  return conditions.some((c) => c.targets.some(([s, f]) => items[s].some((item) => hit(c, item, f))));
}

interface Tests {
  readonly cases: readonly QuarryTestCase[];
  readonly uncovered: readonly number[];
  readonly unmapped: readonly string[];
}

/**
 * The rule's test conversations. A true positive that only a dropped
 * condition caught would fail in Quarry, so it is left out and reported.
 */
function buildTests(rule: ATRRule, converted: readonly ConvertedCondition[], logic: 'any' | 'all'): Tests {
  const fields = new Set(arrayConditions(rule)?.map((c) => c.field) ?? []);
  const cases: QuarryTestCase[] = [];
  const uncovered: number[] = [];
  const unmapped: string[] = [];
  const add = (list: unknown, expect: 'match' | 'no_match', label: string): void => {
    if (!Array.isArray(list)) return;
    list.forEach((tc, i) => {
      const conversation = tc && typeof tc === 'object' ? testConversation(tc as Record<string, unknown>, fields) : null;
      if (!conversation) {
        unmapped.push(`${expect === 'match' ? 'tp' : 'tn'}-${i + 1}`);
        return;
      }
      if (expect === 'match' && !ruleMatches(converted, logic, conversation)) {
        uncovered.push(i + 1);
        return;
      }
      cases.push({ name: `${label}-${i + 1}`, expect, conversation });
    });
  };
  add(rule.test_cases?.true_positives, 'match', 'atr-true-positive');
  add(rule.test_cases?.true_negatives, 'no_match', 'atr-true-negative');
  return { cases, uncovered, unmapped };
}

function arrayConditions(rule: ATRRule): readonly ATRArrayCondition[] | null {
  return Array.isArray(rule.detection.conditions) ? rule.detection.conditions : null;
}

/** Convert one ATR rule, or say why it cannot be converted. */
export function ruleToQuarry(rule: ATRRule): QuarryRuleFile | QuarrySkip {
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
  if (logic === 'all' && sharedSurfaces(converted).length === 0) {
    return { ruleId: rule.id, reason: 'an "all" rule whose conditions read different Quarry surfaces can never match' };
  }
  if (!/^ATR-\d{4}-\d{5}$/.test(rule.id)) return { ruleId: rule.id, reason: 'rule id is not in ATR-YYYY-NNNNN form' };

  const metadata: [string, string][] = [
    ['title', rule.title],
    ['severity', rule.severity],
    ['category', String(rule.tags.category)],
    ['maturity', String(rule.maturity ?? '')],
    ['rule_version', String(rule.rule_version ?? 1)],
    ['source', `Agent Threat Rules ${rule.id} (https://github.com/Agent-Threat-Rule/agent-threat-rules)`],
  ];
  const text = [
    `rule ${quarryString(rule.id)}`,
    'metadata:',
    ...metadata.map(([k, v]) => `    ${k} = ${quarryString(v)}`),
    'strings:',
    // SPEC §6.4: every condition matches case-insensitively.
    ...converted.map((c, i) => `    $p${i} = ${quarryRegexString(c.re2)} regex nocase`),
    'condition:',
    `    ${conditionExpression(converted, logic)}`,
    '',
  ].join('\n');
  const tests = buildTests(rule, converted, logic);
  return {
    ruleId: rule.id,
    stem: rule.id.toLowerCase(),
    rule: text,
    tests: tests.cases,
    droppedConditions: dropped,
    uncoveredTruePositives: tests.uncovered,
    unmappedCases: tests.unmapped,
  };
}

/** Convert the rules in `lane` (default `enforce`). Embedding-confirmed rules are left out of enforce and alert. */
export function rulesToQuarry(rules: readonly ATRRule[], options: QuarryExportOptions = {}): QuarryExport {
  const lane = options.lane ?? 'enforce';
  const files: QuarryRuleFile[] = [];
  const skipped: QuarrySkip[] = [];
  for (const rule of rules) {
    if (rule.status === 'draft' || rule.status === 'deprecated') continue;
    if (!laneAllows(rule.maturity, lane)) continue;
    if (lane !== 'hunt' && requiresConfirm(rule)) {
      skipped.push({ ruleId: rule.id, reason: 'needs embedding confirmation, which this export does not run' });
      continue;
    }
    const out = ruleToQuarry(rule);
    if ('reason' in out) skipped.push(out);
    else files.push(out);
  }
  return { files, skipped };
}

/** `quarry.yaml`, loading the exported rules. */
export const QUARRY_CONFIG = 'config_version: 2\nrules:\n  - rules/\n';

/** `check_atr_tests.py`: runs each rule's ATR test conversations through Quarry. */
export const QUARRY_CHECK_SCRIPT = `"""Run the ATR test cases exported with these rules through Quarry.

From this directory, with Quarry installed:

    python check_atr_tests.py

Each tests/<rule>.json holds that rule's ATR true positives (expect "match")
and true negatives (expect "no_match") as conversations. A case passes when
the named rule's verdict is what the case expects; other rules may match too.
Exits 1 if any case fails or any scan is incomplete.
"""

import json
import sys
from pathlib import Path

from quarry import DSLScanner
from quarry.config import QuarryConfig

HERE = Path(__file__).resolve().parent


def main() -> int:
    scanner = DSLScanner(QuarryConfig.from_yaml(HERE / "quarry.yaml"))
    total = failed = 0
    for path in sorted((HERE / "tests").glob("*.json")):
        suite = json.loads(path.read_text(encoding="utf-8"))
        for case in suite["cases"]:
            total += 1
            result = scanner.scan_data(case["conversation"])
            if not result.is_complete:
                failed += 1
                print(f"{suite['rule']} {case['name']}: scan {result.completion_state}")
                continue
            matched = suite["rule"] in result.rule_matches
            if matched != (case["expect"] == "match"):
                failed += 1
                print(f"{suite['rule']} {case['name']}: expected {case['expect']}")
    print(f"{total - failed}/{total} cases pass")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
`;
