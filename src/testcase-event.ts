import { RUNTIME_SOURCE_TYPE } from "./engine.js";
import type { AgentEvent, ATRRule, ATRTrace } from "./types.js";

/**
 * The tool name a tool event carries when its test case names no tool.
 *
 * A host's tool call reaches the engine through src/hook-handler.ts, which
 * fills tool_name from the host's payload. An empty string did not stand in for
 * that: src/engine.ts resolveField reads a field only when it is truthy, and on
 * a tool_call event it then falls back to event.content, so a tool_name
 * condition read the case's payload as if it were the tool's name. A name no
 * rule is written for fills the field, as the hook does, and keeps the case's
 * text out of it. A case whose rule keys on the tool names the tool. (The MCP
 * scan tool, src/mcp-tools/scan.ts, builds an event of the type its caller
 * names and sets no tool_name, so the fallback still applies there.)
 */
export const UNNAMED_TOOL = 'atr-test-tool';

/**
 * Which fields buildEventFromTestCase fills.
 *
 *   wide     every alias a rule might read the payload from, whatever the event
 *            type: the input is also offered as user_input and as tool_args, and
 *            content as agent_message. The default: atr test, the case-sensitivity
 *            gate and scripts/validate-rule-testcases.ts run a case on it.
 *   runtime  what this repository's producers put on an event of the type:
 *            content; each field the case names, taken as given (whether a
 *            producer fills it is not checked), user_input counting as the input
 *            it is an alias of; user_input on an llm_input event; and on a tool
 *            event, the tool_name and tool_args src/hook-handler.ts fills (the
 *            case's own, or UNNAMED_TOOL and the input). It approximates the
 *            hook, whose PostToolUse content is the JSON of the tool's input, with
 *            the tool's output read only from tool_input.output or .response:
 *            here a case's tool_response is the content, as the engine reads a
 *            tool_response event. The MCP scan tool (src/mcp-tools/scan.ts) copies
 *            its content into user_input, agent_output and tool_response on any
 *            type; that is not modelled.
 */
export type TestCaseFields = 'wide' | 'runtime';

export interface TestCaseEventOptions {
  readonly fields?: TestCaseFields;
  /** Build an event of this type instead of the one the rule's agent_source names. */
  readonly type?: AgentEvent['type'];
}

/**
 * Build the AgentEvent a declared test case describes.
 *
 * Extracted from src/cli.ts so scripts/validate-rule-testcases.ts can use the
 * identical routing without importing the CLI (whose module body runs main()).
 *
 * WHY IT HAS TO BE SHARED. The validator used to extract text with its own
 * chain — `tool_response ?? input ?? content ?? tool_description` — which reads
 * none of tool_args, tool_name, user_input or agent_output. 194 test cases
 * across 27 rules name their payload under one of those, so every one resolved
 * to the empty string, and the two harnesses disagreed about the same rule:
 * `pga test` passed while the validator reported every true positive as NOT
 * triggered.
 *
 * Both directions were wrong and the quiet one is worse. A true positive scored
 * empty looks like a broken rule and invites someone to "fix" a rule that
 * detects fine. A true NEGATIVE scored empty cannot trigger, so it passes — a
 * rule's declared non-detections confirmed by a harness that never read them.
 *
 * One builder, two callers. A second copy drifts the moment either is edited.
 */
export function buildEventFromTestCase(
  tc: Record<string, unknown>,
  rule: ATRRule,
  options: TestCaseEventOptions = {},
): AgentEvent {
  // Stringify any object values
  const str = (v: unknown): string => {
    if (v === undefined || v === null) return '';
    if (typeof v === 'string') return v;
    return JSON.stringify(v);
  };

  // Extract fields, handling multiple test case formats:
  // Object-style: input: { tool_name: "...", tool_args: "...", response: "..." }
  // Flat-style: input: "...", tool_response: "...", tool_name: "..."
  // Tool-call-style: tool_call: { name: "...", args: "..." }
  // Accept `user_input:` as a top-level alias for `input:` — several tool_call
  // rules write their natural-language TPs as `- user_input: "..."`, which the
  // harness previously ignored (it only read `input`), building an EMPTY event so
  // the rule's own documented attack tested as not_triggered (a false failure that
  // left the rule looking broken while it detects fine in production).
  const rawInput = tc['input'] ?? tc['user_input'];
  let input = '';
  let toolName = str(tc['tool_name']);
  let toolArgs = str(tc['tool_args']);
  let toolResponse = str(tc['tool_response']);
  const agentOutput = str(tc['agent_output']);
  // A live engine field (engine.ts resolveField, case 'agent_message') that the
  // canonical corpus shape populates, but which no rule keys on yet. Routed
  // here so the first rule that does is not greeted by a harness that silently
  // hands it an empty event.
  const agentMessage = str(tc['agent_message']);
  const toolDescription = str(tc['tool_description']);
  const rawContent = str(tc['content']);

  // Handle tool_call: { name, args } format (used by tool_call rules like ATR-2026-00098)
  const rawToolCall = tc['tool_call'];
  if (rawToolCall !== null && rawToolCall !== undefined && typeof rawToolCall === 'object' && !Array.isArray(rawToolCall)) {
    const tcObj = rawToolCall as Record<string, unknown>;
    if (tcObj['name'] && !toolName) toolName = str(tcObj['name']);
    if (tcObj['args'] && !toolArgs) toolArgs = str(tcObj['args']);
  }

  if (rawInput !== null && rawInput !== undefined && typeof rawInput === 'object' && !Array.isArray(rawInput)) {
    const inputObj = rawInput as Record<string, unknown>;
    if (inputObj['tool_name'] && !toolName) toolName = str(inputObj['tool_name']);
    if (inputObj['tool_args'] && !toolArgs) toolArgs = str(inputObj['tool_args']);
    // Handle 'response' as alias for 'tool_response' (used in ATR-065 etc.)
    if (inputObj['response'] && !toolResponse) toolResponse = str(inputObj['response']);
    if (inputObj['tool_response'] && !toolResponse) toolResponse = str(inputObj['tool_response']);
    // For object inputs, use tool_args as the primary string input.
    // If no tool_args, only use JSON-stringified input as fallback when there's
    // no other meaningful field (tool_response/response) extracted.
    if (toolArgs) {
      input = toolArgs;
    } else if (!toolResponse) {
      input = str(rawInput);
    }
  } else {
    input = str(rawInput);
  }

  // Infer event type from rule's agent_source and test case structure
  const sourceType = rule.agent_source?.type ?? 'llm_io';

  const SOURCE_TO_EVENT: Record<string, AgentEvent['type']> = {
    llm_io: 'llm_input',
    tool_call: 'tool_call',
    mcp_exchange: 'tool_response',
    agent_behavior: 'agent_behavior',
    multi_agent_comm: 'multi_agent_message',
  };
  // An extended type (context_window, skill_lifecycle, ...) is built as an event
  // of the base type the engine admits it on (RUNTIME_SOURCE_TYPE).
  const baseSourceType = Object.hasOwn(RUNTIME_SOURCE_TYPE, sourceType)
    ? RUNTIME_SOURCE_TYPE[sourceType]
    : sourceType;

  const type: AgentEvent['type'] = options.type ?? SOURCE_TO_EVENT[baseSourceType] ?? 'llm_input';
  const toolEvent = type === 'tool_call' || type === 'tool_response';

  // NOTE: previously, a tool_call rule with a plain-string TP was downgraded to
  // an llm_input event. That mis-tested tool_call-native rules: a shell command or
  // SQL string IS a tool invocation, and evaluating it as llm_input made the engine
  // apply its cross-context confidence penalty, dropping the match below threshold
  // so the rule's own documented attack tested as not_triggered (false failure that
  // silently left broken rules in the enforce lane). We now keep the native
  // tool_call type — the string flows in via `content` (below), and tool_name is
  // pinned to UNNAMED_TOOL (below) so the engine's tool_name fallback never
  // treats the content as a tool name. Plain-string TPs of tool_call rules
  // therefore test in their real (native) context.

  // Determine the primary content based on what the rule conditions check
  // Problem 2 & 3: For rules that check tool_response, the tool_response
  // should be the primary content when the event type resolves tool_response from content
  let content: string;
  if (toolResponse && type === 'tool_response') {
    // If event type is tool_response, engine resolves field:tool_response from event.content
    content = toolResponse;
  } else {
    content = input || toolDescription || rawContent || toolResponse || agentOutput || agentMessage || '';
  }

  const fields: Record<string, string> = {};

  // Populate ALL known field aliases so the engine can resolve any field name
  if (input) fields['user_input'] = input;
  if (toolResponse) fields['tool_response'] = toolResponse;
  if (agentOutput) fields['agent_output'] = agentOutput;
  if (agentMessage) fields['agent_message'] = agentMessage;
  if (toolDescription) fields['tool_description'] = toolDescription;
  // A tool event always names its tool (UNNAMED_TOOL when the case does not).
  // The empty string this used to set did not prevent the engine's fallback
  // from reading event.content as the tool_name of a tool_call event.
  fields['tool_name'] = toolName || (toolEvent ? UNNAMED_TOOL : '');
  // Production ALWAYS populates tool_args: src/hook-handler.ts builds
  // `tool_args: JSON.stringify(toolInput)` for BOTH the PreToolUse (tool_call)
  // and the PostToolUse (tool_response) event. The engine resolves this field as
  // `event.fields.tool_args ?? (event.type === 'tool_call' ? event.content :
  // undefined)` (src/engine.ts resolveField), so a test case that supplies only
  // a plain `input:` string leaves tool_args unresolvable on every non-tool_call
  // event and EVERY `field: tool_args` condition silently evaluates to false.
  // The rule then reports not_triggered on its own documented attack while
  // detecting it correctly in production — a harness defect that reads exactly
  // like a broken rule and invites weakening a rule that is right. 40 rules
  // declare `field: tool_args`.
  // This is the test-case-runner twin of the measurement-shape defect that
  // scripts/lib/corpus-event.ts fixed for the FP gate: a true positive must be
  // exercised on the same shape the benign corpus is charged against.
  // Deliberately narrower than that harness's wide shape: only the INPUT string
  // is offered as tool_args. A `tool_response:` test case asserts what a tool
  // RETURNED, which is not an argument, so pouring it into tool_args would let a
  // tool_args layer pass a TP for the wrong reason.
  const toolArgsValue = toolArgs || input;
  if (toolArgsValue) fields['tool_args'] = toolArgsValue;

  // For content-based rules, set content and agent_message fields. A case that
  // names its own agent_message keeps it: copying the content over it ran such a
  // case on its input there.
  fields['content'] = content;
  fields['agent_message'] = agentMessage || content;

  // v1.1 trace-method rules evaluate over a span DAG (OpenInference), not text.
  // When the rule declares method: trace and the test input is a JSON trace
  // ({"spans":[...]}), parse it into event.trace so the engine's trace
  // evaluator can run. Without this, trace rules can never satisfy their own
  // declared true_positives: the harness would otherwise feed the raw JSON as
  // text to the pattern fallback, whose regex expects a pre-computed synthetic
  // verdict field that is absent from a raw trace.
  let trace: ATRTrace | undefined;
  if (rule.detection?.method === 'trace') {
    let parsed: unknown =
      rawInput && typeof rawInput === 'object' && !Array.isArray(rawInput) ? rawInput : undefined;
    if (parsed === undefined) {
      try {
        parsed = JSON.parse(input);
      } catch {
        parsed = undefined; // input is not a JSON trace; leave trace unset
      }
    }
    if (parsed && typeof parsed === 'object' && Array.isArray((parsed as { spans?: unknown }).spans)) {
      trace = parsed as ATRTrace;
    }
  }

  return {
    type,
    timestamp: new Date().toISOString(),
    content,
    fields:
      options.fields === 'runtime'
        ? runtimeFields({ type, toolEvent, content, input, toolName, toolArgs, toolResponse, agentOutput, agentMessage, toolDescription })
        : fields,
    sessionId: 'test-session',
    agentId: 'test-agent',
    ...(trace ? { trace } : {}),
  };
}

interface CaseValues {
  readonly type: AgentEvent['type'];
  readonly toolEvent: boolean;
  readonly content: string;
  readonly input: string;
  readonly toolName: string;
  readonly toolArgs: string;
  readonly toolResponse: string;
  readonly agentOutput: string;
  readonly agentMessage: string;
  readonly toolDescription: string;
}

/**
 * The "runtime" field set (TestCaseFields): content; each field the case names,
 * with the value it names; the input as user_input on an llm_input event, and on
 * no other, since `user_input:` in a case is the input's alias; and for a tool
 * event, a tool name and tool arguments, which src/hook-handler.ts fills on
 * PreToolUse and PostToolUse alike (the case's own, or UNNAMED_TOOL and the input).
 */
function runtimeFields(v: CaseValues): Record<string, string> {
  const entries: ReadonlyArray<readonly [string, string]> = [
    ['content', v.content],
    ['user_input', v.type === 'llm_input' ? v.input : ''],
    ['tool_response', v.toolResponse],
    ['agent_output', v.agentOutput],
    ['agent_message', v.agentMessage],
    ['tool_description', v.toolDescription],
    ['tool_name', v.toolName || (v.toolEvent ? UNNAMED_TOOL : '')],
    ['tool_args', v.toolArgs || (v.toolEvent ? v.input : '')],
  ];
  return Object.fromEntries(entries.filter(([, value]) => value !== ''));
}

/**
 * Every type an AgentEvent can have. The engine's source filter decides which of
 * them a rule runs on: an llm_io rule also runs on tool_response events, an
 * mcp_exchange rule on tool_call events, and every rule on an mcp_exchange event
 * (src/cli/scan-handler.ts builds those), whose type maps to no source. An
 * extended agent_source type runs where its base type does (RUNTIME_SOURCE_TYPE
 * in src/engine.ts), and one the engine withholds (WITHHELD_SOURCE_TYPES) on an
 * mcp_exchange event alone.
 */
const EVENT_TYPES: readonly AgentEvent['type'][] = [
  'llm_input',
  'llm_output',
  'tool_call',
  'tool_response',
  'agent_behavior',
  'multi_agent_message',
  'mcp_exchange',
];

/**
 * The rule as `atr test` puts it in the engine: status experimental, so a draft
 * or deprecated rule is not skipped. Its agent_source.type stays as declared:
 * the engine maps an extended type itself (RUNTIME_SOURCE_TYPE in
 * src/engine.ts), and atr test reports a rule of a type the engine withholds
 * (WITHHELD_SOURCE_TYPES) as unevaluable rather than running its cases.
 */
export function asTestedRule(rule: ATRRule): ATRRule {
  return { ...rule, status: 'experimental' };
}

/** The slice of ATREngine a test case is run on. */
export interface TestCaseEngine {
  evaluate(event: AgentEvent): readonly { readonly rule: { readonly id: string } }[];
  scanSkill(text: string): readonly { readonly rule: { readonly id: string } }[];
}

/**
 * `atr test`'s verdict on one case: the wide event the case describes through
 * evaluate(), or the case's text through scanSkill(). The engine holds the rule;
 * the rule passed here routes the event.
 */
export function caseMatches(engine: TestCaseEngine, rule: ATRRule, tc: Record<string, unknown>): boolean {
  const document = String(tc['input'] ?? tc['tool_response'] ?? tc['agent_output'] ?? '');
  return firesOn(engine, rule, buildEventFromTestCase(tc, rule)) || skillMatches(engine, rule, document);
}

/**
 * Whether a case matches an event shaped the way this repository's producers
 * shape one: for every event type, the runtime field set (a tool event as the
 * hook builds it, any other with the content, each with the fields the case
 * names), or the case's text as a skill document, user_input included as the
 * input's alias. A true positive that passes caseMatches and not this matches
 * only through a value the wide event copies into a field. Not modelled: the
 * MCP scan tool's copy of its content into user_input, agent_output and
 * tool_response on any type, and an events file src/cli/scan-handler.ts passes
 * on as written.
 */
export function caseMatchesAtRuntime(engine: TestCaseEngine, rule: ATRRule, tc: Record<string, unknown>): boolean {
  const document = String(tc['input'] ?? tc['user_input'] ?? tc['tool_response'] ?? tc['agent_output'] ?? '');
  return (
    EVENT_TYPES.some((type) => firesOn(engine, rule, buildEventFromTestCase(tc, rule, { fields: 'runtime', type }))) ||
    skillMatches(engine, rule, document)
  );
}

function firesOn(engine: TestCaseEngine, rule: ATRRule, event: AgentEvent): boolean {
  return engine.evaluate(event).some((m) => m.rule.id === rule.id);
}

function skillMatches(engine: TestCaseEngine, rule: ATRRule, document: string): boolean {
  return document !== '' && engine.scanSkill(document).some((m) => m.rule.id === rule.id);
}

/** The fields a report names a case by, in the order it looks for one. */
const LABEL_FIELDS = [
  'input',
  'user_input',
  'tool_args',
  'tool_response',
  'agent_output',
  'tool_description',
  'agent_message',
  'content',
  'tool_call',
] as const;

/** The payload a report shows for a case: the first it declares, an object as JSON. */
export function caseLabel(tc: Record<string, unknown>): string {
  const value = LABEL_FIELDS.map((key) => tc[key]).find((v) => v !== undefined && v !== null && v !== '');
  if (value === undefined) return '';
  return typeof value === 'string' ? value : JSON.stringify(value);
}
