import type { AgentEvent, ATRRule, ATRTrace } from "./types.js";

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
    context_window: 'llm_input',
    memory_access: 'llm_input',
    skill_lifecycle: 'tool_call',
    skill_permission: 'tool_call',
    skill_chain: 'tool_call',
  };

  let type: AgentEvent['type'] = SOURCE_TO_EVENT[sourceType] ?? 'llm_input';

  // NOTE: previously, a tool_call rule with a plain-string TP was downgraded to
  // an llm_input event. That mis-tested tool_call-native rules: a shell command or
  // SQL string IS a tool invocation, and evaluating it as llm_input made the engine
  // apply its cross-context confidence penalty, dropping the match below threshold
  // so the rule's own documented attack tested as not_triggered (false failure that
  // silently left broken rules in the enforce lane). We now keep the native
  // tool_call type — the string flows in via `content` (below), and tool_name is
  // pinned to "" (below) so the engine's tool_name fallback never treats the
  // content as a tool name. Plain-string TPs of tool_call rules therefore test in
  // their real (native) context.

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
  // Always set tool_name (even empty) to prevent engine fallback
  // from using event.content as tool_name for tool_call events
  fields['tool_name'] = toolName;
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

  // For content-based rules, set content and agent_message fields
  fields['content'] = content;
  fields['agent_message'] = content;

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
    fields,
    sessionId: 'test-session',
    agentId: 'test-agent',
    ...(trace ? { trace } : {}),
  };
}
