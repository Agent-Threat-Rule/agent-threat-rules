/**
 * The event shapes the garak obfuscation eval reports, kept apart from the eval
 * so the shape a number was measured in is a named thing, not a literal buried
 * in a loop.
 *
 * WHY SHAPE IS REPORTED WITH EVERY NUMBER: src/engine.ts:373 maps an event type
 * to a rule source type (EVENT_TYPE_TO_SOURCE) and skips every rule whose
 * `agent_source.type` differs, and src/engine.ts:404,466 applies a separate
 * compound gate when `scanContext === 'skill'`. The same text through two
 * shapes is two different measurements.
 */
import type { AgentEvent } from "../../src/types.js";

export type ObfuscationShapeName =
  "llm_input" | "tool_response" | "tool_call+skill";

export interface ObfuscationShape {
  readonly name: ObfuscationShapeName;
  readonly note: string;
  readonly build: (text: string) => AgentEvent;
}

const TS = "2026-08-19T00:00:00.000Z";

/**
 * `llm_input` — the human typed it. Maps to source `llm_io`, so only llm_io
 * rules are admitted. Identical to the `llm-input` channel in
 * src/corpus-event.ts:promptChannelShapes.
 */
const llmInput = (text: string): AgentEvent =>
  Object.freeze({
    type: "llm_input",
    timestamp: TS,
    content: text,
    fields: Object.freeze({ user_input: text }),
  }) as AgentEvent;

/**
 * `tool_response` — a tool / MCP / RAG result carried it in. Maps to source
 * `mcp_exchange`, and src/engine.ts:425 additionally admits llm_io rules here.
 * Included because `atr guard` emits only tool_call and tool_response events;
 * llm_input is a shape the shipped hook never produces.
 */
const toolResponse = (text: string): AgentEvent =>
  Object.freeze({
    type: "tool_response",
    timestamp: TS,
    content: text,
    fields: Object.freeze({ tool_response: text }),
  }) as AgentEvent;

/**
 * `tool_call` with `scanContext: 'skill'` — the document-scan presentation.
 * Source filtering is skipped (src/engine.ts:412) but the compound gate at
 * src/engine.ts:466 then rejects any rule that is not `scan_target: skill|both`,
 * which is why this shape sees far fewer rules in practice, not more.
 */
const toolCallSkill = (text: string): AgentEvent =>
  Object.freeze({
    type: "tool_call",
    timestamp: TS,
    content: text,
    scanContext: "skill",
    fields: Object.freeze({ content: text }),
  }) as AgentEvent;

export const OBFUSCATION_SHAPES: readonly ObfuscationShape[] = Object.freeze([
  {
    name: "llm_input",
    note: "source llm_io only; the shape the shipped guard never emits",
    build: llmInput,
  },
  {
    name: "tool_response",
    note: "source mcp_exchange + llm_io admitted; indirect-injection channel the guard does emit",
    build: toolResponse,
  },
  {
    name: "tool_call+skill",
    note: "document scan; source filter skipped but scan_target skill|both compound gate applies",
    build: toolCallSkill,
  },
]);
