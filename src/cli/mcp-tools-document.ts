/**
 * An MCP `tools/list` document is a list of tool definitions, not an event.
 *
 * `atr scan tools.json` on `{"tools":[{"name":"add","description":"...","inputSchema":{...}}]}`
 * — or on the JSON-RPC response `{"jsonrpc":"2.0","id":1,"result":{"tools":[...]}}` — used to
 * wrap the document as one event, find no `content` on it, skip it, and report
 * "nothing was scanned". That is the input a tool-poisoning check most often starts from.
 *
 * Each tool becomes its own `mcp_exchange` event:
 *   - `content` is the tool definition as JSON, the whole object. It carries the name, the
 *     description and the input schema, including per-parameter descriptions, extra property
 *     fields, `required` and defaults: every one of those reaches the model, and the
 *     full-schema-poisoning rules anchor on the schema structure (`inputSchema`, `properties`).
 *   - `fields.tool_name` is the tool's name and `fields.tool_description` its top-level
 *     description, for the rules that read those fields. They are set only when the definition
 *     carries them as strings, never filled with something else.
 * One event per tool keeps a finding attributable to a tool name.
 *
 * The CLI scans these events on an engine constructed with `toolDefinitions: true`, so the rules
 * written for a tool being called do not run on them (src/tool-definition-scope.ts).
 *
 * @module agent-threat-rules/cli/mcp-tools-document
 */

import type { AgentEvent } from '../types.js';

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Event types an AgentEvent carries (src/types.ts AgentEvent['type']). */
const EVENT_TYPES: ReadonlySet<string> = new Set([
  'llm_input',
  'llm_output',
  'tool_call',
  'tool_response',
  'mcp_exchange',
  'agent_behavior',
  'multi_agent_message',
]);

/**
 * An object that is already an event: string `content`, or a `type` that is an event type. Such an
 * object stays on the event path even when it also carries a `tools` array (an LLM request logged
 * with its tool list, for example): reading it as a tools/list document would drop its content.
 */
function looksLikeEvent(doc: JsonObject): boolean {
  return typeof doc['content'] === 'string' || (typeof doc['type'] === 'string' && EVENT_TYPES.has(doc['type']));
}

/** The tools array of a `tools/list` result, bare or inside a JSON-RPC envelope; else null. */
function toolsArrayOf(doc: unknown): unknown[] | null {
  if (!isObject(doc)) return null;
  if (looksLikeEvent(doc)) return null;
  if (Array.isArray(doc['tools'])) return doc['tools'];
  const result = doc['result'];
  if (isObject(result) && Array.isArray(result['tools'])) return result['tools'];
  return null;
}

/** One mcp_exchange event for one tool definition. */
export function toolDefinitionToEvent(tool: JsonObject, timestamp: string): AgentEvent {
  const name = tool['name'];
  const description = tool['description'];
  const fields: Record<string, string> = {
    ...(typeof name === 'string' && name !== '' ? { tool_name: name } : {}),
    ...(typeof description === 'string' && description !== '' ? { tool_description: description } : {}),
  };
  return {
    type: 'mcp_exchange',
    timestamp,
    content: JSON.stringify(tool),
    ...(Object.keys(fields).length > 0 ? { fields } : {}),
  };
}

/**
 * Events for a `tools/list` document, or null when the input is not one.
 *
 * Accepted: `{"tools":[...]}`, `{"result":{"tools":[...]}}` (a JSON-RPC response), and a
 * non-empty JSON array whose every element is one of those (a log of several responses).
 * A document that lists no tools yields an empty array, so the caller reports that nothing
 * was scanned instead of a clean result. A tools entry that is not an object yields an event
 * with no content, which the caller counts as skipped. An object that is already an event (string
 * content, or an event type) is never read as a tools/list document, tools array or not.
 */
export function toolsDocumentToEvents(parsed: unknown): AgentEvent[] | null {
  const documents = Array.isArray(parsed) ? parsed : [parsed];
  if (documents.length === 0) return null;
  const toolLists = documents.map(toolsArrayOf);
  if (toolLists.some((list) => list === null)) return null;

  const timestamp = new Date().toISOString();
  return (toolLists as unknown[][]).flatMap((tools) =>
    tools.map((tool): AgentEvent =>
      isObject(tool)
        ? toolDefinitionToEvent(tool, timestamp)
        : { type: 'mcp_exchange', timestamp, content: '' },
    ),
  );
}
