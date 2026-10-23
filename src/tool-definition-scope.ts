/**
 * Which rules apply to an MCP tool definition.
 *
 * A `tools/list` document defines tools; it calls none. `atr scan` turns each definition into an
 * mcp_exchange event (src/cli/mcp-tools-document.ts), and an mcp_exchange event is filtered against
 * no source type, so without a scope every rule runs on it, including the rules written for a tool
 * being called: they read the called tool's name, arguments or output and ask whether that call is
 * dangerous. On a definition the name is the defined tool's name and the content is its schema, so
 * those rules flag every definition whose name contains delete, exec, upload, ... Measured on 710
 * benign definitions from 45 official and vendor MCP servers (data/measurements/mcp-tools-list-benign/):
 * 54 of the 58 hunt-lane flags came from such rules.
 *
 * The scope, applied when an engine is constructed with `toolDefinitions: true` (ATREngineConfig):
 *   - a rule whose agent_source.type is not `tool_call` runs as before. That covers the mcp_exchange
 *     rules (tool poisoning, full-schema poisoning, written for MCP content) and the llm_io rules
 *     (text that reaches the model), and the extended types (skill_*, context_window, ...), which
 *     describe what a rule reads rather than a call;
 *   - a `tool_call` rule runs only if one of its conditions reads `tool_description`: the description
 *     is part of the definition, so such a rule was written for what a definition carries. The test is
 *     per rule: the rule is then evaluated whole, its other conditions included (ATR-2026-00441 also
 *     reads tool_name and tool_args);
 *   - a `tool_call` rule in TOOL_IDENTITY_RULES runs: its subject is the tool's identity (its name and
 *     what it claims to be), a property of the definition, not of a call. Listed by id because its
 *     fields (tool_name, content) are the same fields the call rules read; the reason is given per rule.
 * Every other `tool_call` rule (the ones that read tool_name, tool_args or content to judge a call)
 * does not run. The scope is derived from each rule's own agent_source and conditions; no rule file
 * changes, and an engine without `toolDefinitions` is unaffected. It is reference-engine scan-context
 * behaviour, set only by `atr scan` for a tools/list document (docs/ARCHITECTURE.md §3.2).
 *
 * @module agent-threat-rules/tool-definition-scope
 */

import type { ATRRule } from './types.js';

/**
 * tool_call rules whose subject is the identity of the tool, kept in the tool-definition scope. One
 * entry per rule, with the reason; add a rule here only when its conditions judge what the tool is,
 * never what a call does.
 */
export const TOOL_IDENTITY_RULES: Readonly<Record<string, string>> = Object.freeze({
  'ATR-2026-00060':
    'Skill impersonation: typosquatted, trust-prefixed or version-spoofed tool names, and descriptions ' +
    'that claim to replace the original tool. Both are properties of a tool definition.',
});

type RuleShape = Partial<Pick<ATRRule, 'id' | 'agent_source' | 'detection'>>;

/** The fields a rule's conditions read, in either condition format (array or named map, incl. sequence steps). */
export function fieldsReadBy(rule: RuleShape): ReadonlySet<string> {
  const fields = new Set<string>();
  const conditions = rule.detection?.conditions as unknown;
  const visit = (c: unknown): void => {
    if (!c || typeof c !== 'object') return;
    const rec = c as Record<string, unknown>;
    if (typeof rec['field'] === 'string') fields.add(rec['field']);
    if (Array.isArray(rec['steps'])) rec['steps'].forEach(visit);
  };
  if (Array.isArray(conditions)) conditions.forEach(visit);
  else if (conditions && typeof conditions === 'object') Object.values(conditions).forEach(visit);
  return fields;
}

/** Whether `rule` runs on an MCP tool definition (see the module comment for the criterion). */
export function appliesToToolDefinition(rule: RuleShape): boolean {
  if (rule.agent_source?.type !== 'tool_call') return true;
  if (fieldsReadBy(rule).has('tool_description')) return true;
  return typeof rule.id === 'string' && Object.hasOwn(TOOL_IDENTITY_RULES, rule.id);
}
