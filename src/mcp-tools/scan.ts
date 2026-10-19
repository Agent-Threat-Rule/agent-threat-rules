/**
 * atr_scan MCP tool - Scan content for agent threats
 *
 * Runs all configured detection layers:
 * - Layer 1: Regex pattern matching (always)
 * - Layer 2: Skill behavioral fingerprinting (if configured)
 * - Layer 3: Semantic LLM-as-judge (if configured and triggered)
 *
 * @module agent-threat-rules/mcp-tools/scan
 */

import type { ATREngine } from '../engine.js';
import type { AgentEvent, AgentEventType } from '../types.js';

export interface ScanInput {
  content: string;
  event_type?: string;
  min_severity?: string;
}

const SEVERITY_ORDER: Record<string, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const VALID_EVENT_TYPES: ReadonlySet<string> = new Set([
  'llm_input',
  'llm_output',
  'tool_call',
  'tool_response',
  'agent_behavior',
  'multi_agent_message',
]);

export async function handleScan(engine: ATREngine, args: Record<string, unknown>): Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}> {
  const MAX_CONTENT_LENGTH = 500_000;
  const content = args['content'];
  if (typeof content !== 'string' || content.trim().length === 0) {
    return {
      content: [{ type: 'text', text: 'Error: "content" is required and must be a non-empty string.' }],
      isError: true,
    };
  }
  if (content.length > MAX_CONTENT_LENGTH) {
    return {
      content: [{ type: 'text', text: `Error: content exceeds maximum size of ${MAX_CONTENT_LENGTH} characters.` }],
      isError: true,
    };
  }

  const eventTypeRaw = (args['event_type'] as string) ?? 'llm_input';
  if (!VALID_EVENT_TYPES.has(eventTypeRaw)) {
    return {
      content: [{ type: 'text', text: `Error: Invalid event_type "${eventTypeRaw}". Valid types: ${[...VALID_EVENT_TYPES].join(', ')}` }],
      isError: true,
    };
  }

  const minSeverity = ((args['min_severity'] as string) ?? 'informational').toLowerCase();
  if (!(minSeverity in SEVERITY_ORDER)) {
    return {
      content: [{ type: 'text', text: `Error: Invalid min_severity "${minSeverity}". Valid: informational, low, medium, high, critical` }],
      isError: true,
    };
  }

  const minIdx = SEVERITY_ORDER[minSeverity] ?? 0;

  const event: AgentEvent = {
    type: eventTypeRaw as AgentEventType,
    timestamp: new Date().toISOString(),
    content: content,
    fields: {
      user_input: content,
      agent_output: content,
      tool_response: content,
      content: content,
    },
  };

  // Use evaluateWithVerdict() to run all configured layers
  const { verdict, layersUsed } = await engine.evaluateWithVerdict(event);

  const filtered = verdict.matches.filter(
    (m) => (SEVERITY_ORDER[m.rule.severity] ?? 0) >= minIdx
  );

  const result = {
    threats_found: filtered.length,
    scan_timestamp: event.timestamp,
    event_type: eventTypeRaw,
    layers_used: layersUsed,
    verdict: {
      outcome: verdict.outcome,
      reason: verdict.reason,
    },
    matches: filtered.map((m) => ({
      rule_id: m.rule.id,
      title: m.rule.title,
      severity: m.rule.severity,
      category: m.rule.tags.category,
      confidence: Math.round(m.confidence * 100),
      description: m.rule.description,
      matched_patterns: m.matchedPatterns,
      recommended_actions: m.rule.response.actions,
      // A model's decision (semantic judge, embedding, semantic layer) is reported
      // without counting toward verdict.outcome unless the engine enforces them.
      decided_by: m.decidedBy ?? null,
    })),
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  };
}
