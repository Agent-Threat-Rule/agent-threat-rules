/**
 * The three production event shapes this measurement charges rules on.
 *
 * WHY SHAPES ARE THE WHOLE MEASUREMENT
 *
 * The engine filters rules by `agent_source.type` against the event type, and
 * resolves condition fields differently per type. The same text through two
 * shapes can differ by more than an order of magnitude in how many rules even
 * get asked. Measuring "ATR's false positive rate" without naming the shape is
 * measuring nothing: on the malicious control sample used by
 * scripts/control-clawhub-fp.ts, `llm_input` returns ZERO matches while
 * `tool_response` returns four.
 *
 * Each shape below is copied from the adapter that actually builds it in
 * production, not invented here.
 *
 *   skill-preflight — src/adapters/nemoclaw-preflight.ts scanFile():
 *                     { type: 'tool_call', content, scanContext: 'skill' }.
 *                     This is the `pga scan` / NeMo preflight path.
 *   llm-input       — src/adapters/mastra.ts processInput() builds
 *                     { type: 'llm_input', content }; promptChannelShapes()
 *                     additionally sets fields.user_input, which only widens.
 *   tool-response   — src/hook-handler.ts's indirect-injection channel.
 *
 * llm-input and tool-response come straight from src/corpus-event.ts so this
 * harness cannot drift from the repo's canonical prompt channels. Only the
 * preflight shape is defined here, because corpus-event.ts deliberately does
 * not model scanContext.
 *
 * IMPORTANT — what `scanContext: 'skill'` does NOT mean.
 * It does not mean all 784 rules are being asked. src/corpus-event.ts
 * (skillPathCoverage) documents the compound gate: any `condition: any` rule
 * that is not `scan_target: skill|both` is unconditionally rejected on that
 * path. A 0 on this shape is a 0 for the rules the shape admits, and the
 * measurement must report that admission count alongside the rate.
 */

import type { AgentEvent } from '../../src/types.js';
import { promptChannelShapes } from '../../src/corpus-event.js';

export type ClawhubShapeName = 'skill-preflight' | 'llm-input' | 'tool-response';

export const CLAWHUB_SHAPE_NAMES: readonly ClawhubShapeName[] = Object.freeze([
  'skill-preflight',
  'llm-input',
  'tool-response',
]);

/** Frozen timestamp: the shapes must be byte-identical across shards and runs. */
const FIXED_TIMESTAMP = '2026-01-01T00:00:00.000Z';

/** src/adapters/nemoclaw-preflight.ts scanFile() — the skill-scanning shape. */
function skillPreflight(text: string): AgentEvent {
  return Object.freeze({
    type: 'tool_call' as const,
    timestamp: FIXED_TIMESTAMP,
    content: text,
    scanContext: 'skill' as const,
  });
}

export interface ClawhubShape {
  readonly name: ClawhubShapeName;
  readonly event: AgentEvent;
}

/**
 * Build all three shapes for one text.
 *
 * promptChannelShapes() is asked for its two channels by name rather than by
 * position, so a reordering upstream fails loudly here instead of silently
 * relabelling a measurement.
 */
export function clawhubShapes(text: string): readonly ClawhubShape[] {
  const channels = promptChannelShapes(text);
  const llmInput = channels.find((s) => s.name === 'llm-input');
  const toolResponse = channels.find((s) => s.name === 'tool-response');
  if (!llmInput || !toolResponse) {
    throw new Error(
      `src/corpus-event.ts promptChannelShapes() no longer provides llm-input + tool-response; got [${channels.map((s) => s.name).join(', ')}]`,
    );
  }
  return Object.freeze([
    Object.freeze({ name: 'skill-preflight' as const, event: skillPreflight(text) }),
    Object.freeze({ name: 'llm-input' as const, event: { ...llmInput.event, timestamp: FIXED_TIMESTAMP } }),
    Object.freeze({ name: 'tool-response' as const, event: { ...toolResponse.event, timestamp: FIXED_TIMESTAMP } }),
  ]);
}
