/**
 * How many rules each shape can even ask about.
 *
 * A flagged-rate is a fraction, and the denominator that matters is not
 * "784 rules" — it is "the rules the engine admitted on this shape". Reporting
 * 0.4% without that number invites the reading "784 rules were quiet", when the
 * truth may be "31 rules were quiet and 753 were never asked".
 *
 * Run: npx tsx scripts/clawhub-shape-admission.ts
 */

import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sourceTypeAdmits } from '../src/engine.js';
import { loadRulesFromDirectory } from '../src/loader.js';
import { skillPathCoverage } from '../src/corpus-event.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function main(): void {
  const rules = loadRulesFromDirectory(join(REPO_ROOT, 'rules'));
  // status deprecated/draft are skipped by the engine on every shape.
  const live = rules.filter((r) => r.status !== 'deprecated' && r.status !== 'draft');
  const blocked = new Set(skillPathCoverage(live).map((g) => g.ruleId));

  // The engine's own source filter: an llm_input event has source llm_io, a
  // tool_response event mcp_exchange (EVENT_TYPE_TO_SOURCE in src/engine.ts).
  const admittedOn = (eventSource: string) => {
    const admitted = live.filter((r) => sourceTypeAdmits(r.agent_source?.type, eventSource));
    const byType = new Map<string, number>();
    for (const r of admitted) byType.set(r.agent_source.type, (byType.get(r.agent_source.type) ?? 0) + 1);
    return `${admitted.length}  (${[...byType].map(([t, n]) => `${t} ${n}`).join(' + ')})`;
  };

  console.log(`rules on disk           ${rules.length}`);
  console.log(`  minus deprecated/draft ${live.length}  <- every shape starts here`);
  console.log('');
  console.log(`skill-preflight  admitted ${live.length - blocked.size}  (compound gate rejects ${blocked.size})`);
  // llm_input -> source llm_io: llm_io rules, and context_window rules
  // (RUNTIME_SOURCE_TYPE).
  console.log(`llm-input        admitted ${admittedOn('llm_io')}`);
  // tool_response -> source mcp_exchange, plus llm_io (and context_window)
  // rules via the indirect-injection allowance.
  console.log(`tool-response    admitted ${admittedOn('mcp_exchange')}`);
  console.log('');
  const counts = new Map<string, number>();
  for (const r of live) counts.set(r.agent_source.type, (counts.get(r.agent_source.type) ?? 0) + 1);
  console.log('agent_source.type distribution:', JSON.stringify(Object.fromEntries([...counts].sort((a, b) => b[1] - a[1]))));
}

main();
