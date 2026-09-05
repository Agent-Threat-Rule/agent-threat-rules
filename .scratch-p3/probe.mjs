// Probe harness: evaluate arbitrary strings against the full rule corpus.
// Usage: node .scratch-p3/probe.mjs <cases.json>
// cases.json: [{ "id": "...", "type": "tool_response", "content": "...", "scanContext": "skill"? }]
import { ATREngine } from '../dist/engine.js';
import { readFileSync } from 'node:fs';

const casesPath = process.argv[2];
const cases = JSON.parse(readFileSync(casesPath, 'utf8'));

const engine = new ATREngine({ rulesDir: 'rules', lane: 'hunt' });
const n = await engine.loadRules();
console.error(`[harness] ${n} rules loaded, lane=${engine.activeLane ?? 'hunt'}`);

for (const c of cases) {
  const ev = {
    type: c.type ?? 'tool_response',
    timestamp: new Date().toISOString(),
    content: c.content,
    ...(c.scanContext ? { scanContext: c.scanContext } : {}),
    ...(c.fields ? { fields: c.fields } : {}),
  };
  const matches = engine.evaluate(ev);
  const ids = matches.map((m) => `${m.rule?.id ?? m.rule_id ?? m.id}`);
  console.log(`${ids.length === 0 ? 'MISS ' : 'HIT  '} ${c.id}  ${ids.length ? ids.join(',') : '-'}`);
}
