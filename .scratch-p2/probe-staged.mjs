import { ATREngine } from '../dist/engine.js';
import fs from 'fs';
const eng = new ATREngine({ rulesDir: '.scratch-p2/staged', lane: 'hunt' });
await eng.loadRules();
for (const c of JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))) {
  const ev = { type: c.type || 'tool_response', content: c.text };
  if (c.scanContext) ev.scanContext = c.scanContext;
  const m = await eng.evaluate(ev);
  console.log((m.length ? 'HIT  ' : 'MISS ') + c.id.padEnd(32) + ' ' + (m.map(x=>x.rule.id).join(',') || '-'));
}
