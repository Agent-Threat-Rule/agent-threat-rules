import { ATREngine } from '../dist/engine.js';
import fs from 'fs';
const eng = new ATREngine({ rulesDir: 'rules', lane: 'hunt' });
await eng.loadRules();
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
let hits = 0;
for (const c of cases) {
  const ev = { type: c.type || 'tool_response', content: c.text };
  if (c.scanContext) ev.scanContext = c.scanContext;
  const m = await eng.evaluate(ev);
  const ids = m.map((x) => x.rule.id + '(' + x.rule.severity + ')');
  if (ids.length) hits++;
  console.log((ids.length ? 'HIT  ' : 'MISS ') + c.id + '  ' + (ids.join(',') || '-'));
}
console.log('--- ' + hits + '/' + cases.length + ' hit');
