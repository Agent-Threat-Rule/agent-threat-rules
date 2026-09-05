import { ATREngine } from '../dist/engine.js';
import fs from 'fs';
const target = process.argv[3] || null;
const eng = new ATREngine({ rulesDir: 'rules', lane: 'hunt' });
const n = await eng.loadRules();
console.error(`[engine] loaded ${n} rules`);
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
let tgt = 0;
for (const c of cases) {
  const ev = { type: c.type || 'tool_response', content: c.text };
  if (c.scanContext) ev.scanContext = c.scanContext;
  const m = await eng.evaluate(ev);
  const ids = m.map((x) => x.rule.id);
  const hitTarget = target ? ids.includes(target) : ids.length > 0;
  if (hitTarget) tgt++;
  const others = ids.filter((i) => i !== target);
  console.log(`${hitTarget ? 'FIRE ' : 'silent'}  ${c.id.padEnd(34)}  ${target ? (hitTarget ? target : '-') : ''}${others.length ? '   [other:' + others.join(',') + ']' : ''}`);
}
console.log(`=== ${tgt}/${cases.length} fired ${target || '(any rule)'}`);
