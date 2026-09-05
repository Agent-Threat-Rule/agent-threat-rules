import { ATREngine } from '../dist/engine.js';
import { readFileSync } from 'node:fs';
import { load } from 'js-yaml';
const engine = new ATREngine({ rulesDir: '/Users/user/Downloads/atr-main-wt/rules' });
await engine.loadRules();
const r = load(readFileSync(process.argv[2], 'utf8'));
const types = process.argv[3].split(',');
for (const tc of r.test_cases.true_positives) {
  for (const t of types) {
    const m = engine.evaluate({ type: t, timestamp: new Date().toISOString(), content: tc.input });
    const others = m.filter(x => x.rule.id !== r.id).map(x => x.rule.id);
    console.log(`[${t}] mine=${m.some(x=>x.rule.id===r.id)?'HIT':'MISS'} others=[${others.join(',')}]  ${JSON.stringify(tc.input).slice(0,80)}`);
  }
}
