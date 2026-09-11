import { ATREngine } from '../dist/engine.js';
import { readFileSync } from 'node:fs';
import { load } from 'js-yaml';
const engine = new ATREngine({ rulesDir: '/Users/user/Downloads/atr-main-wt/rules' });
const n = await engine.loadRules();
console.error(`[loaded ${n} rules]`);
const ruleFile = process.argv[2];
const types = (process.argv[3] ?? 'tool_call,skill').split(',');
const r = load(readFileSync(ruleFile, 'utf8'));
const id = r.id;
let fired = 0, other = 0;
for (const group of ['true_negatives']) {
  for (const tc of r.test_cases[group] ?? []) {
    for (const t of types) {
      const ev = t === 'skill'
        ? { type: 'tool_response', timestamp: new Date().toISOString(), content: tc.input, scanContext: 'skill' }
        : { type: t, timestamp: new Date().toISOString(), content: tc.input };
      const m = engine.evaluate(ev);
      const mine = m.filter(x => x.rule.id === id);
      if (mine.length) { fired++; console.log(`FP [${t}] ${JSON.stringify(tc.input).slice(0,110)}\n     -> ${mine.map(x=>x.matchedPatterns.join('|')).join(' ; ').slice(0,200)}`); }
      const others = m.filter(x => x.rule.id !== id);
      if (others.length) { other++; console.log(`  (other rules [${t}]: ${others.map(x=>x.rule.id).join(',')}) on ${JSON.stringify(tc.input).slice(0,70)}`); }
    }
  }
}
console.log(`\nOWN-RULE FP: ${fired}`);
for (const tc of r.test_cases.true_positives ?? []) {
  for (const t of types) {
    const ev = t === 'skill'
      ? { type: 'tool_response', timestamp: new Date().toISOString(), content: tc.input, scanContext: 'skill' }
      : { type: t, timestamp: new Date().toISOString(), content: tc.input };
    const m = engine.evaluate(ev).filter(x => x.rule.id === id);
    console.log(`TP [${t}] ${m.length ? 'HIT' : '*** MISS ***'}  ${JSON.stringify(tc.input).slice(0,90)}`);
  }
}
