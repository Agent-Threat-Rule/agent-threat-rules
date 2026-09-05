import { ATREngine } from '../dist/engine.js';
import fs from 'fs';
const eng = new ATREngine({ rulesDir: 'rules', lane: 'hunt' });
await eng.loadRules();
const lines = fs.readFileSync('data/benign-corpus-extended/p2-paper-harvest-benign-twins.jsonl','utf8').split('\n').filter(Boolean);
for (const l of lines) {
  const o = JSON.parse(l);
  for (const ty of ['tool_response','llm_input','tool_call','agent_behavior']) {
    const m = await eng.evaluate({ type: ty, content: o.text });
    const hit = m.filter(x=>x.rule.id==='ATR-2026-00030');
    if (hit.length) console.log(ty, '|', o.source_id, '|', JSON.stringify(o.text.slice(0,220)));
  }
}
