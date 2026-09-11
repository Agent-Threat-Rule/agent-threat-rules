// Run a rule's own test_cases through the REAL engine.
import { ATREngine } from '../dist/engine.js';
import fs from 'fs';
import yaml from 'js-yaml';
const doc = yaml.load(fs.readFileSync(process.argv[2],'utf8'));
const id = doc.id;
const types = (process.argv[3]||'tool_response').split(',');
const eng = new ATREngine({ rulesDir: 'rules', lane: 'hunt' });
console.error(`[engine] loaded ${await eng.loadRules()} rules`);
let tpOk=0, tpN=0, tnOk=0, tnN=0;
for (const tc of doc.test_cases.true_positives ?? []) {
  tpN++;
  let hit=false, via='';
  for (const t of types) { const m = await eng.evaluate({type:t, content: tc.input}); if (m.some(x=>x.rule.id===id)) { hit=true; via=t; break; } }
  if (hit) tpOk++;
  console.log(`TP ${hit?'FIRE ':'MISS '} (${via||'none'})  ${JSON.stringify(tc.input).slice(0,90)}`);
}
for (const tc of doc.test_cases.true_negatives ?? []) {
  tnN++;
  let hit=false, via='';
  for (const t of types) { const m = await eng.evaluate({type:t, content: tc.input}); if (m.some(x=>x.rule.id===id)) { hit=true; via=t; break; } }
  if (!hit) tnOk++;
  console.log(`TN ${hit?'FIRE!':'ok   '} (${via||'-'})  ${JSON.stringify(tc.input).slice(0,90)}`);
}
console.log(`=== ${id}: TP ${tpOk}/${tpN} fire, TN ${tnOk}/${tnN} silent`);
