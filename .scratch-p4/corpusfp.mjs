import { ATREngine } from '../dist/engine.js';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
const engine = new ATREngine({ rulesDir: '/Users/user/Downloads/atr-main-wt/rules' });
console.error(`[loaded ${await engine.loadRules()} rules]`);
const ids = new Set(process.argv.slice(2));
const samples = [];
function pushJsonl(p){ let t; try{t=readFileSync(p,'utf8')}catch{return}
  for(const l of t.split('\n')){ if(!l.trim())continue; try{const o=JSON.parse(l); if(typeof o.text==='string') samples.push({t:o.text,id:o.source_id??o.label??p});}catch{} } }
function walk(d,out){ let e; try{e=readdirSync(d)}catch{return} for(const f of e){const p=join(d,f); let s; try{s=statSync(p)}catch{continue} if(s.isDirectory())walk(p,out); else if(s.size<2_000_000)out.push(p);} }
for(const f of readdirSync('data/benign-corpus-extended')) if(f.endsWith('.jsonl')) pushJsonl(join('data/benign-corpus-extended',f));
const raw=[]; walk('data/skill-benchmark/benign',raw); walk('data/benign-code',raw);
for(const p of raw){ let t; try{t=readFileSync(p,'utf8')}catch{continue} samples.push({t,id:p}); }
console.log(`samples ${samples.length}`);
const types = ['llm_input','tool_response','tool_call','multi_agent_message'];
const counts = {}; const shown = {};
for (const s of samples) {
  for (const ty of types) {
    let m;
    try { m = engine.evaluate({ type: ty, timestamp: new Date().toISOString(), content: s.t }); } catch { continue; }
    for (const x of m) if (ids.has(x.rule.id)) {
      const k = `${x.rule.id}|${ty}`; counts[k]=(counts[k]??0)+1;
      if((shown[k]??0)<3){ shown[k]=(shown[k]??0)+1; console.log(`FP ${k} <${String(s.id).slice(-50)}> ${JSON.stringify(x.matchedPatterns.join('|')).slice(0,120)}`); }
    }
  }
  // skill path
  let m2; try { m2 = engine.evaluate({ type:'tool_response', timestamp:new Date().toISOString(), content:s.t, scanContext:'skill' }); } catch { continue; }
  for (const x of m2) if (ids.has(x.rule.id)) { const k=`${x.rule.id}|skill`; counts[k]=(counts[k]??0)+1;
    if((shown[k]??0)<3){shown[k]=(shown[k]??0)+1; console.log(`FP ${k} <${String(s.id).slice(-50)}>`);} }
}
console.log('\n--- totals ---'); if(!Object.keys(counts).length) console.log('0 false positives across all channels');
for(const [k,v] of Object.entries(counts)) console.log(k, v);
