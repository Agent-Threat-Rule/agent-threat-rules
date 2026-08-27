import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { load } from 'js-yaml';
const samples = [];
function pushJsonl(p){ let t; try{t=readFileSync(p,'utf8')}catch{return}
  for(const l of t.split('\n')){ if(!l.trim())continue; try{const o=JSON.parse(l); if(typeof o.text==='string') samples.push({t:o.text,id:o.source_id??o.label??p});}catch{} } }
function walk(d,out){ let e; try{e=readdirSync(d)}catch{return} for(const f of e){const p=join(d,f); let s; try{s=statSync(p)}catch{continue} if(s.isDirectory())walk(p,out); else if(s.size<2_000_000)out.push(p);} }
for(const f of readdirSync('data/benign-corpus-extended')) if(f.endsWith('.jsonl')) pushJsonl(join('data/benign-corpus-extended',f));
const raw=[]; walk('data/skill-benchmark/benign',raw); walk('data/benign-code',raw);
for(const p of raw){ let t; try{t=readFileSync(p,'utf8')}catch{continue} samples.push({t,id:p}); }
console.log(`corpus ${samples.length} samples`);
for (const f of process.argv.slice(2)) {
  const r = load(readFileSync(f,'utf8'));
  console.log(`\n### ${r.id}`);
  r.detection.conditions.forEach((c,i)=>{
    const re = new RegExp(String(c.value).replace(/^\(\?[imsx]+\)/,''), 'i');
    const hits = samples.filter(s=>re.test(s.t));
    console.log(`  cond[${i}] hits=${hits.length}`);
    for(const h of hits.slice(0,5)) console.log(`      <${String(h.id).slice(-55)}> ${JSON.stringify(h.t.match(re)[0].slice(0,150))}`);
  });
}
