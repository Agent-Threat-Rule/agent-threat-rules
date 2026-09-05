import { readFileSync } from 'node:fs';
import { load } from 'js-yaml';
const samples = [];
for (const l of readFileSync('data/research-mentions/corpus.jsonl', 'utf8').split('\n')) {
  if (!l.trim()) continue;
  try { const o = JSON.parse(l); samples.push({ t: o.text ?? o.content ?? o.input ?? '', id: o.id ?? o.source ?? '' }); } catch {}
}
console.log(`research-mentions samples: ${samples.length}`);
for (const f of process.argv.slice(2)) {
  const r = load(readFileSync(f, 'utf8'));
  r.detection.conditions.forEach((c, i) => {
    const re = new RegExp(String(c.value).replace(/^\(\?[imsx]+\)/, ''), 'i');
    const hits = samples.filter(s => re.test(s.t));
    console.log(`${r.id} cond[${i}] hits=${hits.length}`);
    for (const h of hits.slice(0,3)) console.log(`    <${h.id}> ${JSON.stringify(h.t.match(re)[0].slice(0,140))}`);
  });
}
