import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

// --- sample loader: jsonl {text}, plus raw skill/code files ---
const samples = [];
function pushJsonl(p, src) {
  let t; try { t = readFileSync(p, 'utf8'); } catch { return; }
  for (const line of t.split('\n')) {
    if (!line.trim()) continue;
    try { const o = JSON.parse(line); if (typeof o.text === 'string') samples.push({ text: o.text, src: o.source ?? src, id: o.source_id ?? o.label ?? '' }); } catch {}
  }
}
function walkFiles(d, out) {
  let e; try { e = readdirSync(d); } catch { return; }
  for (const f of e) { const p = join(d, f); let s; try { s = statSync(p); } catch { continue; }
    if (s.isDirectory()) walkFiles(p, out); else if (s.size < 2_000_000) out.push(p); }
}
for (const f of readdirSync('data/benign-corpus-extended')) if (f.endsWith('.jsonl')) pushJsonl(join('data/benign-corpus-extended', f), f);
const rawFiles = [];
walkFiles('data/skill-benchmark/benign', rawFiles);
walkFiles('data/benign-code', rawFiles);
for (const p of rawFiles) { let t; try { t = readFileSync(p, 'utf8'); } catch { continue; } samples.push({ text: t, src: 'file', id: p }); }
console.log(`corpus samples: ${samples.length}`);

const probes = JSON.parse(readFileSync(process.argv[2], 'utf8'));
for (const [name, pat] of Object.entries(probes)) {
  let re; try { re = new RegExp(pat, 'i'); } catch (err) { console.log(`${name}: REGEX ERROR ${err.message}`); continue; }
  const hits = [];
  for (const s of samples) { if (re.test(s.text)) hits.push(s); }
  console.log(`\n=== ${name}: ${hits.length} / ${samples.length}`);
  for (const h of hits.slice(0, 6)) {
    const m = h.text.match(re);
    console.log(`   [${h.src}:${String(h.id).slice(-60)}] ...${JSON.stringify(String(m[0]).slice(0, 180))}`);
  }
}
