// FP probe: run a candidate regex (or a rule file's conditions) over the whole
// measurement corpus and print every hit.
// Usage: node .scratch-p3/fp.mjs '<regex source>'
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const CORPORA = ['data/skill-benchmark/benign', 'data/benign-corpus-extended', 'data/benign-code'];
function files(dir) {
  const out = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...files(full));
    else if (e.endsWith('.jsonl') || e.endsWith('.md')) out.push(full);
  }
  return out;
}
export function loadSamples() {
  const s = [];
  for (const c of CORPORA) {
    for (const f of files(c)) {
      const raw = readFileSync(f, 'utf8');
      if (f.endsWith('.md')) { s.push({ text: raw, file: f }); continue; }
      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        try { const o = JSON.parse(line); if (typeof o.text === 'string' && o.text) s.push({ text: o.text, file: f }); } catch {}
      }
    }
  }
  return s;
}

if (process.argv[2]) {
  const src = process.argv[2];
  const re = new RegExp(src, src.includes('\\u{') || src.includes('\\p{') ? 'iu' : 'i');
  const samples = loadSamples();
  let hits = 0;
  for (const s of samples) {
    const m = s.text.match(re);
    if (m) { hits++; console.log(`HIT ${s.file}\n   ...${s.text.slice(Math.max(0, m.index - 90), m.index + m[0].length + 90).replace(/\n/g, ' ⏎ ')}...\n`); }
  }
  console.log(`--- ${hits} / ${samples.length} samples ---`);
}
