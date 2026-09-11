// FP scan: load ONLY the candidate rules (from .scratch-p2/staged/) into an
// engine, then run every benign sample in data/benign-corpus-extended/*.jsonl
// plus data/skill-benchmark/benign + data/benign-code through it.
import { ATREngine } from '../dist/engine.js';
import fs from 'fs';
import path from 'path';

const eng = new ATREngine({ rulesDir: '.scratch-p2/staged', lane: 'hunt' });
await eng.loadRules();
console.log('candidate rules loaded: ' + eng.rules.length + ' -> ' + eng.rules.map(r=>r.id).join(','));

const samples = [];
const dir = 'data/benign-corpus-extended';
for (const f of fs.readdirSync(dir)) {
  if (!f.endsWith('.jsonl')) continue;
  for (const line of fs.readFileSync(path.join(dir, f), 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const o = JSON.parse(line);
      const t = o.text ?? o.content ?? o.input;
      if (typeof t === 'string' && t.length) samples.push({ text: t, src: f });
    } catch {}
  }
}
for (const d of ['data/skill-benchmark/benign', 'data/benign-code']) {
  if (!fs.existsSync(d)) continue;
  const walk = (p) => {
    for (const e of fs.readdirSync(p, { withFileTypes: true })) {
      const fp = path.join(p, e.name);
      if (e.isDirectory()) walk(fp);
      else if (/\.(md|py|js|ts|sh|json|ya?ml|txt)$/i.test(e.name)) {
        try { samples.push({ text: fs.readFileSync(fp, 'utf8'), src: fp }); } catch {}
      }
    }
  };
  walk(d);
}
console.log('benign samples: ' + samples.length);

const types = ['tool_response', 'llm_input'];
const fps = [];
for (const s of samples) {
  for (const ty of types) {
    const ev = { type: ty, content: s.text };
    if (ty === 'llm_input') ev.scanContext = 'skill';
    const m = await eng.evaluate(ev);
    for (const hit of m) fps.push({ rule: hit.rule.id, src: s.src, ty, snip: s.text.slice(0, 400) });
  }
}
const byRule = {};
for (const f of fps) (byRule[f.rule] ??= []).push(f);
console.log('=== FP TOTAL: ' + fps.length + ' ===');
for (const [r, list] of Object.entries(byRule)) {
  console.log('--- ' + r + ': ' + list.length + ' FP');
  for (const f of list.slice(0, 6)) console.log('    [' + f.ty + '] ' + f.src + ' :: ' + JSON.stringify(f.snip.slice(0, 260)));
}
if (!fps.length) console.log('CLEAN');
