import { ATREngine } from '../dist/engine.js';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
const engine = new ATREngine({ rulesDir: '/Users/user/Downloads/atr-main-wt/rules' });
console.error(`[loaded ${await engine.loadRules()} rules]`);
const ids = new Set(['ATR-2026-02845','ATR-2026-02846','ATR-2026-02847','ATR-2026-02848','ATR-2026-02849']);
const files = [];
(function walk(d){ let e; try{e=readdirSync(d)}catch{return} for(const f of e){const p=join(d,f); const s=statSync(p); if(s.isDirectory())walk(p); else files.push(p);} })('data/skill-benchmark/benign');
let fp = 0;
for (const p of files) {
  let t; try { t = readFileSync(p, 'utf8'); } catch { continue; }
  const m = engine.evaluate({ type: 'tool_response', timestamp: new Date().toISOString(), content: t, scanContext: 'skill' });
  for (const x of m) if (ids.has(x.rule.id)) { fp++; console.log('FP', x.rule.id, p); }
}
console.log(`benign skill files: ${files.length}  own-rule FP: ${fp}`);
