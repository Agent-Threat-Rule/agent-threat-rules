// Evaluate a candidate 2-condition ALL rule over a case file, at regex level.
import fs from 'fs';
const cases = JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const pats = JSON.parse(fs.readFileSync(process.argv[3],'utf8')); // {c1:"...", c2:"..."}
const mk = (p) => new RegExp(p, /\\u\{|\\p\{/.test(p) ? 'iu' : 'i');
const r1 = mk(pats.c1), r2 = mk(pats.c2);
let n=0;
for (const c of cases) {
  const a = r1.test(c.text), b = r2.test(c.text);
  const fire = a && b;
  if (fire) n++;
  console.log(`${fire?'FIRE ':'silent'}  ${c.id.padEnd(34)} c1=${a?'Y':'n'} c2=${b?'Y':'n'}`);
}
console.log(`=== ${n}/${cases.length} fire`);
