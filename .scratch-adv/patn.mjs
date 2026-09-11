import fs from 'fs';
const cases = JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const pats = JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
const mode = process.argv[4] || 'any';
const mk = (p) => new RegExp(p, /\\u\{|\\p\{/.test(p) ? 'iu' : 'i');
const rs = Object.keys(pats).sort().map(k=>[k,mk(pats[k])]);
let n=0;
for (const c of cases) {
  const res = rs.map(([k,r])=>[k,r.test(c.text)]);
  const fire = mode==='all' ? res.every(([,v])=>v) : res.some(([,v])=>v);
  if (fire) n++;
  console.log(`${fire?'FIRE ':'silent'}  ${c.id.padEnd(32)} ${res.map(([k,v])=>k+'='+(v?'Y':'n')).join(' ')}`);
}
console.log(`=== ${n}/${cases.length} fire (${mode})`);
