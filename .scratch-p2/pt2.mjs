// AND-semantics tester (condition: all)
import fs from 'fs';
const pats = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const samples = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const c = pats.map(p => ({ name: p.name, re: new RegExp(p.value, 'i') }));
let bad = 0;
for (const s of samples) {
  const fired = c.filter(x => x.re.test(s.text));
  const got = fired.length === c.length ? 'hit' : 'miss';
  const ok = got === s.expect; if (!ok) bad++;
  console.log((ok ? '  ok  ' : 'FAIL  ') + s.id.padEnd(30) + ' expect=' + s.expect.padEnd(5) + ' got=' + got.padEnd(5) + ' [' + fired.map(f=>f.name).join('+') + ']');
}
console.log('=== ' + bad + ' mismatches of ' + samples.length);
