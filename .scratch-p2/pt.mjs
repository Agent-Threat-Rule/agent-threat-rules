// Pattern tester: node pt.mjs <patternsFile.json> <samplesFile.json>
// patterns: [{name, value}]   samples: [{id, text, expect:"hit"|"miss"}]
import fs from 'fs';
const pats = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const samples = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const compiled = pats.map(p => ({ name: p.name, re: new RegExp(p.value, /\\u\{|\\p\{/.test(p.value) ? 'iu' : 'i') }));
let bad = 0;
for (const s of samples) {
  const fired = compiled.filter(c => c.re.test(s.text)).map(c => c.name);
  const got = fired.length ? 'hit' : 'miss';
  const ok = got === s.expect;
  if (!ok) bad++;
  console.log((ok ? '  ok  ' : 'FAIL  ') + s.id.padEnd(34) + ' expect=' + s.expect.padEnd(5) + ' got=' + got.padEnd(5) + ' ' + fired.join(','));
}
console.log('=== ' + bad + ' mismatches of ' + samples.length);
