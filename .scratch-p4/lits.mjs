import { readFileSync } from 'node:fs';
const { requirementOf } = await import('./scripts/lib/regex-literals.ts').catch(async () => await import('../scripts/lib/regex-literals.js'));
const probes = JSON.parse(readFileSync(process.argv[2], 'utf8'));
for (const [name, pat] of Object.entries(probes)) {
  const r = requirementOf(pat);
  console.log(`\n${name}  constrained=${r.constrained}`);
  for (const alt of r.alternatives.slice(0, 12)) console.log('   AND ', JSON.stringify(alt));
  if (r.alternatives.length > 12) console.log(`   ... ${r.alternatives.length} alternatives`);
}
