import { readFileSync } from "node:fs";
import yaml from "js-yaml";
import { requirementOf, literalsOf } from "../scripts/lib/regex-literals.js";
const doc: any = yaml.load(readFileSync(process.argv[2], "utf8"));
const conds: any[] = doc?.detection?.conditions ?? [];
console.log(`RULE ${doc.id}  condition:${doc.detection.condition}  conds=${conds.length}  agent_source.type=${doc.agent_source?.type}`);
for (const [i, c] of conds.entries()) {
  const r = requirementOf(String(c.value));
  console.log(`\n[${i + 1}] field=${c.field} op=${c.operator}`);
  console.log(`    constrained=${r.constrained}`);
  console.log(`    MANDATORY-LITERAL DNF (must contain ALL of one alternative):`);
  for (const alt of r.alternatives) console.log(`      - ${JSON.stringify(alt)}`);
  console.log(`    all literals mentioned: ${JSON.stringify(literalsOf(r))}`);
}
