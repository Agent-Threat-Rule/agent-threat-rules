import { requirementOf } from "../scripts/lib/regex-literals.js";
for (const p of process.argv.slice(2)) {
  const r = requirementOf(p);
  console.log("PATTERN: " + p);
  console.log("  constrained: " + r.constrained);
  console.log("  alternatives: " + JSON.stringify(r.alternatives));
}
