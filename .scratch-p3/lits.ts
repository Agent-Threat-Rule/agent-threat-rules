import { requirementOf } from "./../scripts/lib/regex-literals.js";
const pat = process.argv[2];
const r = requirementOf(pat);
console.log("constrained:", r.constrained);
for (const alt of r.alternatives) console.log("  ALT:", JSON.stringify(alt));
