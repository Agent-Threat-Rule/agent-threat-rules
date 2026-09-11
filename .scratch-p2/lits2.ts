import { requirementOf } from "../scripts/lib/regex-literals.js";
import fs from "fs";
const r = requirementOf(fs.readFileSync(process.argv[2], "utf8"));
console.log("constrained:", r.constrained, "| alternatives:", r.alternatives.length);
console.log(JSON.stringify(r.alternatives.slice(0, 6)));
