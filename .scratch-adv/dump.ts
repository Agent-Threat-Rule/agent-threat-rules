import { readFileSync, writeFileSync } from "node:fs";
import yaml from "js-yaml";
const doc: any = yaml.load(readFileSync(process.argv[2], "utf8"));
const c = doc.detection.conditions;
writeFileSync(process.argv[3], JSON.stringify({ c1: String(c[0].value), c2: String(c[1].value) }, null, 0));
console.log("ok");
