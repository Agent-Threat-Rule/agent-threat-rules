import { readFileSync, writeFileSync } from "node:fs";
import yaml from "js-yaml";
const doc: any = yaml.load(readFileSync(process.argv[2], "utf8"));
const out: Record<string,string> = {};
doc.detection.conditions.forEach((c: any, i: number) => { out["c" + (i+1)] = String(c.value); });
writeFileSync(process.argv[3], JSON.stringify(out));
console.log("ok " + Object.keys(out).join(","));
