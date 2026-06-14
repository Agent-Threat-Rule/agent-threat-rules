/**
 * verify-atd-mappings — honesty gate for ATD upstream mappings. Every MITRE
 * ATLAS id cited in website/public/atd/atd-techniques.json must exist in the
 * vendored authoritative catalog (data/threat-frameworks/mitre-atlas.json),
 * so a technique can never claim a fabricated ATLAS technique.
 *   npx tsx scripts/atd/verify-atd-mappings.ts
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ATLAS: Record<string, string> = JSON.parse(readFileSync(join(REPO, "data/threat-frameworks/mitre-atlas.json"), "utf8")).valids;
const techs = JSON.parse(readFileSync(join(REPO, "website/public/atd/atd-techniques.json"), "utf8")).techniques;
const bad: string[] = [];
for (const t of techs) for (const a of t.mappings?.mitre_atlas ?? []) if (!(a in ATLAS)) bad.push(`${t.atd_id}: ${a} not in MITRE ATLAS`);
console.log(`verify-atd-mappings: ${techs.length} techniques, ${Object.keys(ATLAS).length} ATLAS ids`);
if (bad.length) { console.error("FAIL — fabricated ATLAS ids:"); bad.forEach((b) => console.error("  " + b)); process.exit(1); }
console.log("OK — all ATLAS ids valid.");
