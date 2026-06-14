/**
 * Vendor the authoritative MITRE ATLAS technique id->name map so ATD/ATR mapping
 * verification can run offline and deterministically. Refreshable like a feed:
 * re-run when ATLAS publishes new techniques.
 *
 *   npx tsx scripts/atd/sync-atlas-allowlist.ts
 *   -> data/threat-frameworks/mitre-atlas.json
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml";
const ID_RE = /^AML\.T\d{4}(\.\d{3})?$/;

const text = await (await fetch(URL)).text();
const doc = yaml.load(text);

// ATLAS.yaml nests techniques inside matrices; walk the whole tree and collect
// every {id, name} where id is a technique id. Robust to structure changes.
const valids: Record<string, string> = {};
function collect(node: unknown): void {
  if (Array.isArray(node)) {
    node.forEach(collect);
  } else if (node && typeof node === "object") {
    const o = node as Record<string, unknown>;
    if (typeof o.id === "string" && ID_RE.test(o.id) && typeof o.name === "string") {
      valids[o.id] = o.name;
    }
    Object.values(o).forEach(collect);
  }
}
collect(doc);

mkdirSync(join(REPO, "data/threat-frameworks"), { recursive: true });
writeFileSync(
  join(REPO, "data/threat-frameworks/mitre-atlas.json"),
  JSON.stringify(
    { framework: "MITRE ATLAS", source: URL, idField: "mitre_atlas", count: Object.keys(valids).length, valids },
    null,
    2,
  ) + "\n",
);
console.log(`vendored ${Object.keys(valids).length} MITRE ATLAS technique ids -> data/threat-frameworks/mitre-atlas.json`);
