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

// As of ATLAS content release v2026.05 the data format split: content follows a
// date-based YYYY.MM version (stored in the Collection object) and the data
// FORMAT follows semver (now 6.0.0). The old flat `dist/ATLAS.yaml` is DEPRECATED
// and frozen at the v5.6.0-format content (101 techniques) — it does NOT receive
// new techniques. The current data lives under `dist/v6/`, reachable via a chain
// of tiny pointer files: dist/ATLAS-latest.yaml -> v6/ATLAS-latest.yaml ->
// v6/ATLAS-<YYYY.MM>.yaml. Resolve that chain so this stays current automatically.
const DIST_BASE = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/";
const ENTRY = "ATLAS-latest.yaml";
const ID_RE = /^AML\.T\d{4}(\.\d{3})?$/;

// A pointer file is a single short line naming another .yaml (no YAML mapping,
// i.e. no ':'). Follow pointers relative to their own directory until we reach
// the real data document.
async function fetchResolving(rel: string, depth = 0): Promise<string> {
  if (depth > 6) throw new Error(`ATLAS pointer chain too deep at ${rel}`);
  const url = new globalThis.URL(rel, DIST_BASE).href;
  const text = (await (await fetch(url)).text()).trim();
  const looksLikePointer =
    text.length < 200 && !text.includes("\n") && !text.includes(":") && text.endsWith(".yaml");
  if (looksLikePointer) {
    const dir = rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/") + 1) : "";
    return fetchResolving(dir + text, depth + 1);
  }
  return text;
}

const text = await fetchResolving(ENTRY);
const doc = yaml.load(text) as Record<string, unknown>;
const contentVersion =
  ((doc?.collection as Record<string, unknown> | undefined)?.version as string | undefined) ?? "unknown";
const formatVersion = (doc?.["format-version"] as string | undefined) ?? "unknown";

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
    {
      framework: "MITRE ATLAS",
      source: DIST_BASE + ENTRY,
      contentVersion,
      formatVersion,
      idField: "mitre_atlas",
      count: Object.keys(valids).length,
      valids,
    },
    null,
    2,
  ) + "\n",
);
console.log(
  `vendored ${Object.keys(valids).length} MITRE ATLAS technique ids ` +
    `(content ${contentVersion}, format ${formatVersion}) -> data/threat-frameworks/mitre-atlas.json`,
);
