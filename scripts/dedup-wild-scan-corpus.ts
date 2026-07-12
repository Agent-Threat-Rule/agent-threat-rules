#!/usr/bin/env npx tsx
/**
 * dedup-wild-scan-corpus.ts
 *
 * Cross-source deduplication for the wild-scan pipeline. The same underlying
 * MCP server / skill can appear independently in multiple collected sources:
 *   - data/wild-scan/official-registry/  (MCP Registry, one file per unique package)
 *   - data/wild-scan/github-topic/       (GitHub topic search, one file per repo)
 *   - data/wild-scan/package-deps/       (npm/PyPI SDK-dependents, one file per package)
 *   - data/wild-scan/clawhub/            (ClawHub skills -- separate ecosystem,
 *                                          rarely overlaps with the other three)
 *
 * This does NOT merge/rewrite the source files. It produces a manifest
 * (data/wild-scan/dedup-manifest.json) grouping records that refer to the
 * same real-world entity, so a downstream scan phase can process each unique
 * entity once instead of re-scanning the same server 2-3x under different
 * source identities.
 *
 * Identity keys (union-find merge -- two records sharing ANY key are the
 * same entity):
 *   - github:<owner>/<repo>   (lowercased) -- from repository.url / html_url /
 *     full_name / an io.github.<owner>/<repo> style server name
 *   - npm:<package>           -- from packages[].identifier (registryType npm)
 *     or an npm__<pkg>.json / pkg-npm-<pkg> file
 *   - pypi:<package>          -- same idea for PyPI
 *
 * Deliberately does NOT scan free-text (README bodies, descriptions) for
 * github.com links -- that would false-match on repos merely MENTIONED in a
 * README (e.g. "see also X/Y"), not the record's own identity.
 *
 * Usage: npx tsx scripts/dedup-wild-scan-corpus.ts [--roots dir1,dir2,...]
 */

import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { join, basename } from 'node:path';

interface Record_ {
  source: string;
  file: string;
  keys: string[];
}

const DEFAULT_SOURCES: Record<string, string> = {
  'official-registry': 'data/wild-scan/official-registry',
  'github-topic': 'data/wild-scan/github-topic',
  'package-deps': 'data/wild-scan/package-deps',
  clawhub: 'data/wild-scan/clawhub',
};

// Priority for picking a "primary" source to represent a merged group
// (richest content first: github-topic captures full README + descriptor +
// entrypoint; official-registry is structured install metadata;
// package-deps is thinner npm/pypi metadata; clawhub is its own ecosystem).
const SOURCE_PRIORITY = ['github-topic', 'official-registry', 'package-deps', 'clawhub'];

function normGithub(url: string | undefined | null): string | null {
  if (!url) return null;
  const m = /github\.com[/:]([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#]|$)/i.exec(url);
  if (!m) return null;
  return `github:${m[1].toLowerCase()}/${m[2].toLowerCase()}`;
}

function extractKeysOfficialRegistry(data: any): string[] {
  const keys: string[] = [];
  const entry = data.latest_registry_entry ?? data;
  const srv = entry?.server ?? entry;
  if (!srv) return keys;
  const repoUrl = srv.repository?.url;
  const g = normGithub(repoUrl);
  if (g) keys.push(g);
  // server.name convention: io.github.<owner>/<repo>
  if (typeof srv.name === 'string' && srv.name.startsWith('io.github.')) {
    const rest = srv.name.slice('io.github.'.length);
    const parts = rest.split('/');
    if (parts.length >= 2) keys.push(`github:${parts[0].toLowerCase()}/${parts[1].toLowerCase()}`);
  }
  const packages = srv.packages ?? [];
  if (Array.isArray(packages)) {
    for (const p of packages) {
      const type = (p.registryType || p.registry_name || '').toLowerCase();
      const id = p.identifier;
      if (!id) continue;
      if (type === 'npm') keys.push(`npm:${id.toLowerCase()}`);
      if (type === 'pypi') keys.push(`pypi:${id.toLowerCase()}`);
    }
  }
  return keys;
}

function extractKeysGithubTopic(data: any): string[] {
  const keys: string[] = [];
  const g = normGithub(data.html_url) ?? (data.full_name ? `github:${data.full_name.toLowerCase()}` : null);
  if (g) keys.push(g);
  return keys;
}

function extractKeysPackageDeps(data: any, filename: string): string[] {
  const keys: string[] = [];
  const g = normGithub(data.repository_url);
  if (g) keys.push(g);
  const m = /^(npm|pypi)__(.+)\.json$/.exec(filename);
  if (m) keys.push(`${m[1]}:${m[2].replace(/__/g, '/').toLowerCase()}`);
  return keys;
}

function extractKeysClawhub(data: any): string[] {
  // ClawHub skills are a distinct marketplace; only merge if a record
  // explicitly links a GitHub repo (structured field, not README text).
  const keys: string[] = [];
  const g = normGithub(data.homepage) ?? normGithub(data.repository_url);
  if (g) keys.push(g);
  return keys;
}

function loadRecords(sources: Record<string, string>): Record_[] {
  const records: Record_[] = [];
  for (const [source, dir] of Object.entries(sources)) {
    if (!existsSync(dir)) {
      console.error(`  (skip ${source}: ${dir} not found)`);
      continue;
    }
    const files = readdirSync(dir).filter((f) => f.endsWith('.json'));
    for (const file of files) {
      let data: any;
      try {
        data = JSON.parse(readFileSync(join(dir, file), 'utf8'));
      } catch {
        continue;
      }
      let keys: string[] = [];
      if (source === 'official-registry') keys = extractKeysOfficialRegistry(data);
      else if (source === 'github-topic') keys = extractKeysGithubTopic(data);
      else if (source === 'package-deps') keys = extractKeysPackageDeps(data, file);
      else if (source === 'clawhub') keys = extractKeysClawhub(data);
      records.push({ source, file, keys: [...new Set(keys)] });
    }
    console.error(`  loaded ${files.length} files from ${source}`);
  }
  return records;
}

// Union-find over records connected by shared keys.
function groupRecords(records: Record_[]): Record_[][] {
  const parent = new Map<number, number>();
  function find(i: number): number {
    while (parent.get(i) !== i) {
      const p = parent.get(i)!;
      parent.set(i, parent.get(p)!);
      i = p;
    }
    return i;
  }
  function union(a: number, b: number) {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  }
  records.forEach((_, i) => parent.set(i, i));

  const keyToFirstIdx = new Map<string, number>();
  records.forEach((rec, i) => {
    for (const k of rec.keys) {
      if (keyToFirstIdx.has(k)) {
        union(i, keyToFirstIdx.get(k)!);
      } else {
        keyToFirstIdx.set(k, i);
      }
    }
  });

  const groups = new Map<number, Record_[]>();
  records.forEach((rec, i) => {
    const root = find(i);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root)!.push(rec);
  });
  return [...groups.values()];
}

function main() {
  const args = process.argv.slice(2);
  let sources = DEFAULT_SOURCES;
  const rootsIdx = args.indexOf('--roots');
  if (rootsIdx !== -1 && args[rootsIdx + 1]) {
    const dirs = args[rootsIdx + 1].split(',');
    sources = {};
    for (const d of dirs) sources[basename(d)] = d;
  }

  console.error('Loading records...');
  const records = loadRecords(sources);
  console.error(`Total records: ${records.length}`);

  console.error('Grouping by shared identity keys...');
  const groups = groupRecords(records);

  const multiSourceGroups = groups.filter((g) => new Set(g.map((r) => r.source)).size > 1);

  const manifestGroups = groups.map((g, idx) => {
    const bySourcePriority = [...g].sort(
      (a, b) => SOURCE_PRIORITY.indexOf(a.source) - SOURCE_PRIORITY.indexOf(b.source)
    );
    return {
      id: idx,
      primary: { source: bySourcePriority[0].source, file: bySourcePriority[0].file },
      members: g.map((r) => ({ source: r.source, file: r.file })),
      keys: [...new Set(g.flatMap((r) => r.keys))],
    };
  });

  const manifest = {
    total_records: records.length,
    total_unique_entities: groups.length,
    cross_source_duplicate_groups: multiSourceGroups.length,
    records_saved_by_dedup: records.length - groups.length,
    by_source_input_counts: Object.fromEntries(
      Object.keys(sources).map((s) => [s, records.filter((r) => r.source === s).length])
    ),
    groups: manifestGroups,
  };

  writeFileSync('data/wild-scan/dedup-manifest.json', JSON.stringify(manifest, null, 2) + '\n');
  console.error(
    `\nDone: ${records.length} records -> ${groups.length} unique entities ` +
      `(${multiSourceGroups.length} cross-source duplicate groups, ${manifest.records_saved_by_dedup} records saved).`
  );
  console.error('Wrote data/wild-scan/dedup-manifest.json');
}

main();
