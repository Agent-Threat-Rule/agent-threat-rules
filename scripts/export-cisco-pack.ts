#!/usr/bin/env npx tsx
/**
 * scripts/export-cisco-pack.ts
 *
 * Generate the ATR rule pack vendored by cisco-ai-defense/skill-scanner at
 * `skill_scanner/data/packs/atr/` (pack.yaml + README.md + 10 category
 * signature files).
 *
 * WHY THIS EXISTS
 *
 * The pack was refreshed twice by hand (2.0.12 in PR #99, 3.5.6 in PR #142)
 * with a converter that never lived in this repository. That made the single
 * largest downstream deployment of ATR unreproducible: nobody could tell which
 * ATR commit a shipped pack came from, and the previously shipped pack still
 * advertises a precision figure this project has since retired. This script
 * makes the pack a build artifact instead of a hand edit.
 *
 * Usage:
 *   npx tsx scripts/export-cisco-pack.ts --out dist/cisco-pack
 *   npx tsx scripts/export-cisco-pack.ts --out dist/cisco-pack \
 *       --diff-against /path/to/skill-scanner/skill_scanner/data/packs/atr
 *
 * Options:
 *   --rules <dir>          Rule source directory (default: rules)
 *   --out <dir>            Output pack directory (default: dist/cisco-pack)
 *   --version <v>          Pack version (default: package.json version)
 *   --ref <git-ref>        Ref used in atr_url permalinks (default: main)
 *   --diff-against <dir>   Existing pack directory to diff against
 *   --reproduce-vendored   Reproduce the banner comments of the pack already
 *                          vendored downstream (generator name, and a per-file
 *                          rule count that counts files rather than emitted
 *                          signatures). Only for byte-for-byte verification.
 *   --json                 Emit the run summary as JSON on stdout
 *
 * Exit codes: 0 on success, 1 on any failure (missing measurement file,
 * unparsable rule, empty output).
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBenchmarkClaims } from './cisco-pack/benchmarks.js';
import {
  diffPacks,
  readExistingPack,
  summariseByCategory,
  summariseByMaturity,
  summariseBySeverity,
} from './cisco-pack/diff.js';
import { loadRules } from './cisco-pack/load-rules.js';
import { renderPackManifest, renderReadme, renderSignatureFile, type RenderContext } from './cisco-pack/render.js';
import { buildSignatureFiles, DEFAULT_REPO_URL } from './cisco-pack/transform.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

interface Args {
  readonly rules: string;
  readonly out: string;
  readonly version: string;
  readonly ref: string;
  readonly diffAgainst?: string;
  readonly reproduceVendored: boolean;
  readonly json: boolean;
}

function readFlag(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) throw new Error(`${name} needs a value`);
  return value;
}

function parseArgs(argv: readonly string[]): Args {
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as { version?: string };
  const version = readFlag(argv, '--version') ?? pkg.version;
  if (!version) throw new Error('no version: pass --version or fix package.json');
  return {
    rules: resolve(readFlag(argv, '--rules') ?? join(REPO_ROOT, 'rules')),
    out: resolve(readFlag(argv, '--out') ?? join(REPO_ROOT, 'dist', 'cisco-pack')),
    version,
    ref: readFlag(argv, '--ref') ?? 'main',
    diffAgainst: readFlag(argv, '--diff-against'),
    reproduceVendored: argv.includes('--reproduce-vendored'),
    json: argv.includes('--json'),
  };
}

function countOwaspAgenticCategories(rulesDir: string): number {
  const { rules } = loadRules(rulesDir, { includeDeprecated: true });
  const categories = new Set<string>();
  for (const { rule } of rules) {
    const refs = (rule as unknown as { references?: { owasp_agentic?: unknown[] } }).references
      ?.owasp_agentic;
    for (const ref of refs ?? []) categories.add(String(ref).split(':')[0].trim());
  }
  return categories.size;
}

function writePack(args: Args): { total: number; summary: Record<string, unknown> } {
  const loaded = loadRules(args.rules, { includeDeprecated: args.reproduceVendored });
  if (loaded.rules.length === 0) throw new Error(`no rules found under ${args.rules}`);

  const files = buildSignatureFiles(loaded.rules, {
    ref: args.ref,
    repoUrl: DEFAULT_REPO_URL,
    omitMaturity: args.reproduceVendored,
  });
  const claims = loadBenchmarkClaims(REPO_ROOT, countOwaspAgenticCategories(args.rules));
  const context: RenderContext = {
    version: args.version,
    repoUrl: DEFAULT_REPO_URL,
    benchmarkSentence: claims.sentence,
    benchmarkReadmeLine: claims.readmeLine,
    reproduceVendored: args.reproduceVendored,
    filesPerCategory: loaded.filesPerCategory,
  };

  mkdirSync(join(args.out, 'signatures'), { recursive: true });
  for (const file of files) {
    writeFileSync(join(args.out, file.path), renderSignatureFile(file, context), 'utf8');
  }
  writeFileSync(join(args.out, 'pack.yaml'), renderPackManifest(files, context), 'utf8');
  writeFileSync(join(args.out, 'README.md'), renderReadme(files, context, loaded.excluded), 'utf8');

  const all = files.flatMap((file) => [...file.signatures]);
  const summary: Record<string, unknown> = {
    version: args.version,
    ruleFilesOnDisk: Object.values(loaded.filesPerCategory).reduce((a, b) => a + b, 0),
    emitted: all.length,
    excluded: loaded.excluded,
    patterns: all.reduce((sum, s) => sum + s.patterns.length, 0),
    byCategory: Object.fromEntries(summariseByCategory(all)),
    bySeverity: Object.fromEntries(summariseBySeverity(all)),
    byMaturity: Object.fromEntries(summariseByMaturity(all)),
  };

  if (args.diffAgainst) {
    const previous = readExistingPack(resolve(args.diffAgainst));
    const diff = diffPacks(previous, files);
    summary.diff = {
      previousTotal: previous.size,
      added: diff.added.length,
      removed: diff.removed.length,
      changed: diff.changed.filter((c) => c.fields.length > 0).length,
      changedOnlyByNewField: diff.changed.filter((c) => c.fields.length === 0).length,
      unchanged: diff.unchanged,
      addedByCategory: Object.fromEntries(summariseByCategory(diff.added)),
      addedBySeverity: Object.fromEntries(summariseBySeverity(diff.added)),
      removedIds: diff.removed,
      changedFieldHistogram: diff.changed
        .flatMap((c) => c.fields)
        .reduce<Record<string, number>>((acc, f) => ({ ...acc, [f]: (acc[f] ?? 0) + 1 }), {}),
      newFieldHistogram: diff.changed
        .flatMap((c) => c.fieldsAdded)
        .reduce<Record<string, number>>((acc, f) => ({ ...acc, [f]: (acc[f] ?? 0) + 1 }), {}),
      changedIds: diff.changed.filter((c) => c.fields.length > 0).map((c) => c.atr_id),
    };
  }
  return { total: all.length, summary };
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const { total, summary } = writePack(args);
  if (args.json) {
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    return;
  }
  process.stdout.write(`wrote ${total} signatures to ${args.out}\n`);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`export-cisco-pack failed: ${(error as Error).message}\n`);
  process.exit(1);
}
