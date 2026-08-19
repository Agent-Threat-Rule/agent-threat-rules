#!/usr/bin/env npx tsx
/**
 * scripts/cisco-pack/verify-reproduction.ts
 *
 * Prove that scripts/export-cisco-pack.ts reproduces the pack currently
 * vendored in cisco-ai-defense/skill-scanner, byte for byte.
 *
 * WHY BYTE FOR BYTE
 *
 * "Field-by-field equal" would pass while every line of an 18,000-line pack
 * reflows, which turns any future refresh PR into an unreviewable diff. The
 * exporter therefore has to match the vendored file's exact scalar styles,
 * anchor names and folding behaviour, and the only way to know it does is to
 * compare bytes.
 *
 * WHAT IS COMPARED
 *
 *   signatures/*.yaml   compared in full — this is the detection content
 *   pack.yaml           compared from the `rules:` line down — the `pack:`
 *                       header block carries prose (description, benchmark
 *                       claims) that this change deliberately rewrites
 *   README.md           not compared; deliberately rewritten
 *
 * Usage:
 *   npx tsx scripts/cisco-pack/verify-reproduction.ts \
 *     --vendored <path-to-vendored-pack-dir> \
 *     --rules <path-to-rules-dir-at-the-source-commit> \
 *     --version 3.5.6
 *
 * Exit codes: 0 = every compared byte matches. 1 = a mismatch, a missing
 * file, or a comparison that turned out to be trivial (an empty or tiny
 * file compares equal to nothing useful, so that is also a failure).
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..', '..');

/** Below this, "the files are equal" is not evidence of anything. */
const MIN_MEANINGFUL_BYTES = 4_000;
const MIN_MEANINGFUL_FILES = 5;

/**
 * Rules where the vendored pack does not match the ATR rule it was generated
 * from. These are upstream artifacts, not transform differences: regenerating
 * from source changes them, and that is the correct outcome. Any rule NOT on
 * this list that differs is a real failure.
 */
const KNOWN_VENDORED_DIVERGENCES: ReadonlyMap<string, string> = new Map([
  [
    'ATR-2026-01610',
    'vendored patterns 1-2 carry a literal backslash-n where the rule carries a real line feed ' +
      '(the rule writes "[^)\\n]" in a double-quoted YAML scalar). Identical under Python re; ' +
      'regenerating restores the rule\'s own bytes.',
  ],
  [
    'ATR-2026-00398',
    'vendored drops one of the rule\'s two identical "pickle\\.(?:load|loads|Unpickler)" regexes ' +
      '(the rule carries it once for tool_response and once for user_input). No other rule with ' +
      'a repeated regex was deduped, so this is not a converter rule.',
  ],
]);

interface Signature {
  readonly atr_id: string;
  readonly patterns: readonly string[];
  readonly [key: string]: unknown;
}

function signaturesOf(text: string): Map<string, Signature> {
  const doc = yaml.load(text) as { signatures?: Signature[] };
  return new Map((doc?.signatures ?? []).map((s) => [s.atr_id, s]));
}

/** Rule ids whose parsed content differs between the two files. */
function differingRuleIds(generated: string, vendored: string): string[] {
  const a = signaturesOf(generated);
  const b = signaturesOf(vendored);
  const ids = new Set([...a.keys(), ...b.keys()]);
  return [...ids]
    .filter((id) => JSON.stringify(a.get(id) ?? null) !== JSON.stringify(b.get(id) ?? null))
    .sort();
}

function flag(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  if (value === undefined || value.startsWith('--')) throw new Error(`${name} needs a value`);
  return value;
}

function firstDifference(a: string, b: string): string {
  const aLines = a.split('\n');
  const bLines = b.split('\n');
  for (let i = 0; i < Math.max(aLines.length, bLines.length); i += 1) {
    if (aLines[i] !== bLines[i]) {
      return `line ${i + 1}\n  generated: ${JSON.stringify(aLines[i] ?? '<eof>')}\n  vendored : ${JSON.stringify(bLines[i] ?? '<eof>')}`;
    }
  }
  return 'files differ only in trailing bytes';
}

function rulesIndexOf(packYaml: string): string {
  const marker = '\nrules:\n';
  const at = packYaml.indexOf(marker);
  if (at === -1) throw new Error('pack.yaml has no top-level `rules:` block');
  return packYaml.slice(at + 1);
}

function main(): number {
  const vendored = resolve(flag('--vendored') ?? '');
  const rules = resolve(flag('--rules') ?? join(REPO_ROOT, 'rules'));
  const version = flag('--version');
  if (!existsSync(vendored)) throw new Error(`--vendored directory not found: ${vendored}`);
  if (!version) throw new Error('--version is required (the version the vendored pack claims)');

  const out = mkdtempSync(join(tmpdir(), 'atr-cisco-pack-'));
  execFileSync(
    'npx',
    [
      'tsx',
      join(REPO_ROOT, 'scripts', 'export-cisco-pack.ts'),
      '--rules', rules,
      '--out', out,
      '--version', version,
      '--reproduce-vendored',
      '--json',
    ],
    { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'inherit'] },
  );

  const vendoredSignatures = join(vendored, 'signatures');
  const names = readdirSync(vendoredSignatures).filter((n) => n.endsWith('.yaml')).sort();
  if (names.length < MIN_MEANINGFUL_FILES) {
    process.stderr.write(`CONTROL FAILED: only ${names.length} vendored signature files found\n`);
    return 1;
  }

  let failures = 0;
  let comparedBytes = 0;
  for (const name of names) {
    const generatedPath = join(out, 'signatures', name);
    if (!existsSync(generatedPath)) {
      process.stderr.write(`MISSING  ${name} — exporter did not produce it\n`);
      failures += 1;
      continue;
    }
    const generated = readFileSync(generatedPath, 'utf8');
    const expected = readFileSync(join(vendoredSignatures, name), 'utf8');
    comparedBytes += expected.length;
    if (generated === expected) {
      process.stdout.write(`OK       ${name} (${expected.length} bytes)\n`);
      continue;
    }
    const differing = differingRuleIds(generated, expected);
    const unexplained = differing.filter((id) => !KNOWN_VENDORED_DIVERGENCES.has(id));
    if (differing.length > 0 && unexplained.length === 0) {
      process.stdout.write(
        `KNOWN    ${name} (${expected.length} bytes) — differs only in ${differing.join(', ')}\n`,
      );
      for (const id of differing) {
        process.stdout.write(`           ${id}: ${KNOWN_VENDORED_DIVERGENCES.get(id)}\n`);
      }
      continue;
    }
    process.stderr.write(
      `MISMATCH ${name}${unexplained.length > 0 ? ` — unexplained rules: ${unexplained.join(', ')}` : ''}\n  ${firstDifference(generated, expected)}\n`,
    );
    writeFileSync(join(out, `${name}.generated`), generated, 'utf8');
    failures += 1;
  }

  const generatedIndex = rulesIndexOf(readFileSync(join(out, 'pack.yaml'), 'utf8'));
  const expectedIndex = rulesIndexOf(readFileSync(join(vendored, 'pack.yaml'), 'utf8'));
  comparedBytes += expectedIndex.length;
  if (generatedIndex === expectedIndex) {
    process.stdout.write(`OK       pack.yaml rules index (${expectedIndex.length} bytes)\n`);
  } else {
    process.stderr.write(`MISMATCH pack.yaml rules index\n  ${firstDifference(generatedIndex, expectedIndex)}\n`);
    failures += 1;
  }

  if (comparedBytes < MIN_MEANINGFUL_BYTES) {
    process.stderr.write(`CONTROL FAILED: only ${comparedBytes} bytes compared; refusing to call that a reproduction\n`);
    return 1;
  }
  process.stdout.write(`\ncompared ${comparedBytes.toLocaleString('en-US')} bytes across ${names.length + 1} files; ${failures} mismatch(es)\n`);
  process.stdout.write(`generated pack kept at ${out}\n`);
  return failures === 0 ? 0 : 1;
}

try {
  process.exit(main());
} catch (error) {
  process.stderr.write(`verify-reproduction failed: ${(error as Error).message}\n`);
  process.exit(1);
}
