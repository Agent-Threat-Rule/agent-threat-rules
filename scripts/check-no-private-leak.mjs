#!/usr/bin/env node
/**
 * check-no-private-leak — guard so the rule-production DATA MOAT can never be
 * committed to this PUBLIC repo, even via `git add -f` (which .gitignore can't
 * stop). Stronger than .gitignore: runs in CI on every PR + locally pre-commit.
 *
 * What it blocks (the private moat, per ATR-TUNING-CONVENTION / Path B):
 *   - labeled corpora + attack-embedding reference sets
 *   - benign gate datasets
 *   - new mining/crawl scripts that belong in the private engine
 * It does NOT block the existing public engine/scripts or rule self-test cases —
 * those are the open standard (Path B keeps them public).
 *
 * Usage:
 *   node scripts/check-no-private-leak.mjs                 # checks staged files
 *   node scripts/check-no-private-leak.mjs <file> [file..] # checks given files (CI)
 *   node scripts/check-no-private-leak.mjs --base <ref>    # checks files added vs <ref>
 *
 * Exit 1 (fail) if any checked path matches a private pattern.
 */

import { execSync } from 'node:child_process';

// Private paths that must never land in the public repo. Keep in sync with
// .gitignore's "rule-production data moat" block.
const DENY = [
  /^data\/benign-gate\//,
  /^data\/corpus-raw\//,
  /^data\/attack-embeddings-v2\./,
  /^data\/(bipia|dan-sweep|garak-sweep|injecagent|tt-extract|tt-hijack)\//,
  /^data\/corpora\//,
  /^scripts\/crawl-corpora\.ts$/,
];

function changedFiles() {
  const args = process.argv.slice(2);
  const baseIdx = args.indexOf('--base');
  if (baseIdx !== -1 && args[baseIdx + 1]) {
    const base = args[baseIdx + 1];
    // Files ADDED relative to base (what a PR would introduce).
    const out = execSync(`git diff --name-only --diff-filter=ACMR ${base}...HEAD`, {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 64,
    });
    return out.split('\n').filter(Boolean);
  }
  const explicit = args.filter((a) => !a.startsWith('--'));
  if (explicit.length > 0) return explicit;
  // Default: staged files (pre-commit hook).
  const out = execSync('git diff --cached --name-only', {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 64,
  });
  return out.split('\n').filter(Boolean);
}

const files = changedFiles();
const violations = files.filter((f) => DENY.some((re) => re.test(f)));

if (violations.length > 0) {
  console.error('\n  BLOCKED: private rule-production data/scripts must not enter the public repo.');
  console.error('  These belong in the private engine (see ATR-TUNING-CONVENTION):\n');
  for (const v of violations) console.error(`    - ${v}`);
  console.error('\n  If this is a false positive, update DENY in scripts/check-no-private-leak.mjs.\n');
  process.exit(1);
}

console.log(`  check-no-private-leak: OK (${files.length} file(s) checked, 0 private leaks)`);
