#!/usr/bin/env node
/**
 * reconcile-rule-count.mjs — keep the ATR rule count consistent across the repo.
 *
 * Ground truth for the rule count is the set of `rules/**\/*.yaml` files in git
 * (every rule file carries a top-level `id: ATR-...`). Two derived caches restate
 * that number:
 *   - stats.json           -> ruleCount.total   (propagated to README / docs / MCP)
 *   - data/stats.json      -> rules.total       (used by the website + tooling)
 *
 * These caches drift whenever rules are added/removed without regenerating them,
 * and were historically fixed by hand with `chore(stats): reconcile ...` commits.
 * This script recomputes the disk count and writes it into BOTH caches so they
 * can never diverge from disk. Run it in CI on every push to main
 * (.github/workflows/reconcile-stats.yml) to close the drift window automatically.
 *
 * Scope: only the `total` field — the number that is cited and that drifts. The
 * status breakdown (stable/experimental/draft) and byCategory remain owned by the
 * existing generators (sync-stats.ts / sync-stats-from-measurements.ts).
 *
 * Usage:
 *   node scripts/reconcile-rule-count.mjs           # reconcile in place (write)
 *   node scripts/reconcile-rule-count.mjs --check    # report drift, exit 1, write nothing
 */
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const RULES_DIR = join(REPO_ROOT, 'rules');
const ID_RE = /^id:\s*ATR-/m;
const CHECK = process.argv.includes('--check');

/** Count rule files on disk (a rule = a *.yaml carrying a top-level `id: ATR-`). */
function countRules(dir) {
  let n = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) n += countRules(p);
    else if (entry.isFile() && entry.name.endsWith('.yaml') && ID_RE.test(readFileSync(p, 'utf8'))) n++;
  }
  return n;
}

const diskCount = countRules(RULES_DIR);
let drift = false;

/**
 * Reconcile one cache file's `total` to the disk count.
 * Edits only the total's digits in place (surgical) so the diff is a single line
 * and the file's existing formatting is preserved exactly.
 */
function reconcile(relPath, blockKey) {
  const abs = join(REPO_ROOT, relPath);
  const text = readFileSync(abs, 'utf8');
  const json = JSON.parse(text);
  const block = json[blockKey] || {};
  const before = block.total;
  if (before === diskCount) {
    console.log(`[reconcile] ${relPath}: ${blockKey}.total=${before} — in sync`);
    return;
  }
  drift = true;
  console.log(`[reconcile] ${relPath}: ${blockKey}.total ${before} -> ${diskCount}${CHECK ? ' (drift)' : ' (fixed)'}`);
  if (CHECK) return;
  // Surgical replace: the "total": N inside the target block (total is the first key).
  const re = new RegExp(`("${blockKey}"\\s*:\\s*\\{[^{}]*?"total"\\s*:\\s*)${before}\\b`);
  const next = text.replace(re, `$1${diskCount}`);
  if (next === text) {
    console.error(`[reconcile] FATAL: could not locate ${blockKey}.total in ${relPath}`);
    process.exit(2);
  }
  writeFileSync(abs, next);
}

reconcile('stats.json', 'ruleCount');
reconcile('data/stats.json', 'rules');

console.log(`[reconcile] disk rule count = ${diskCount}`);
if (CHECK && drift) {
  console.error('[reconcile] FAIL: stats caches drift from disk. Fix: node scripts/reconcile-rule-count.mjs');
  process.exit(1);
}
