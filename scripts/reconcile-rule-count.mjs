#!/usr/bin/env node
/**
 * reconcile-rule-count.mjs — keep the ATR rule numbers consistent across the repo.
 *
 * Ground truth is the set of `rules/**\/*.yaml` files in git (every rule file
 * carries a top-level `id: ATR-...`). Two derived caches restate those numbers:
 *   - stats.json           -> ruleCount.*   (propagated to README / docs / MCP)
 *   - data/stats.json      -> rules.*       (used by the website + tooling)
 *
 * These caches drift whenever rules are added/removed without regenerating them,
 * and were historically fixed by hand with `chore(stats): reconcile ...` commits.
 * This script recomputes from disk and writes back, so they cannot diverge. Run it
 * in CI on every push to main (.github/workflows/reconcile-stats.yml).
 *
 * TWO DIFFERENT NUMBERS, BOTH TRUE, AND THE DIFFERENCE MATTERS
 *   total     — rule FILES on disk. What `find rules -name '*.yaml' | wc -l` says.
 *   effective — rules the engine will load AND that can fire. A rule with
 *               `status: draft` or `status: deprecated` is skipped by
 *               src/engine.ts before the lane gate and before any pattern is
 *               compiled, so it fires in NO lane, ever. Same for
 *               `maturity: deprecated` (see src/quality/rule-contract.ts).
 *
 *   Quoting `total` as detection coverage overstates it by exactly `inert`. The
 *   gap was 96 rules when this was added, and no published surface distinguished
 *   the two. Both are computed here so a citation can be honest without anyone
 *   re-deriving it by hand:
 *
 *     node scripts/reconcile-rule-count.mjs --report
 *
 * Scope: the numeric fields only (total, effective, inert, and the status
 * breakdown). byCategory and the benchmark blocks remain owned by their existing
 * generators (sync-stats.ts / sync-stats-from-measurements.ts). The status
 * breakdown is now included because it sits directly beside `effective` —
 * publishing a fresh `effective` next to a stale `draft` would read as an
 * arithmetic error, and that breakdown had in fact gone stale (draft: 37 on
 * record against 96 on disk).
 *
 * Stdlib only, no dependencies: reconcile-stats.yml runs it without npm install.
 *
 * Usage:
 *   node scripts/reconcile-rule-count.mjs           # reconcile in place (write)
 *   node scripts/reconcile-rule-count.mjs --check   # report drift, exit 1, write nothing
 *   node scripts/reconcile-rule-count.mjs --report  # print the numbers, write nothing
 */
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const RULES_DIR = join(REPO_ROOT, 'rules');
const ID_RE = /^id:\s*ATR-/m;

/** Statuses src/engine.ts refuses to evaluate, in either evaluation path. */
export const INERT_STATUSES = new Set(['draft', 'deprecated']);
/** A deprecated maturity never fires in any lane (src/quality/rule-contract.ts). */
export const INERT_MATURITY = 'deprecated';
/** Canonical maturity ladder; anything else normalizes to 'experimental'. */
const MATURITIES = new Set(['draft', 'experimental', 'test', 'stable', 'deprecated']);

// ---------------------------------------------------------------------------
// Counting (pure)
// ---------------------------------------------------------------------------

/** Read the fields that decide whether a rule can ever fire. Null = not a rule. */
export function parseRuleMeta(text) {
  if (!ID_RE.test(text)) return null;
  const status = /^status:\s*["']?([A-Za-z-]+)/m.exec(text)?.[1] ?? '';
  const maturity = /^maturity:\s*["']?([A-Za-z-]+)/m.exec(text)?.[1] ?? '';
  return { status, maturity: MATURITIES.has(maturity) ? maturity : 'experimental' };
}

/** Can the engine load this rule AND let it fire in at least one lane? */
export function isEffective(meta) {
  return !INERT_STATUSES.has(meta.status) && meta.maturity !== INERT_MATURITY;
}

/** Walk the rule tree once and derive every number the caches restate. */
export function computeCounts(dir) {
  const byStatus = { stable: 0, experimental: 0, draft: 0, deprecated: 0 };
  const lanes = { enforce: 0, alert: 0, hunt: 0 };
  let total = 0;
  let effective = 0;

  const walk = (d) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, entry.name);
      if (entry.isDirectory()) {
        walk(p);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith('.yaml')) continue;
      const meta = parseRuleMeta(readFileSync(p, 'utf8'));
      if (meta === null) continue;
      total++;
      if (meta.status in byStatus) byStatus[meta.status]++;
      if (!isEffective(meta)) continue;
      effective++;
      lanes.hunt++;
      if (meta.maturity === 'stable') lanes.enforce++;
      if (meta.maturity === 'stable' || meta.maturity === 'test') lanes.alert++;
    }
  };
  walk(dir);
  return { total, effective, inert: total - effective, byStatus, lanes };
}

// ---------------------------------------------------------------------------
// Surgical JSON editing
// ---------------------------------------------------------------------------

/**
 * Character range of a named block's braces. Edits stay inside it so a field
 * name that also appears elsewhere in the file cannot be hit by accident.
 */
function blockRange(text, blockKey) {
  const header = new RegExp(`"${blockKey}"\\s*:\\s*\\{`).exec(text);
  if (!header) return null;
  const open = header.index + header[0].length - 1;
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}' && --depth === 0) return { open, close: i };
  }
  return null;
}

/**
 * Set one numeric field inside a block, preserving the file's formatting so the
 * diff stays a single line. The field is replaced when present, and inserted
 * directly after `anchorField` when absent — callers chain the anchor so a run
 * of inserts lands in the order they were requested rather than reversed.
 * Returns null when the block or the anchor is missing; callers must treat that
 * as fatal, never as "nothing to do".
 */
export function setBlockNumber(text, blockKey, field, value, anchorField = 'total') {
  const range = blockRange(text, blockKey);
  if (!range) return null;
  const body = text.slice(range.open, range.close);
  const splice = (nextBody) => text.slice(0, range.open) + nextBody + text.slice(range.close);

  const existing = new RegExp(`("${field}"\\s*:\\s*)(-?\\d+)`).exec(body);
  if (existing) {
    const before = Number(existing[2]);
    if (before === value) return { text, before, changed: false };
    const head = body.slice(0, existing.index) + existing[1] + value;
    return { text: splice(head + body.slice(existing.index + existing[0].length)), before, changed: true };
  }

  // Insert immediately after the anchor's digits and BEFORE whatever follows —
  // that way the separator already in the file (a comma, or the newline before
  // the closing brace) still terminates the new field correctly.
  const anchor = new RegExp(`\\n(\\s*)"${anchorField}"\\s*:\\s*-?\\d+`).exec(body);
  if (!anchor) return null;
  const at = anchor.index + anchor[0].length;
  const inserted = `${body.slice(0, at)},\n${anchor[1]}"${field}": ${value}${body.slice(at)}`;
  return { text: splice(inserted), before: null, changed: true };
}

// ---------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------

const CHECK = process.argv.includes('--check');
const REPORT = process.argv.includes('--report');

/** Fields written into each cache. stats.json also restates the status split. */
function fieldsFor(blockKey, counts) {
  const shared = { total: counts.total, effective: counts.effective, inert: counts.inert };
  return blockKey === 'ruleCount' ? { ...shared, ...counts.byStatus } : shared;
}

function reconcile(relPath, blockKey, counts, log) {
  const abs = join(REPO_ROOT, relPath);
  let text = readFileSync(abs, 'utf8');
  let drift = false;
  // Each newly inserted field becomes the anchor for the next, so a run of
  // inserts reads in request order (total, effective, inert) rather than
  // reversed. Fields that already exist are edited in place and leave the
  // anchor where it was.
  let anchor = 'total';

  for (const [field, value] of Object.entries(fieldsFor(blockKey, counts))) {
    const result = setBlockNumber(text, blockKey, field, value, anchor);
    anchor = field;
    if (result === null) {
      console.error(
        `[reconcile] FATAL: could not locate ${blockKey}.${field} (or the "total" anchor) in ${relPath}`,
      );
      process.exit(2);
    }
    if (!result.changed) {
      log.push(`[reconcile] ${relPath}: ${blockKey}.${field}=${value} — in sync`);
      continue;
    }
    drift = true;
    const from = result.before === null ? 'absent' : result.before;
    log.push(
      `[reconcile] ${relPath}: ${blockKey}.${field} ${from} -> ${value}${CHECK ? ' (drift)' : ' (fixed)'}`,
    );
    text = result.text;
  }

  if (drift && !CHECK) writeFileSync(abs, text);
  return drift;
}

function printReport(counts) {
  const byStatus = Object.entries(counts.byStatus)
    .map(([k, v]) => `${k}=${v}`)
    .join(' ');
  console.log(`rule files on disk        : ${counts.total}`);
  console.log(`effective (can ever fire) : ${counts.effective}`);
  console.log(`inert (never fires)       : ${counts.inert}   [status draft/deprecated, or maturity deprecated]`);
  console.log(`  by status               : ${byStatus}`);
  console.log(`lane ceilings (effective) : enforce=${counts.lanes.enforce} alert=${counts.lanes.alert} hunt=${counts.lanes.hunt}`);
  console.log('');
  console.log('Cite `total` for corpus size and `effective` for detection coverage.');
  console.log('They are different numbers; quoting total as coverage overstates it by `inert`.');
}

export function main() {
  const counts = computeCounts(RULES_DIR);
  if (REPORT) {
    printReport(counts);
    return 0;
  }

  const log = [];
  const drifted = [
    reconcile('stats.json', 'ruleCount', counts, log),
    reconcile('data/stats.json', 'rules', counts, log),
  ];
  console.log(log.join('\n'));
  console.log(
    `[reconcile] disk: ${counts.total} rule files, ${counts.effective} effective, ${counts.inert} inert`,
  );

  if (CHECK && drifted.some(Boolean)) {
    console.error('[reconcile] FAIL: stats caches drift from disk. Fix: node scripts/reconcile-rule-count.mjs');
    return 1;
  }
  return 0;
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined && process.argv[1].endsWith('reconcile-rule-count.mjs');

if (INVOKED_DIRECTLY) process.exitCode = main();
