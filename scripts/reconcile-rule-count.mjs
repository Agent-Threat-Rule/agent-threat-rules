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
 * OWNERSHIP (read this before adding a field to either cache)
 *   Everything derived from the rule tree is owned HERE: total, effective,
 *   inert, the status breakdown, and — since 2026-09-22 — `byCategory` /
 *   `categories` / `version` in data/stats.json.
 *
 *   This header used to say byCategory "remains owned by its existing
 *   generator (sync-stats.ts / sync-stats-from-measurements.ts)". Neither of
 *   those ever wrote it: sync-stats.ts reads the root stats.json and writes
 *   README/CITATION/crosswalks, and sync-stats-from-measurements.ts writes
 *   only `benchmarks` + `benchmarks_generated_at` (it says so in its own
 *   header). So byCategory had no owner at all. It was last written by hand on
 *   2026-07-02 and silently froze there: by 2026-09-22 it summed to 675 against
 *   a `total` of 825 in the same object, in the file the README calls canonical.
 *   A comment that assigns ownership to another file is not ownership — hence
 *   the invariant check at the bottom of main(), which fails the run when the
 *   breakdown stops adding up to the total.
 *
 * CATEGORY = DIRECTORY, NOT `tags.category`
 *   A rule's category is the top-level directory it lives in under rules/.
 *   That is the same source `total` is counted from, so the breakdown is
 *   guaranteed to sum to the total; deriving one from the directory and the
 *   other from the YAML field is exactly how they came apart. `tags.category`
 *   drifts on some rules — the old hand-written snapshot was built from it and
 *   reported `model-security: 0` for a directory holding real rules.
 *   website/lib/rules.ts made the same call independently and documents it at
 *   its `category:` assignment; the two must stay on the same definition.
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
/**
 * Bucket for a rule file sitting directly in rules/ rather than in a category
 * directory. No such file exists today. It gets a visible key instead of being
 * dropped so the sum keeps matching `total` and the anomaly shows up in the
 * breakdown rather than as an unexplained arithmetic failure.
 */
const UNCATEGORIZED = 'uncategorized';

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

/**
 * Walk the rule tree once and derive every number the caches restate.
 *
 * `byCategory` is keyed by the top-level directory under `dir` and is seeded
 * from the directory listing, so a category that exists but holds no rule
 * reports 0 rather than disappearing from the breakdown. Because every counted
 * file is attributed to exactly one key, `sum(byCategory) === total` holds by
 * construction — the invariant main() then re-checks on disk.
 */
export function computeCounts(dir) {
  const byStatus = { stable: 0, experimental: 0, draft: 0, deprecated: 0 };
  const lanes = { enforce: 0, alert: 0, hunt: 0 };
  const counted = new Map();
  let total = 0;
  let effective = 0;

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) counted.set(entry.name, 0);
  }

  const walk = (d, category) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, entry.name);
      if (entry.isDirectory()) {
        walk(p, category ?? entry.name);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith('.yaml')) continue;
      const meta = parseRuleMeta(readFileSync(p, 'utf8'));
      if (meta === null) continue;
      total++;
      const key = category ?? UNCATEGORIZED;
      counted.set(key, (counted.get(key) ?? 0) + 1);
      if (meta.status in byStatus) byStatus[meta.status]++;
      if (!isEffective(meta)) continue;
      effective++;
      lanes.hunt++;
      if (meta.maturity === 'stable') lanes.enforce++;
      if (meta.maturity === 'stable' || meta.maturity === 'test') lanes.alert++;
    }
  };
  walk(dir, null);

  const byCategory = Object.fromEntries([...counted.entries()].sort(([a], [b]) => a.localeCompare(b)));
  return {
    total,
    effective,
    inert: total - effective,
    byStatus,
    lanes,
    byCategory,
    categories: Object.keys(byCategory).length,
  };
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

/**
 * Replace an object-valued field inside a block (e.g. `rules.byCategory`),
 * re-rendered at the indentation of the line the field starts on so the file
 * keeps its formatting. Braces are matched rather than regex'd, so a nested
 * object inside the value is handled. Returns null when the block or the field
 * is absent — callers must treat that as fatal, never as "nothing to do".
 */
export function setBlockObject(text, blockKey, field, value) {
  const range = blockRange(text, blockKey);
  if (!range) return null;
  const body = text.slice(range.open, range.close);

  const header = new RegExp(`\\n(\\s*)"${field}"\\s*:\\s*\\{`).exec(body);
  if (!header) return null;
  const indent = header[1];
  const open = header.index + header[0].length - 1;

  let depth = 0;
  let close = -1;
  for (let i = open; i < body.length; i++) {
    if (body[i] === '{') depth++;
    else if (body[i] === '}' && --depth === 0) {
      close = i;
      break;
    }
  }
  if (close === -1) return null;

  const currentText = body.slice(open, close + 1);
  const before = JSON.parse(currentText);
  const rendered = JSON.stringify(value, null, 2).split('\n').join(`\n${indent}`);
  if (currentText === rendered) return { text, before, changed: false };

  const nextBody = body.slice(0, open) + rendered + body.slice(close + 1);
  return { text: text.slice(0, range.open) + nextBody + text.slice(range.close), before, changed: true };
}

/**
 * Set a top-level string field (e.g. the cache's `version`). Anchored to the
 * start of a line so a nested key that merely ends in the same word — this file
 * also carries `atr_version` and `source_version` — cannot be hit instead.
 * Returns null when the field is absent.
 */
export function setTopLevelString(text, field, value) {
  const re = new RegExp(`^(\\s*"${field}"\\s*:\\s*")([^"]*)(")`, 'm');
  const match = re.exec(text);
  if (!match) return null;
  if (match[2] === value) return { text, before: match[2], changed: false };
  return { text: text.replace(re, `$1${value}$3`), before: match[2], changed: true };
}

// ---------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------

const CHECK = process.argv.includes('--check');
const REPORT = process.argv.includes('--report');

/**
 * The published version of the cache is the package version — one number, one
 * place. data/stats.json used to carry a hand-copied one and was still claiming
 * 3.5.0 at package 4.1.0, six minor versions behind.
 */
function packageVersion() {
  return readRepoJson('package.json').version;
}

/** Default JSON reader for verifyWritten: a repo-relative path off REPO_ROOT. */
function readRepoJson(relPath) {
  return JSON.parse(readFileSync(join(REPO_ROOT, relPath), 'utf8'));
}

/** Fields written into each cache. stats.json also restates the status split. */
function fieldsFor(blockKey, counts) {
  const shared = { total: counts.total, effective: counts.effective, inert: counts.inert };
  return blockKey === 'ruleCount' ? { ...shared, ...counts.byStatus } : shared;
}

/**
 * Log-friendly rendering. An in-sync line only needs the shape, so a ten-key
 * breakdown prints as its key count and sum rather than as `[object Object]`
 * or as a full line of JSON.
 */
function fmt(value) {
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value);
    const sum = entries.reduce((acc, [, n]) => acc + (typeof n === 'number' ? n : 0), 0);
    return `{${entries.length} keys, sum ${sum}}`;
  }
  return String(value);
}

/** Apply one editor result, logging it and aborting on a missing target. */
function apply(state, relPath, label, value, result) {
  if (result === null) {
    console.error(`[reconcile] FATAL: could not locate ${label} in ${relPath}`);
    process.exit(2);
  }
  if (!result.changed) {
    state.log.push(`[reconcile] ${relPath}: ${label}=${fmt(value)} — in sync`);
    return;
  }
  state.drift = true;
  const from = result.before === null ? 'absent' : JSON.stringify(result.before);
  state.log.push(
    `[reconcile] ${relPath}: ${label} ${from} -> ${JSON.stringify(value)}${CHECK ? ' (drift)' : ' (fixed)'}`,
  );
  state.text = result.text;
}

/**
 * `data/stats.json` additionally carries the per-category breakdown and its own
 * copy of the version. Both are derived — never hand-edit them — so they are
 * rewritten here alongside the totals they have to agree with.
 */
function reconcileDerivedExtras(state, relPath, counts) {
  apply(state, relPath, 'rules.categories', counts.categories,
    setBlockNumber(state.text, 'rules', 'categories', counts.categories, 'inert'));
  apply(state, relPath, 'rules.byCategory', counts.byCategory,
    setBlockObject(state.text, 'rules', 'byCategory', counts.byCategory));
  const version = packageVersion();
  apply(state, relPath, 'version', version, setTopLevelString(state.text, 'version', version));
}

/**
 * @param derivedExtras true for the cache that also carries byCategory /
 *   categories / version. Passed explicitly rather than inferred from the block
 *   name so adding a third cache is a decision, not an accident.
 */
function reconcile(relPath, blockKey, counts, log, derivedExtras = false) {
  const abs = join(REPO_ROOT, relPath);
  const state = { text: readFileSync(abs, 'utf8'), drift: false, log };
  // Each newly inserted field becomes the anchor for the next, so a run of
  // inserts reads in request order (total, effective, inert) rather than
  // reversed. Fields that already exist are edited in place and leave the
  // anchor where it was.
  let anchor = 'total';

  for (const [field, value] of Object.entries(fieldsFor(blockKey, counts))) {
    apply(state, relPath, `${blockKey}.${field}`, value,
      setBlockNumber(state.text, blockKey, field, value, anchor));
    anchor = field;
  }

  if (derivedExtras) reconcileDerivedExtras(state, relPath, counts);

  // `generatedAt` describes when these numbers were derived, so it moves only
  // when one of them actually did. Stamping it on every run would produce a
  // timestamp-only commit on each rules merge and make the field read as fresh
  // while the numbers beside it had not been recomputed at all.
  if (state.drift) {
    const stamped = setTopLevelString(state.text, 'generatedAt', new Date().toISOString());
    if (stamped !== null) state.text = stamped.text;
  }

  if (state.drift && !CHECK) writeFileSync(abs, state.text);
  return state.drift;
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
  console.log(`categories (directories)  : ${counts.categories}`);
  for (const [category, n] of Object.entries(counts.byCategory)) {
    console.log(`  ${category.padEnd(24)}: ${n}`);
  }
  console.log('');
  console.log('Cite `total` for corpus size and `effective` for detection coverage.');
  console.log('They are different numbers; quoting total as coverage overstates it by `inert`.');
}

/**
 * Re-read what was just written and check the numbers agree with each other.
 *
 * This is the part that was missing. A breakdown that no longer adds up to the
 * total beside it is not a rounding error, it is a dead generator — and with
 * nothing asserting the sum, data/stats.json published `byCategory` summing to
 * 675 under `total: 825` for nearly three months without a single failing run.
 * Parsing the result also catches a surgical edit that produced invalid JSON.
 *
 * `read` is injected so the failure branches can be unit-tested against
 * fabricated caches. An invariant whose failing path is never exercised is an
 * assumption, not a check — which is how the original one came to be missing.
 */
export function verifyWritten(counts, read = readRepoJson) {
  const problems = [];

  const root = read('stats.json').ruleCount;
  if (root.total !== counts.total) problems.push(`stats.json ruleCount.total=${root.total}, disk has ${counts.total}`);

  const data = read('data/stats.json');
  const sum = Object.values(data.rules.byCategory).reduce((a, b) => a + b, 0);
  if (data.rules.total !== counts.total) {
    problems.push(`data/stats.json rules.total=${data.rules.total}, disk has ${counts.total}`);
  }
  if (sum !== data.rules.total) {
    problems.push(`data/stats.json rules.byCategory sums to ${sum} but rules.total=${data.rules.total}`);
  }
  const keys = Object.keys(data.rules.byCategory).length;
  if (data.rules.categories !== keys) {
    problems.push(`data/stats.json rules.categories=${data.rules.categories} but byCategory has ${keys} keys`);
  }
  const version = read('package.json').version;
  if (data.version !== version) {
    problems.push(`data/stats.json version=${data.version} but package.json is ${version}`);
  }
  return problems;
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
    reconcile('data/stats.json', 'rules', counts, log, true),
  ];
  console.log(log.join('\n'));
  console.log(
    `[reconcile] disk: ${counts.total} rule files, ${counts.effective} effective, ${counts.inert} inert, ` +
      `${counts.categories} categories`,
  );

  if (CHECK && drifted.some(Boolean)) {
    console.error('[reconcile] FAIL: stats caches drift from disk. Fix: node scripts/reconcile-rule-count.mjs');
    return 1;
  }

  if (!CHECK) {
    const problems = verifyWritten(counts);
    if (problems.length > 0) {
      console.error('[reconcile] FAIL: stats are internally inconsistent after writing:');
      for (const p of problems) console.error(`  - ${p}`);
      return 4;
    }
    console.log('[reconcile] OK: byCategory sums to total, categories match, version tracks package.json');
  }
  return 0;
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined && process.argv[1].endsWith('reconcile-rule-count.mjs');

if (INVOKED_DIRECTLY) process.exitCode = main();
