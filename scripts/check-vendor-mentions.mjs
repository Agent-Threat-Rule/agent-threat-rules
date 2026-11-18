#!/usr/bin/env node
// Fails when a tracked file names the maintainer's company or its products
// anywhere other than a conflict-of-interest disclosure. Product names count
// even when the company name is absent: the community reporting pipeline is
// the "ATR Community Feed", not the vendor product it used to be named after.
//
// Policy: ATR is vendor-neutral. The only place the company may be named is a
// disclosure, and a disclosure uses the exact legal name "PANGUARD AI, INC."
// with no product names, links or marketing text.
//
// This scans the whole tree on every run instead of the diff, so a change
// cannot slip past by touching a line the diff does not show.
//
// Exceptions live in .github/vendor-mentions-allowlist.json. Each entry needs a
// path, a substring of the offending line, a reason and an expiry date. An
// expired entry, or one that no longer matches any line, also fails the check,
// so the list cannot quietly go stale.
//
//   node scripts/check-vendor-mentions.mjs

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const ALLOWLIST = '.github/vendor-mentions-allowlist.json';
const DISCLOSURE = 'PANGUARD AI, INC.';
const COMPANY = /(?<![A-Za-z])panguard/i;
// Vendor product names. Matched as written, so generic prose ("a skill auditor
// reads the manifest") does not trip the check.
const PRODUCTS = [/threat\s?cloud/i, /Skill Auditor/, /GuardATREngine/];
const MAX_BYTES = 2 * 1024 * 1024;
// The checker and its fixtures have to spell the banned terms out.
const SELF = new Set([ALLOWLIST, 'scripts/check-vendor-mentions.mjs', 'tests/check-vendor-mentions.test.ts']);

function trackedFiles() {
  return execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8', maxBuffer: 1 << 28 })
    .split('\0')
    .filter(Boolean);
}

function readText(path) {
  let buf;
  try {
    buf = readFileSync(path);
  } catch {
    return null; // listed by git but absent on disk (sparse checkout, submodule)
  }
  if (buf.length > MAX_BYTES || buf.subarray(0, 8192).includes(0)) return null;
  return buf.toString('utf8');
}

export function offends(line) {
  if (COMPANY.test(line.split(DISCLOSURE).join(''))) return true;
  return PRODUCTS.some((re) => re.test(line));
}

export function loadAllowlist(text, today) {
  const doc = JSON.parse(text);
  const problems = [];
  const entries = (doc.entries || []).map((e, i) => {
    const missing = ['path', 'contains', 'reason', 'expires'].filter((k) => !e[k]);
    if (missing.length) problems.push(`${ALLOWLIST} entries[${i}] is missing ${missing.join(', ')}`);
    if (e.expires && e.expires < today) {
      problems.push(`${ALLOWLIST} entries[${i}] (${e.path}) expired on ${e.expires}: fix the line or renew with a reason`);
    }
    return { ...e, used: false };
  });
  return { entries, problems };
}

export function scan(files, read, entries) {
  const violations = [];
  for (const path of files) {
    if (SELF.has(path)) continue;
    const text = read(path);
    if (text === null) continue;
    text.split('\n').forEach((line, i) => {
      if (!offends(line)) return;
      const hit = entries.find((e) => e.path === path && line.includes(e.contains));
      if (hit) {
        hit.used = true;
        return;
      }
      violations.push(`${path}:${i + 1}: ${line.trim().slice(0, 140)}`);
    });
  }
  return violations;
}

function main() {
  const today = new Date().toISOString().slice(0, 10);
  const { entries, problems } = loadAllowlist(readFileSync(ALLOWLIST, 'utf8'), today);
  const violations = scan(trackedFiles(), readText, entries);
  const stale = entries
    .filter((e) => !e.used)
    .map((e) => `${ALLOWLIST}: entry for ${e.path} ("${e.contains}") matches nothing any more; delete it`);
  const all = [...problems, ...stale];
  if (violations.length) {
    console.error(`Vendor mentions outside a disclosure (${violations.length}):`);
    for (const v of violations) console.error(`  ${v}`);
    console.error(
      `\nFix: remove the mention, or rewrite it as a disclosure that uses only "${DISCLOSURE}".` +
        `\nIf it truly has to stay, add an entry with a reason and an expiry to ${ALLOWLIST}.`,
    );
  }
  for (const p of all) console.error(p);
  if (violations.length || all.length) process.exit(1);
  console.log(`vendor mentions: clean (${entries.length} allow-listed lines, all with reasons and expiry dates)`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
