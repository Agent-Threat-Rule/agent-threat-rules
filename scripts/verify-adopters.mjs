#!/usr/bin/env node
/**
 * verify-adopters.mjs — re-verify every ADOPTERS.md evidence link against
 * GitHub and record the result in data/adopters-verification.json.
 *
 * Why: ADOPTERS.md is the single source of truth for the website's adopter
 * wall. Its Status fields (shipped / in-review) are claims about external
 * repositories, and those repositories move — PRs merge, close, or get
 * superseded. This script turns "we claim" into "we checked, on this date".
 * Every evidence link of an entry is checked (an entry may give several):
 *   - shipped   + evidence PR    -> PR must be MERGED
 *   - in-review + evidence PR    -> PR must be OPEN
 *   - any       + evidence issue -> issue must be OPEN (conversation alive)
 *   - any       + plain link     -> URL must resolve (HTTP < 400)
 * and a Still-present assertion ('<path> contains "<text>"') must hold on the
 * default branch of the repository the first PR or issue link names.
 *
 * GitHub is asked through scripts/lib/github-link-state.mjs: a rate limit, a
 * 5xx or a network error is retried, and every request times out. A failed
 * entry is one of three kinds:
 *   - drift      GitHub disagrees with the declared status, or the asserted
 *                file no longer holds the text
 *   - gone       the PR, issue, repository or page no longer exists (404/410)
 *   - unverified GitHub or the page could not be asked (rate limit, 5xx,
 *                network, an answer that cannot be read)
 *
 * Output: data/adopters-verification.json, read by the website's /ecosystem
 * page (verification date and per-entry result) and by CI. Drift and gone are
 * data, not errors: the file is written and the script exits 0, so the honest
 * state is committed and published, and the workflow gates on the drift count
 * separately. An unverified entry is no result at all: the script then writes
 * nothing and exits 1, so an API problem never changes what the site says.
 *
 * Auth: set GITHUB_TOKEN to avoid the 60 req/h unauthenticated API limit.
 * Run: node scripts/verify-adopters.mjs
 */

import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evidenceUrls, firstUrl } from './lib/adopters-evidence.mjs';
import { RETRIES, TIMEOUT_MS, classifyLink, failureKind, fetchFileText, fetchState } from './lib/github-link-state.mjs';

export { evidenceUrls };

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const ADOPTERS_PATH = join(REPO_ROOT, 'ADOPTERS.md');
export const OUT_PATH = join(REPO_ROOT, 'data', 'adopters-verification.json');

const TIER_HEADINGS = [
  { heading: 'Tier S', tier: 'S' },
  { heading: 'Tier 1', tier: '1' },
  { heading: 'Tier 2', tier: '2' },
  { heading: 'Tier 3', tier: '3' },
  { heading: 'Tier 4', tier: '4' },
];

function extractField(block, fieldName) {
  const re = new RegExp(`\\*\\*${fieldName}\\*\\*\\s*:\\s*([^\\n]+)`, 'i');
  const m = block.match(re);
  return m ? m[1].trim() : undefined;
}

export function parseAdopters(raw) {
  const entries = [];
  let currentTier = null;
  let block = [];
  let name = null;

  const flush = () => {
    if (!name || !currentTier) return;
    const body = block.join('\n');
    const evidence = extractField(body, 'Evidence');
    const status = (extractField(body, 'Status') || 'shipped').toLowerCase();
    if (!evidence) return;
    entries.push({
      name,
      tier: currentTier,
      evidence: firstUrl(evidence),
      evidenceUrls: evidenceUrls(evidence),
      status,
      stillPresent: extractField(body, 'Still-present'),
    });
  };

  for (const line of raw.split('\n')) {
    const top = /^## (.+)$/.exec(line);
    if (top) {
      flush();
      name = null;
      block = [];
      const match = TIER_HEADINGS.find((t) => top[1].startsWith(t.heading));
      currentTier = match ? match.tier : null;
      continue;
    }
    const h3 = /^###\s+(.+?)\s*$/.exec(line);
    if (h3) {
      flush();
      name = h3[1];
      block = [];
      continue;
    }
    if (name) block.push(line);
  }
  flush();
  return entries;
}

const realSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** 'reachable', 'http-<status>' or 'network-error'; a 429, a 5xx or a network error is retried. */
async function checkReachable(url, { fetchImpl, sleep, retries }) {
  let observed = 'network-error';
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await sleep(1000 * 2 ** (attempt - 1));
    try {
      const res = await fetchImpl(url, {
        method: 'GET',
        headers: { 'User-Agent': 'atr-adopters-verify' },
        redirect: 'follow',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (res.status < 400) return 'reachable';
      observed = `http-${res.status}`;
      if (res.status !== 429 && res.status < 500) return observed;
    } catch {
      observed = 'network-error';
    }
  }
  return observed;
}

/** The state a link must be in for the declared status, or null when none can hold. */
function expectedState(kind, declared) {
  if (kind === 'pr') return { shipped: 'merged', 'in-review': 'open' }[declared] ?? null;
  return kind === 'issue' ? 'open' : 'reachable';
}

async function checkUrl(url, declared, opts) {
  const link = classifyLink(url);
  const kind = link.kind === 'pr' || link.kind === 'issue' ? link.kind : 'link';
  const observed = kind === 'link' ? await checkReachable(url, opts) : await fetchState(link, opts);
  return { url, kind, observed, expected: expectedState(kind, declared) };
}

/** null when the check holds, else 'drift' | 'gone' | 'unverified'. */
function checkFailure(check) {
  if (check.expected !== null && check.observed === check.expected) return null;
  if (check.kind === 'link') {
    // A page that answers with any other error says nothing about the claim.
    return check.observed === 'http-404' || check.observed === 'http-410' ? 'gone' : 'unverified';
  }
  return check.expected === null ? 'drift' : failureKind(check.observed);
}

/** 'present' | 'absent' | 'path-missing' | 'unparsable', or an error string when GitHub could not be asked. */
async function checkStillPresent(link, spec, opts) {
  const m = /^(\S+)\s+contains\s+"(.+)"\s*$/.exec(spec.trim());
  if (!m) return 'unparsable';
  const { text, error } = await fetchFileText(link.owner, link.repo, m[1], opts);
  if (error === 'api-404' || error === 'api-410' || error === 'not-a-file') return 'path-missing';
  if (error) return error;
  return text.includes(m[2]) ? 'present' : 'absent';
}

function contentFailure(content) {
  if (content === null || content === 'present') return null;
  return ['absent', 'path-missing', 'unparsable'].includes(content) ? 'drift' : 'unverified';
}

async function verifyEntry(entry, opts) {
  let checks = [];
  for (const url of entry.evidenceUrls) checks = [...checks, await checkUrl(url, entry.status, opts)];
  const repoLink = entry.evidenceUrls.map(classifyLink).find((l) => l.kind === 'pr' || l.kind === 'issue');
  const content = entry.stillPresent && repoLink ? await checkStillPresent(repoLink, entry.stillPresent, opts) : null;
  const failures = [...checks.map(checkFailure), contentFailure(content)];
  // A definite finding (drift, then gone) outranks a question GitHub did not answer.
  const found = ['drift', 'gone', 'unverified'].find((kind) => failures.includes(kind)) ?? null;
  const failure = checks.length === 0 ? 'drift' : found;
  const shown = checks.find((c) => checkFailure(c) !== null) ?? checks[0];
  return {
    name: entry.name,
    tier: entry.tier,
    evidence: entry.evidence,
    declared: entry.status,
    kind: shown?.kind ?? 'none',
    observed: shown?.observed ?? 'missing',
    checks,
    content,
    ok: failure === null,
    failure,
  };
}

/**
 * One result per entry, checked one at a time (a few dozen requests).
 * options: fetchImpl, sleep, retries, token (as for fetchState).
 */
export async function verifyAdopters(entries, options = {}) {
  const opts = {
    ...options,
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
    sleep: options.sleep ?? realSleep,
    retries: options.retries ?? RETRIES,
  };
  let results = [];
  for (const entry of entries) results = [...results, await verifyEntry(entry, opts)];
  return results;
}

/** The data file's content: the fields the website reads, the failures, and every result. */
export function summarize(results, today) {
  const failed = results.filter((r) => !r.ok);
  return {
    $comment: 'AUTO by scripts/verify-adopters.mjs — every ADOPTERS.md evidence link re-checked against GitHub. Do not edit by hand.',
    verified_at: today,
    total: results.length,
    ok: results.length - failed.length,
    drift: failed.map((r) => ({
      name: r.name,
      declared: r.declared,
      observed: r.observed,
      content: r.content,
      evidence: (r.checks.find((c) => checkFailure(c) !== null) ?? r.checks[0])?.url ?? r.evidence,
      failure: r.failure,
    })),
    results,
  };
}

function reportLine(r) {
  const tag = { drift: '[DRIFT]', gone: '[GONE]', unverified: '[UNVERIFIED]' }[r.failure] ?? '[ok]';
  const content = r.content === null ? ' [no content assertion]' : ` [content ${r.content}]`;
  return `${tag.padEnd(12)} ${r.name} — declared ${r.declared}, observed ${r.observed} (${r.kind})${content}`;
}

/** options: adoptersPath, outPath, today (YYYY-MM-DD), and verifyAdopters' options. */
export async function main(options = {}) {
  const adoptersPath = options.adoptersPath ?? ADOPTERS_PATH;
  const outPath = options.outPath ?? OUT_PATH;
  let raw;
  try {
    raw = readFileSync(adoptersPath, 'utf8');
  } catch (err) {
    console.error(`[adopters] cannot read ${adoptersPath}: ${err instanceof Error ? err.message : err}`);
    return 1;
  }
  const results = await verifyAdopters(parseAdopters(raw), options);
  for (const r of results) console.log(reportLine(r));
  const unverified = results.filter((r) => r.failure === 'unverified').map((r) => r.name);
  if (unverified.length > 0) {
    console.error(
      `\n${unverified.length} entries could not be verified (GitHub or the page did not answer): ${unverified.join(', ')}.` +
        ` Nothing was written. Re-run with a valid GITHUB_TOKEN; api-401 means the token itself was rejected.`,
    );
    return 1;
  }
  const out = summarize(results, options.today ?? new Date().toISOString().slice(0, 10));
  writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);
  console.log(`\nwrote ${outPath} — ${out.ok}/${out.total} verified, ${out.drift.length} drift`);
  const unasserted = results.filter((r) => r.content === null).length;
  if (unasserted > 0) {
    console.log(`${unasserted} entries have no Still-present assertion — a merged PR is all that backs them.`);
  }
  return 0;
}

/** True when node was asked to run this file, through any symlink to it. */
function invokedDirectly() {
  if (process.argv[1] === undefined) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) process.exitCode = await main();
