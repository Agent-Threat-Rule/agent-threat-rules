#!/usr/bin/env node
/**
 * verify-red-team-links.mjs — re-check every link the /red-team page offers as
 * evidence, against GitHub.
 *
 * Why: the page's list of offensive tools and corpora used to be written by
 * hand inside the page. NVIDIA/garak#1676 was withdrawn on 2026-08-04 and
 * stayed listed as under review for ten weeks; nothing noticed until a person
 * read every link (#688). The list now lives in
 * website/data/red-team-tools.json, and this script holds each status label to
 * what GitHub says, the way scripts/verify-adopters.mjs does for ADOPTERS.md:
 *   - in-review     -> the linked PR or issue must be OPEN
 *   - in-production -> the linked PR must be MERGED, and the file named in
 *                      `stillPresent` must still mention ATR upstream (a merged
 *                      PR can be reverted the next day)
 *   - corpus        -> the linked PR must be MERGED
 * A merged PR still filed under in-review is drift too: it belongs under
 * in-production.
 *
 * It cannot tell an open proposal nobody answers from one under active review:
 * six of the seven proposals #688 removed were open and unanswered until their
 * author withdrew them. The page calls the group "Open proposals" for that
 * reason.
 *
 * Every failure is one of three kinds, reported separately:
 *   - drift      GitHub disagrees with the declared status: fix the list
 *   - gone       the PR, issue, repository or file no longer exists (404/410)
 *   - unverified GitHub could not be asked (rate limit, 5xx, network, bad body).
 *                Not a pass: re-run with GITHUB_TOKEN set before editing.
 *
 * Exit 0 when every entry checks out, 1 otherwise (including a malformed or
 * empty list). Auth: set GITHUB_TOKEN to avoid the 60 req/h unauthenticated
 * limit. Run: node scripts/verify-red-team-links.mjs
 */

import { readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const DATA_PATH = join(REPO_ROOT, 'website', 'data', 'red-team-tools.json');

export const STATUSES = ['in-production', 'in-review', 'corpus'];
const REQUIRED_FIELDS = ['name', 'org', 'status', 'homepage', 'hook', 'what_atr_did'];
const ALLOWED_FIELDS = new Set([...REQUIRED_FIELDS, 'prUrl', 'figures', 'stillPresent']);
const NAME = /^[A-Za-z0-9_.-]+$/;
const TIMEOUT_MS = 20_000;
const RETRIES = 2;

/** The state each status needs its link in, by link kind. A missing kind never passes. */
const EXPECTED = {
  'in-review': { pr: 'open', issue: 'open' },
  'in-production': { pr: 'merged' },
  corpus: { pr: 'merged' },
};

/**
 * { kind: 'pr' | 'issue', owner, repo, number } for a GitHub PR or issue URL,
 * else { kind: 'other' }. Accepts what people paste: a query, a fragment, a
 * trailing /files, www. or an upper-case host.
 */
export function classifyLink(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { kind: 'other' };
  }
  const host = parsed.hostname.toLowerCase().replace(/^www\./, '');
  if (parsed.protocol !== 'https:' || host !== 'github.com') return { kind: 'other' };
  const [owner, repo, type, num] = parsed.pathname.split('/').filter(Boolean);
  const named = (s) => typeof s === 'string' && NAME.test(s) && s !== '.' && s !== '..';
  if (!named(owner) || !named(repo) || !/^\d+$/.test(num ?? '')) return { kind: 'other' };
  if (type !== 'pull' && type !== 'issues') return { kind: 'other' };
  return { kind: type === 'pull' ? 'pr' : 'issue', owner, repo, number: Number(num) };
}

/** Whether a link of `kind`, observed in state `observed`, supports the declared status. */
export function verdict(status, kind, observed) {
  const expected = EXPECTED[status]?.[kind];
  return expected !== undefined && observed === expected;
}

/** `<path> contains "<needle>"` -> { path, needle }, else null. */
export function parseStillPresent(spec) {
  const m = /^(\S+)\s+contains\s+"(.+)"\s*$/.exec(typeof spec === 'string' ? spec.trim() : '');
  return m ? { path: m[1], needle: m[2] } : null;
}

function linkProblems(tool, label) {
  if (typeof tool.prUrl !== 'string') return [`${label}: needs a prUrl that CI can check`];
  const { kind } = classifyLink(tool.prUrl);
  if (tool.status === 'in-review' && kind === 'other') {
    return [`${label}: in-review needs a prUrl that is a GitHub pull request or issue`];
  }
  if ((tool.status === 'in-production' || tool.status === 'corpus') && kind !== 'pr') {
    return [`${label}: ${tool.status} needs a prUrl that is the merged pull request`];
  }
  return [];
}

function stillPresentProblems(tool, label) {
  if (tool.status === 'in-production' && tool.stillPresent === undefined) {
    return [`${label}: in-production needs stillPresent ('<path> contains "<text>"'): a merged PR can be reverted`];
  }
  if (tool.stillPresent !== undefined && parseStillPresent(tool.stillPresent) === null) {
    return [`${label}: stillPresent must read '<path> contains "<text>"'`];
  }
  return [];
}

function entryProblems(tool, index) {
  if (tool === null || typeof tool !== 'object' || Array.isArray(tool)) return [`entry ${index}: not an object`];
  const label = typeof tool.name === 'string' ? `"${tool.name}"` : `entry ${index}`;
  const missing = REQUIRED_FIELDS.filter((f) => typeof tool[f] !== 'string' || tool[f].trim() === '')
    .map((f) => `${label}: missing ${f}`);
  const unknown = Object.keys(tool).filter((k) => !ALLOWED_FIELDS.has(k))
    .map((k) => `${label}: unknown field "${k}"`);
  const status = typeof tool.status === 'string' && !STATUSES.includes(tool.status)
    ? [`${label}: unknown status "${tool.status}" (expected ${STATUSES.join(', ')})`]
    : [];
  const figures = tool.figures !== undefined
    && !(Array.isArray(tool.figures) && tool.figures.every((f) => typeof f?.source === 'string' && typeof f?.label === 'string'))
    ? [`${label}: figures must be a list of { source, label }`]
    : [];
  return [...missing, ...unknown, ...status, ...linkProblems(tool, label), ...stillPresentProblems(tool, label), ...figures];
}

/** Every structural problem with the list, as readable lines. Empty when the list is valid. */
export function validateTools(tools) {
  if (!Array.isArray(tools)) return ['the list must be a JSON array'];
  if (tools.length === 0) return ['the list is empty: there is nothing to check, and the page would show no tools'];
  const names = tools.map((t) => t?.name).filter((n) => typeof n === 'string');
  const duplicates = [...new Set(names.filter((n, i) => names.indexOf(n) !== i))]
    .map((n) => `"${n}": duplicate name`);
  return [...tools.flatMap((tool, i) => entryProblems(tool, i)), ...duplicates];
}

function apiHeaders() {
  return {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'atr-red-team-verify',
    ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
  };
}

const realSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const transient = (status) => status === 429 || status >= 500;

/**
 * GET a GitHub API path. Resolves { body } on success, { error } otherwise:
 * 'api-<status>', 'network-error' or 'bad-response'. Retries 429, 5xx and
 * network errors; never retries a 404.
 */
async function getJson(path, { fetchImpl, sleep, retries }) {
  let error = 'network-error';
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await sleep(1000 * 2 ** (attempt - 1));
    let res;
    try {
      res = await fetchImpl(`https://api.github.com${path}`, { headers: apiHeaders(), signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch {
      error = 'network-error';
      continue;
    }
    if (!res.ok) {
      error = `api-${res.status}`;
      if (transient(res.status)) continue;
      return { error };
    }
    try {
      const body = await res.json();
      return body !== null && typeof body === 'object' ? { body } : { error: 'bad-response' };
    } catch {
      error = 'bad-response';
    }
  }
  return { error };
}

/** 'open' | 'closed' | 'merged', or an error string from getJson. */
async function fetchState(link, opts) {
  const endpoint = link.kind === 'pr' ? 'pulls' : 'issues';
  const { body, error } = await getJson(`/repos/${link.owner}/${link.repo}/${endpoint}/${link.number}`, opts);
  if (error) return error;
  if (typeof body.state !== 'string') return 'bad-response';
  if (link.kind === 'pr' && body.merged_at) return 'merged';
  return body.state === 'open' ? 'open' : 'closed';
}

/** 'present' | 'absent' | 'gone' (no such path) | an error string from getJson. */
async function fetchStillPresent(link, spec, opts) {
  const encodedPath = spec.path.split('/').map(encodeURIComponent).join('/');
  const { body, error } = await getJson(`/repos/${link.owner}/${link.repo}/contents/${encodedPath}`, opts);
  if (error === 'api-404') return 'gone';
  if (error) return error;
  if (typeof body.content !== 'string') return 'gone';
  return Buffer.from(body.content, 'base64').toString('utf8').includes(spec.needle) ? 'present' : 'absent';
}

async function verifyOne(tool, opts) {
  const base = { name: tool.name, declared: tool.status, link: tool.prUrl ?? null, content: null };
  if (typeof tool.prUrl !== 'string') return { ...base, kind: 'none', observed: 'no-link', ok: false };
  const link = classifyLink(tool.prUrl);
  if (link.kind === 'other') return { ...base, kind: 'other', observed: 'unverifiable', ok: false };
  const observed = await fetchState(link, opts);
  const stateOk = verdict(tool.status, link.kind, observed);
  const spec = parseStillPresent(tool.stillPresent);
  if (!stateOk || spec === null) return { ...base, kind: link.kind, observed, ok: stateOk };
  const content = await fetchStillPresent(link, spec, opts);
  return { ...base, kind: link.kind, observed, content, ok: content === 'present' };
}

/**
 * One result per entry, checked one at a time (a handful of API calls; no need
 * to fan out). `options` lets tests replace the delay between retries.
 */
export async function verifyTools(tools, fetchImpl = globalThis.fetch, options = {}) {
  const opts = { fetchImpl, sleep: options.sleep ?? realSleep, retries: options.retries ?? RETRIES };
  let results = [];
  for (const tool of tools) results = [...results, await verifyOne(tool, opts)];
  return results;
}

const isUnverified = (s) => typeof s === 'string' && (s === 'network-error' || s === 'bad-response' || (s.startsWith('api-') && s !== 'api-404' && s !== 'api-410'));

/** 'drift' | 'gone' | 'unverified' for a failed result. */
export function failureKind(result) {
  if (isUnverified(result.observed) || isUnverified(result.content)) return 'unverified';
  if (['api-404', 'api-410'].includes(result.observed) || result.content === 'gone') return 'gone';
  return 'drift';
}

const ADVICE = {
  drift: 'GitHub disagrees with the declared status. Fix website/data/red-team-tools.json: move a merged proposal to in-production, remove a closed one, and remove an in-production entry whose upstream file no longer mentions ATR.',
  gone: 'The linked PR, issue, repository or stillPresent file no longer exists (a PR link to an issue also 404s). Remove the entry or point it at the right URL.',
  unverified: 'GitHub could not be asked (rate limit, server error, network or an unreadable response). This is not a pass: re-run with GITHUB_TOKEN set before editing the list.',
};

function report(results) {
  for (const r of results) {
    const content = r.content === null ? '' : `, upstream file ${r.content}`;
    const where = r.link ? ` ${r.link}` : '';
    console.log(`${r.ok ? '[ok]   ' : '[FAIL] '} ${r.name} — declared ${r.declared}, observed ${r.observed} (${r.kind})${content}${where}`);
  }
  const failed = results.filter((r) => !r.ok);
  if (failed.length === 0) {
    console.log(`\n${results.length}/${results.length} red-team entries match GitHub.`);
    return 0;
  }
  console.error(`\n${failed.length} of ${results.length} red-team entries failed:`);
  for (const kind of ['drift', 'gone', 'unverified']) {
    const names = failed.filter((r) => failureKind(r) === kind).map((r) => r.name);
    if (names.length > 0) console.error(`  ${kind}: ${names.join(', ')}\n    ${ADVICE[kind]}`);
  }
  return 1;
}

export async function main(options = {}) {
  const dataPath = options.dataPath ?? DATA_PATH;
  let tools;
  try {
    tools = JSON.parse(readFileSync(dataPath, 'utf8'));
  } catch (err) {
    console.error(`[red-team] cannot read ${dataPath}: ${err instanceof Error ? err.message : err}`);
    return 1;
  }
  const problems = validateTools(tools);
  if (problems.length > 0) {
    console.error('[red-team] website/data/red-team-tools.json is malformed:');
    for (const p of problems) console.error(`  - ${p}`);
    return 1;
  }
  return report(await verifyTools(tools, options.fetchImpl ?? globalThis.fetch, options));
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
