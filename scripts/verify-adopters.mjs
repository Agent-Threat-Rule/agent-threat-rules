#!/usr/bin/env node
/**
 * verify-adopters.mjs — re-verify every ADOPTERS.md evidence link against
 * GitHub and record the result in data/adopters-verification.json.
 *
 * Why: ADOPTERS.md is the single source of truth for the website's adopter
 * wall. Its Status fields (shipped / in-review) are claims about external
 * repositories, and those repositories move — PRs merge, close, or get
 * superseded. This script turns "we claim" into "we checked, on this date":
 *   - shipped   + evidence PR   -> PR must be MERGED
 *   - in-review + evidence PR   -> PR must be OPEN
 *   - any       + evidence issue-> issue must be OPEN (conversation alive)
 *   - any       + plain link    -> URL must resolve (HTTP < 400)
 *
 * Output: data/adopters-verification.json (consumed by the website's
 * /ecosystem page to print the verification date, and by CI to alert on
 * drift). The script always exits 0 and always writes the file — drift is
 * data, not an error here. The workflow gates on the drift count separately
 * so the honest state still gets committed and published.
 *
 * Auth: set GITHUB_TOKEN to avoid the 60 req/h unauthenticated API limit.
 * Run: node scripts/verify-adopters.mjs
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ADOPTERS_PATH = join(REPO_ROOT, 'ADOPTERS.md');
const OUT_PATH = join(REPO_ROOT, 'data', 'adopters-verification.json');

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

/** First canonical URL out of an Evidence value (mirrors website/lib/adopters.ts). */
function firstUrl(evidence) {
  const angle = evidence.match(/<(https?:\/\/[^>\s]+)>/);
  if (angle) return angle[1];
  const link = evidence.match(/^\[.*?\]\((.+?)\)/);
  if (link) return link[1];
  const bare = evidence.match(/https?:\/\/[^\s>)]+/);
  return bare ? bare[0] : undefined;
}

function parseAdopters(raw) {
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

const API_HEADERS = {
  Accept: 'application/vnd.github+json',
  'User-Agent': 'atr-adopters-verify',
  ...(process.env.GITHUB_TOKEN
    ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
    : {}),
};

async function checkPr(owner, repo, num) {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/pulls/${num}`,
    { headers: API_HEADERS },
  );
  if (!res.ok) return { observed: `api-${res.status}` };
  const pr = await res.json();
  if (pr.merged_at) return { observed: 'merged' };
  return { observed: pr.state === 'open' ? 'open' : 'closed' };
}

async function checkIssue(owner, repo, num) {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/issues/${num}`,
    { headers: API_HEADERS },
  );
  if (!res.ok) return { observed: `api-${res.status}` };
  const issue = await res.json();
  return { observed: issue.state === 'open' ? 'open' : 'closed' };
}

async function checkLink(url) {
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'atr-adopters-verify' },
      redirect: 'follow',
    });
    return { observed: res.status < 400 ? 'reachable' : `http-${res.status}` };
  } catch {
    return { observed: 'unreachable' };
  }
}

/**
 * Assert that a path on the adopter's default branch still contains a string.
 *
 * Spec format, in the Still-present field:
 *   README.md contains "Agent-Threat-Rule"
 *
 * Returns 'present' | 'absent' | 'path-missing' | 'unparsable' | 'api-NNN'.
 */
async function checkStillPresent(owner, repo, spec) {
  const m = /^(\S+)\s+contains\s+"(.+)"\s*$/.exec(spec.trim());
  if (!m) return 'unparsable';
  const [, path, needle] = m;
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
    { headers: API_HEADERS },
  );
  if (res.status === 404) return 'path-missing';
  if (!res.ok) return `api-${res.status}`;
  const body = await res.json();
  if (!body.content) return 'path-missing';
  const text = Buffer.from(body.content, 'base64').toString('utf8');
  return text.includes(needle) ? 'present' : 'absent';
}

function isOk(kind, declared, observed) {
  if (kind === 'pr') {
    if (declared === 'shipped') return observed === 'merged';
    if (declared === 'in-review') return observed === 'open';
    return false;
  }
  if (kind === 'issue') return observed === 'open';
  if (kind === 'link') return observed === 'reachable';
  return false;
}

async function main() {
  const raw = readFileSync(ADOPTERS_PATH, 'utf8');
  const entries = parseAdopters(raw);
  const results = [];

  for (const entry of entries) {
    if (!entry.evidence) {
      results.push({ ...entry, kind: 'none', observed: 'missing', ok: false });
      continue;
    }
    const prMatch = entry.evidence.match(
      /github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/,
    );
    const issueMatch = entry.evidence.match(
      /github\.com\/([^/]+)\/([^/]+)\/issues\/(\d+)/,
    );
    let kind;
    let observed;
    if (prMatch) {
      kind = 'pr';
      ({ observed } = await checkPr(prMatch[1], prMatch[2], prMatch[3]));
    } else if (issueMatch) {
      kind = 'issue';
      ({ observed } = await checkIssue(issueMatch[1], issueMatch[2], issueMatch[3]));
    } else {
      kind = 'link';
      ({ observed } = await checkLink(entry.evidence));
    }
    const repoMatch = prMatch || issueMatch;
    let content = null;
    if (entry.stillPresent && repoMatch) {
      content = await checkStillPresent(
        repoMatch[1],
        repoMatch[2],
        entry.stillPresent,
      );
    }
    const ok =
      isOk(kind, entry.status, observed) &&
      (content === null || content === 'present');
    results.push({
      name: entry.name,
      tier: entry.tier,
      evidence: entry.evidence,
      declared: entry.status,
      kind,
      observed,
      content,
      ok,
    });
    const contentNote =
      content === null
        ? ' [no content assertion]'
        : content === 'present'
          ? ' [content present]'
          : ` [content ${content}]`;
    console.log(
      `${ok ? '[ok]   ' : '[DRIFT]'} ${entry.name} — declared ${entry.status}, observed ${observed} (${kind})${contentNote}`,
    );
  }

  const drift = results.filter((r) => !r.ok);
  const out = {
    $comment:
      'AUTO by scripts/verify-adopters.mjs — every ADOPTERS.md evidence link re-checked against GitHub. Do not edit by hand.',
    verified_at: new Date().toISOString().slice(0, 10),
    total: results.length,
    ok: results.length - drift.length,
    drift: drift.map((d) => ({
      name: d.name,
      declared: d.declared,
      observed: d.observed,
      content: d.content,
      evidence: d.evidence,
    })),
    results,
  };
  writeFileSync(OUT_PATH, `${JSON.stringify(out, null, 2)}\n`);
  const unasserted = results.filter((r) => r.content === null).length;
  console.log(
    `\nwrote ${OUT_PATH} — ${out.ok}/${out.total} verified, ${drift.length} drift`,
  );
  if (unasserted > 0) {
    console.log(
      `${unasserted} entries have no Still-present assertion — a merged PR is all that backs them.`,
    );
  }
}

await main();
