#!/usr/bin/env node
/**
 * verify-status-claims.mjs — hold every hand-written statement about the state
 * of a pull request or issue in another repository to what GitHub says.
 *
 * Why: README.md, DEPLOYMENTS.md, STANDARDIZATION-STATUS.md and the website
 * state such things by hand, and nothing checked them. The three /threats
 * actor pages showed NousResearch/hermes-agent#9809 as OPEN for six months
 * after it was closed on 2026-04-15. Each such link is now a claim in
 * website/data/status-claims.json: the state the files give it, and the files
 * that give it. This script
 *   1. checks the list is well formed and that the files agree with it (the
 *      same checks npm test runs; see scripts/lib/status-claims.mjs), then
 *   2. asks GitHub for the state of every claim.
 * A failed claim names every file that states it, so one fix covers them all.
 *
 * Every failure is one of three kinds, reported separately:
 *   - drift      GitHub disagrees with the claimed state: fix the files, then the list
 *   - gone       the pull request, issue or repository no longer exists (404/410)
 *   - unverified GitHub could not be asked (rate limit, 5xx, network, bad body).
 *                Not a pass: re-run with GITHUB_TOKEN set before editing.
 *
 * With --base <commit> (the workflow passes a pull request's base), a claim
 * whose state changed since that commit's list, or that left the list, must
 * come with an edit to every file that list named for it: the files say the
 * state in words, and a state changed in the list alone would leave them
 * saying the old one.
 *
 * Exit 0 when the list, the files and GitHub agree; 1 otherwise; 2 on a bad
 * argument. --offline skips the GitHub step. Auth: set GITHUB_TOKEN to avoid
 * the 60 req/h unauthenticated limit.
 * Run: node scripts/verify-status-claims.mjs [--offline] [--base <commit>]
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classifyLink, failureKind, fetchState } from './lib/github-link-state.mjs';
import {
  OPEN_ONLY_SECTIONS,
  REGISTRY_PATH,
  fileProblems,
  listScopedFiles,
  stateChangeProblems,
  validateRegistry,
} from './lib/status-claims.mjs';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * One result per claim, asked one at a time (a few dozen API calls; no need to
 * fan out). `options` reaches fetchState: fetchImpl, sleep, retries, token.
 */
export async function verifyClaims(claims, options = {}) {
  let results = [];
  for (const claim of claims) {
    const observed = await fetchState(classifyLink(claim.url), options);
    results = [...results, { url: claim.url, declared: claim.state, observed, ok: observed === claim.state, files: claim.files }];
  }
  return results;
}

const ADVICE = {
  drift: `GitHub disagrees with what the listed files say. Fix the wording in each of them, then the claim's state in ${REGISTRY_PATH} (or remove the link and the claim).`,
  gone: 'The pull request, issue or repository no longer exists (404/410). Remove or re-point the link in the listed files, and the claim.',
  unverified: 'GitHub could not be asked (rate limit, server error, network, or an answer that cannot be read). This is not a pass: re-run with a valid GITHUB_TOKEN before editing anything. api-401 means the token itself was rejected.',
};

/** Print one line per claim and a summary by failure kind; return the exit code. */
export function report(results) {
  for (const r of results) {
    const files = r.ok ? '' : `; files: ${r.files.join(', ')}`;
    console.log(`${r.ok ? '[ok]   ' : '[FAIL] '} ${r.url} — claimed ${r.declared}, observed ${r.observed}${files}`);
  }
  const failed = results.filter((r) => !r.ok);
  if (failed.length === 0) {
    console.log(`\n${results.length}/${results.length} status claims match GitHub.`);
    return 0;
  }
  console.error(`\n${failed.length} of ${results.length} status claims failed:`);
  for (const kind of ['drift', 'gone', 'unverified']) {
    const urls = failed.filter((r) => failureKind(r.observed) === kind).map((r) => r.url);
    if (urls.length > 0) console.error(`  ${kind}: ${urls.join(', ')}\n    ${ADVICE[kind]}`);
  }
  return 1;
}

/**
 * The list at `base` and the paths changed since then, read with git in root:
 * { list, changed }, with list null when `base` has no list (it is new), or
 * { error } when the commit or its list cannot be read.
 */
function readBase(root, base) {
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    git('cat-file', '-e', `${base}^{commit}`);
  } catch {
    return { error: `cannot read the base commit ${base}` };
  }
  let text;
  try {
    text = git('show', `${base}:${REGISTRY_PATH}`);
  } catch {
    return { list: null, changed: [] };
  }
  let list;
  try {
    list = JSON.parse(text);
  } catch {
    return { error: `the list at ${base} is not JSON` };
  }
  if (validateRegistry(list).length > 0) return { error: `the list at ${base} is malformed` };
  // Against the working tree, so uncommitted edits count; both sides of a rename.
  const changed = git('diff', '--name-only', '--no-renames', base).split('\n').filter(Boolean);
  return { list, changed };
}

function printProblems(heading, problems) {
  console.error(`[status-claims] ${heading}:`);
  for (const p of problems) console.error(`  - ${p}`);
}

/** options: root (repository root), offline, base, and fetchState's options. */
export async function main(options = {}) {
  const root = options.root ?? REPO_ROOT;
  const read = (path) => {
    try {
      return readFileSync(join(root, path), 'utf8');
    } catch {
      return null;
    }
  };
  let registry;
  try {
    registry = JSON.parse(readFileSync(join(root, REGISTRY_PATH), 'utf8'));
  } catch (err) {
    console.error(`[status-claims] cannot read ${REGISTRY_PATH}: ${err instanceof Error ? err.message : err}`);
    return 1;
  }
  const malformed = validateRegistry(registry);
  if (malformed.length > 0) {
    printProblems(`${REGISTRY_PATH} is malformed`, malformed);
    return 1;
  }
  const disagreements = fileProblems(registry, {
    files: listScopedFiles(root),
    read,
    adoptersText: read('ADOPTERS.md') ?? '',
    openOnlySections: OPEN_ONLY_SECTIONS,
  });
  if (disagreements.length > 0) {
    printProblems(`the files and ${REGISTRY_PATH} disagree`, disagreements);
    return 1;
  }
  console.log(`${registry.claims.length} status claims; the files and the list agree.`);
  if (options.base !== undefined) {
    const base = readBase(root, options.base);
    if (base.error !== undefined) {
      console.error(`[status-claims] ${base.error}`);
      return 1;
    }
    const changes = base.list === null ? [] : stateChangeProblems(base.list, registry, base.changed);
    if (changes.length > 0) {
      printProblems(`states changed since ${options.base} without their files`, changes);
      return 1;
    }
    console.log(base.list === null ? `No list at ${options.base}; no states to compare.` : `Every state changed since ${options.base} came with its files.`);
  }
  if (options.offline) return 0;
  return report(await verifyClaims(registry.claims, options));
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

/** { offline, base } from the command line, or { error }. */
function parseArgs(argv) {
  let options = { offline: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--offline') {
      options = { ...options, offline: true };
    } else if (argv[i] === '--base') {
      const base = argv[i + 1];
      // Never let the value reach git as an option.
      if (base === undefined || base.startsWith('-')) return { error: '--base needs a commit' };
      options = { ...options, base };
      i++;
    } else {
      return { error: `unknown argument "${argv[i]}" (options: --offline, --base <commit>)` };
    }
  }
  return options;
}

if (invokedDirectly()) {
  const options = parseArgs(process.argv.slice(2));
  if (options.error !== undefined) {
    console.error(`[status-claims] ${options.error}`);
    process.exitCode = 2;
  } else {
    process.exitCode = await main(options);
  }
}
