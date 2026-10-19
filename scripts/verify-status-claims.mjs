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
 * Exit 0 when the list, the files and GitHub agree; 1 otherwise; 2 on an
 * unknown argument. --offline skips step 2. Auth: set GITHUB_TOKEN to avoid
 * the 60 req/h unauthenticated limit.
 * Run: node scripts/verify-status-claims.mjs [--offline]
 */

import { readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classifyLink, failureKind, fetchState } from './lib/github-link-state.mjs';
import { OPEN_ONLY_SECTIONS, REGISTRY_PATH, fileProblems, listScopedFiles, validateRegistry } from './lib/status-claims.mjs';

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

function printProblems(heading, problems) {
  console.error(`[status-claims] ${heading}:`);
  for (const p of problems) console.error(`  - ${p}`);
}

/** options: root (repository root), offline, and fetchState's options. */
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

if (invokedDirectly()) {
  const args = process.argv.slice(2);
  const unknown = args.filter((a) => a !== '--offline');
  if (unknown.length > 0) {
    console.error(`[status-claims] unknown argument "${unknown[0]}" (the only option is --offline)`);
    process.exitCode = 2;
  } else {
    process.exitCode = await main({ offline: args.includes('--offline') });
  }
}
