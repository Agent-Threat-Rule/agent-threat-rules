/**
 * status-claims.mjs — the offline half of the status-claims check: is
 * website/data/status-claims.json well formed, and do the files agree with it?
 * Standard library only. scripts/verify-status-claims.mjs runs these checks
 * and then asks GitHub; tests/status-claims.test.ts runs them in npm test.
 *
 * The site, README.md, DEPLOYMENTS.md and STANDARDIZATION-STATUS.md state the
 * current state of pull requests and issues in other repositories by hand.
 * Every such link is recorded in the list as a claim: the link, the state the
 * files give it (open, closed or merged), the files, and optionally refs (exact
 * strings such as "PR #338" for files that name it without a link). The files
 * and the list must agree:
 *   - every file listed for a claim mentions its link or one of its refs;
 *   - every pull request or issue a scanned file links, or names as
 *     owner/repo#N, is listed for that file, unless it is a merged pull
 *     request that ADOPTERS.md declares shipped (verify-adopters.mjs checks
 *     those, and a merged pull request cannot reopen);
 *   - every scanned file that mentions one of a claim's refs is listed;
 *   - an open-only section (README's "Under maintainer review") lists open
 *     claims and nothing else.
 */

import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalUrl, classifyLink, linkKey } from './github-link-state.mjs';

export const REGISTRY_PATH = 'website/data/status-claims.json';
export const STATES = ['open', 'closed', 'merged'];

/** Sections that may list open claims only: a merged or closed PR left there is drift. */
export const OPEN_ONLY_SECTIONS = [{ file: 'README.md', heading: '### Under maintainer review (open PRs)' }];

/** The files scanned: the pages people read as current. */
export const SCOPE = {
  files: ['README.md', 'DEPLOYMENTS.md', 'STANDARDIZATION-STATUS.md'],
  dirs: ['website'],
  extensions: ['.md', '.mdx', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json'],
  skipDirs: ['node_modules', 'public', 'out'],
  skipNames: ['package-lock.json'],
  exclude: {
    [REGISTRY_PATH]: 'the list itself',
    'website/data/errata.json': 'dated corrections: each entry says what was true on its date',
    'website/app/[locale]/red-team/page.tsx':
      'the red-team list has a check of its own in review (PR #691), which moves it to website/data/red-team-tools.json',
    'website/data/red-team-tools.json': 'see the red-team page',
    'website/lib/red-team-tools.ts': 'see the red-team page (the list\'s loader in #691)',
  },
};

/** This repository: its own pull requests and issues are not another repository's state. */
const OWN_REPO = 'agent-threat-rule/agent-threat-rules';

const TOP_FIELDS = new Set(['$comment', 'claims']);
const FIELDS = new Set(['url', 'state', 'files', 'refs']);

function claimKey(url) {
  const link = typeof url === 'string' ? classifyLink(url) : { kind: 'other' };
  return link.kind === 'pr' || link.kind === 'issue' ? linkKey(link) : null;
}

function urlProblems(url, label) {
  const link = typeof url === 'string' ? classifyLink(url) : { kind: 'other' };
  if (link.kind !== 'pr' && link.kind !== 'issue') return [`${label}: url must be a GitHub pull request or issue link`];
  const plain = canonicalUrl(link);
  return plain === url ? [] : [`${label}: write it as ${plain}`];
}

function stateProblems(state, label) {
  if (state === undefined) return [`${label}: missing state (one of ${STATES.join(', ')})`];
  return STATES.includes(state) ? [] : [`${label}: unknown state "${state}" (expected ${STATES.join(', ')})`];
}

function pathProblem(path) {
  if (typeof path !== 'string' || path === '') return 'is not a path';
  if (path.startsWith('/')) return 'is absolute';
  if (path.includes('\\')) return 'uses a backslash';
  if (path.split('/').some((s) => s === '' || s === '.' || s === '..')) return 'has an empty, . or .. segment';
  return null;
}

function repeated(list) {
  return [...new Set(list.filter((x, i) => list.indexOf(x) !== i))];
}

function filesProblems(files, label) {
  if (!Array.isArray(files) || files.length === 0) {
    return [`${label}: files must be a non-empty list of repository-relative paths`];
  }
  const bad = files.flatMap((f) => {
    const problem = pathProblem(f);
    return problem === null ? [] : [`${label}: file ${JSON.stringify(f)} ${problem}`];
  });
  return [...bad, ...repeated(files).map((f) => `${label}: file "${f}" is listed twice`)];
}

function refsProblems(refs, url, label) {
  if (refs === undefined) return [];
  if (!Array.isArray(refs) || refs.length === 0) return [`${label}: refs, when present, must be a non-empty list of strings`];
  const link = typeof url === 'string' ? classifyLink(url) : { kind: 'other' };
  const names = link.kind === 'pr' || link.kind === 'issue' ? new RegExp(`#${link.number}(?!\\d)`) : null;
  const bad = refs.flatMap((ref) => {
    if (typeof ref !== 'string') return [`${label}: ref ${JSON.stringify(ref)} is not a string`];
    return names === null || names.test(ref) ? [] : [`${label}: ref "${ref}" must contain #${link.number}`];
  });
  return [...bad, ...repeated(refs).map((r) => `${label}: ref "${r}" is listed twice`)];
}

function claimProblems(claim, index) {
  if (claim === null || typeof claim !== 'object' || Array.isArray(claim)) return [`claim ${index}: not an object`];
  const label = typeof claim.url === 'string' ? `claim ${index} (${claim.url})` : `claim ${index}`;
  return [
    ...Object.keys(claim).filter((k) => !FIELDS.has(k)).map((k) => `${label}: unknown field "${k}"`),
    ...urlProblems(claim.url, label),
    ...stateProblems(claim.state, label),
    ...filesProblems(claim.files, label),
    ...refsProblems(claim.refs, claim.url, label),
  ];
}

function duplicateProblems(claims) {
  const first = new Map();
  return claims.flatMap((claim, i) => {
    const key = claimKey(claim?.url);
    if (key === null) return [];
    if (!first.has(key)) {
      first.set(key, i);
      return [];
    }
    return [`${key} is listed twice (claims ${first.get(key)} and ${i})`];
  });
}

/** Every structural problem with the list, as readable lines. Empty when it is valid. */
export function validateRegistry(doc) {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    return ['the list must be a JSON object with a "claims" array'];
  }
  const unknown = Object.keys(doc).filter((k) => !TOP_FIELDS.has(k)).map((k) => `unknown top-level field "${k}"`);
  if (!Array.isArray(doc.claims)) return [...unknown, '"claims" must be an array'];
  if (doc.claims.length === 0) return [...unknown, '"claims" is empty: there is nothing to check'];
  return [...unknown, ...doc.claims.flatMap((claim, i) => claimProblems(claim, i)), ...duplicateProblems(doc.claims)];
}

// A pull request or issue link, with or without its scheme, but not on another
// host whose name ends in github.com (api., gist.).
const LINK = /(?:https?:\/\/)?(?<![\w.-])(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/(?:pull|issues)\/(\d+)/gi;
// owner/repo#N in prose. Not inside a longer path or name, and not a markdown
// anchor: ARCHITECTURE.md#2-layers, SPEC.md#3, SPEC.md#6.4.
const SHORT_REF = /(?<![\w./-])([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+)(?<!\.[mM][dD][xX]?)#(\d+)(?![\w-]|\.\d)/g;

/** Text with its \uXXXX escapes decoded: website/lib/i18n.ts stores Chinese that way. */
export function decodeEscapes(text) {
  return text.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

/** The owner/repo#N key of every pull request or issue a text links or names. */
export function scanKeys(text) {
  const plain = decodeEscapes(text);
  const keys = new Set();
  for (const re of [LINK, SHORT_REF]) {
    for (const m of plain.matchAll(re)) keys.add(`${m[1].toLowerCase()}/${m[2].toLowerCase()}#${Number(m[3])}`);
  }
  return keys;
}

/** Whether text contains ref, not as the start of a longer number ("PR #1" is not in "PR #12"). */
function mentionsRef(text, ref) {
  for (let i = text.indexOf(ref); i !== -1; i = text.indexOf(ref, i + 1)) {
    if (!/\d/.test(text[i + ref.length] ?? '')) return true;
  }
  return false;
}

function adoptersField(block, name) {
  const m = new RegExp(`\\*\\*${name}\\*\\*\\s*:\\s*([^\\n]+)`, 'i').exec(block);
  return m ? m[1].trim() : undefined;
}

/** First URL of an Evidence value, read as scripts/verify-adopters.mjs reads it. */
function firstUrl(evidence) {
  const angle = /<(https?:\/\/[^>\s]+)>/.exec(evidence);
  if (angle) return angle[1];
  const link = /^\[.*?\]\((.+?)\)/.exec(evidence);
  if (link) return link[1];
  const bare = /https?:\/\/[^\s>)]+/.exec(evidence);
  return bare ? bare[0] : undefined;
}

/** The tier headings scripts/verify-adopters.mjs reads; it checks nothing under any other. */
const ADOPTERS_TIERS = ['Tier S', 'Tier 1', 'Tier 2', 'Tier 3', 'Tier 4'];

/**
 * Keys of the pull requests ADOPTERS.md gives as evidence for a shipped entry,
 * under the tiers verify-adopters.mjs reads (not the schema example or removed
 * entries). Status defaults to shipped, as there.
 */
export function adoptersShippedKeys(text) {
  const keys = new Set();
  let inTier = false;
  let block = null;
  const flush = () => {
    if (block === null) return;
    const body = block.join('\n');
    const status = (adoptersField(body, 'Status') ?? 'shipped').toLowerCase();
    const evidence = adoptersField(body, 'Evidence');
    const link = evidence === undefined ? { kind: 'other' } : classifyLink(firstUrl(evidence) ?? '');
    if (status === 'shipped' && link.kind === 'pr') keys.add(linkKey(link));
    block = null;
  };
  for (const line of text.split('\n')) {
    if (line.startsWith('## ')) {
      flush();
      inTier = ADOPTERS_TIERS.some((tier) => line.slice(3).startsWith(tier));
    } else if (line.startsWith('### ')) {
      flush();
      block = inTier ? [] : null;
    } else if (block !== null) {
      block.push(line);
    }
  }
  flush();
  return keys;
}

/** The text under a markdown heading, up to the next heading of its level or higher; null if absent. */
export function sectionText(markdown, heading) {
  const lines = markdown.split('\n');
  const start = lines.findIndex((l) => l.trimEnd() === heading);
  if (start === -1) return null;
  const level = /^#+/.exec(heading)[0].length;
  const isEnd = (l) => {
    const m = /^(#+)\s/.exec(l);
    return m !== null && m[1].length <= level;
  };
  const end = lines.findIndex((l, i) => i > start && isEnd(l));
  return lines.slice(start + 1, end === -1 ? undefined : end).join('\n').trim();
}

function listedFileProblems(claims, text) {
  return claims.flatMap((claim) => {
    const key = claimKey(claim.url);
    return claim.files.flatMap((file) => {
      const t = text(file);
      if (t === null) return [`${file}: listed for ${claim.url}, but does not exist`];
      if (scanKeys(t).has(key) || (claim.refs ?? []).some((ref) => mentionsRef(t, ref))) return [];
      return [`${file}: listed for ${claim.url}, but mentions neither the link nor any of its refs`];
    });
  });
}

function unlistedLinkProblems(files, text, byKey, shipped) {
  return files.flatMap((file) => {
    const t = text(file);
    if (t === null) return [];
    return [...scanKeys(t)].filter((key) => !key.startsWith(`${OWN_REPO}#`)).flatMap((key) => {
      const claim = byKey.get(key);
      if (claim === undefined) {
        return shipped.has(key)
          ? []
          : [`${file}: links ${key}, which is not listed in ${REGISTRY_PATH}; add a claim with the state this file gives it (merged ADOPTERS.md evidence needs none)`];
      }
      return claim.files.includes(file)
        ? []
        : [`${file}: links ${key}, which is listed for ${claim.files.join(', ')} only; add ${file} to its files`];
    });
  });
}

function unlistedRefProblems(files, text, claims) {
  return claims.flatMap((claim) => {
    const refs = claim.refs ?? [];
    return files.flatMap((file) => {
      if (claim.files.includes(file)) return [];
      const t = text(file);
      const ref = t === null ? undefined : refs.find((r) => mentionsRef(t, r));
      return ref === undefined ? [] : [`${file}: mentions "${ref}" (a ref of ${claimKey(claim.url)}) but is not among its files`];
    });
  });
}

function openOnlyProblems(sections, text, byKey) {
  return sections.flatMap(({ file, heading }) => {
    const t = text(file);
    const section = t === null ? null : sectionText(t, heading);
    if (section === null) {
      return [`${file}: heading "${heading}" not found; if it was renamed, update OPEN_ONLY_SECTIONS in scripts/lib/status-claims.mjs`];
    }
    return [...scanKeys(section)].flatMap((key) => {
      const claim = byKey.get(key);
      if (claim === undefined) return [`${file}: "${heading}" lists ${key}, which is not an open claim in ${REGISTRY_PATH}`];
      return claim.state === 'open' ? [] : [`${file}: "${heading}" lists ${key}, which is ${claim.state}, not open; move it out of the section`];
    });
  });
}

/**
 * Every disagreement between a valid list and the files, as readable lines.
 * `files` are the scanned files (listScopedFiles); `read(path)` returns a
 * repository file's text or null; `adoptersText` is ADOPTERS.md.
 */
export function fileProblems(registry, { files, read, adoptersText = '', openOnlySections = OPEN_ONLY_SECTIONS }) {
  const cache = new Map();
  const text = (path) => {
    if (!cache.has(path)) {
      const raw = read(path);
      cache.set(path, raw === null ? null : decodeEscapes(raw));
    }
    return cache.get(path);
  };
  const byKey = new Map(registry.claims.map((claim) => [claimKey(claim.url), claim]));
  return [
    ...listedFileProblems(registry.claims, text),
    ...unlistedLinkProblems(files, text, byKey, adoptersShippedKeys(adoptersText)),
    ...unlistedRefProblems(files, text, registry.claims),
    ...openOnlyProblems(openOnlySections, text, byKey),
  ];
}

/**
 * The files say a claim's state in words, so a change to the list must come
 * with the files: compared with `base` (the list on the base branch), every
 * file the base list named for a claim whose state changed, or that left the
 * list, and every file dropped from a claim's files, must be among
 * `changedFiles` (the paths whose text the change edits; a pure rename or a
 * change of file mode is not an edit).
 * That a file was edited is all this can see: not what the edit says.
 */
export function stateChangeProblems(base, head, changedFiles) {
  const now = new Map(head.claims.map((claim) => [claimKey(claim.url), claim]));
  const touched = new Set(changedFiles);
  return base.claims.flatMap((before) => {
    const key = claimKey(before.url);
    const after = now.get(key);
    const fix = '; update what it says (or remove the mention) in the same change';
    if (after === undefined || after.state !== before.state) {
      const what = after === undefined ? 'was removed from the list' : `changed from ${before.state} to ${after.state}`;
      return before.files
        .filter((file) => !touched.has(file))
        .map((file) => `${file}: ${key} ${what}, but this file, which the list named for it, is unchanged${fix}`);
    }
    return before.files
      .filter((file) => !after.files.includes(file) && !touched.has(file))
      .map((file) => `${file}: dropped from ${key}'s files, but unchanged${fix}, or keep it listed`);
  });
}

function walk(root, dir) {
  let entries;
  try {
    entries = readdirSync(join(root, dir), { withFileTypes: true });
  } catch {
    return [];
  }
  return entries.flatMap((entry) => {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      return entry.name.startsWith('.') || SCOPE.skipDirs.includes(entry.name) ? [] : walk(root, rel);
    }
    if (!entry.isFile() || SCOPE.skipNames.includes(entry.name)) return [];
    return SCOPE.extensions.some((ext) => entry.name.endsWith(ext)) ? [rel] : [];
  });
}

/** The scanned files under root, repository-relative with forward slashes, sorted. */
export function listScopedFiles(root) {
  const top = SCOPE.files.filter((f) => {
    try {
      return readdirSync(root).includes(f);
    } catch {
      return false;
    }
  });
  const nested = SCOPE.dirs.flatMap((dir) => walk(root, dir));
  return [...top, ...nested].filter((f) => !(f in SCOPE.exclude)).sort();
}
