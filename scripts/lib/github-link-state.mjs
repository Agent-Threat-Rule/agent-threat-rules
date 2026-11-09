/**
 * github-link-state.mjs — what GitHub says a pull request or issue is: open,
 * closed or merged. Standard library only, so a workflow can run it without
 * npm install.
 *
 * Written for the scripts that hold a hand-written status to GitHub
 * (scripts/verify-status-claims.mjs). A request is retried on a rate limit, a
 * 5xx or a network error, never on a 4xx such as a 404, and times out after
 * TIMEOUT_MS. An answer that is not a state comes back as an error string, so
 * a caller can never mistake "GitHub could not be asked" for a state:
 *   'api-<status>'  GitHub answered with an error status
 *   'network-error' no answer
 *   'bad-response'  an answer that is not a readable pull request or issue
 *   'unverifiable'  the link is not a pull request or an issue
 */

export const TIMEOUT_MS = 20_000;
export const RETRIES = 2;

const NAME = /^[A-Za-z0-9_.-]+$/;
const SHA = /^[0-9a-f]{7,40}$/i;

/**
 * { kind: 'pr' | 'issue', owner, repo, number } for a GitHub pull request or
 * issue URL, { kind: 'commit', owner, repo, sha } for a commit URL (7-40 hex),
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
  if (!named(owner) || !named(repo)) return { kind: 'other' };
  if (type === 'commit') {
    return SHA.test(num ?? '') ? { kind: 'commit', owner, repo, sha: num.toLowerCase() } : { kind: 'other' };
  }
  if (!/^\d+$/.test(num ?? '')) return { kind: 'other' };
  if (type !== 'pull' && type !== 'issues') return { kind: 'other' };
  return { kind: type === 'pull' ? 'pr' : 'issue', owner, repo, number: Number(num) };
}

/**
 * 'owner/repo#N', lower-cased. Pull requests and issues share one number space
 * and GitHub names are case-insensitive, so /pull/5 and /issues/5 of O/R and
 * o/r all have one key.
 */
export function linkKey(link) {
  return `${link.owner.toLowerCase()}/${link.repo.toLowerCase()}#${link.number}`;
}

/** https://github.com/<owner>/<repo>/(pull|issues)/<N>, keeping the case it was given. */
export function canonicalUrl(link) {
  return `https://github.com/${link.owner}/${link.repo}/${link.kind === 'pr' ? 'pull' : 'issues'}/${link.number}`;
}

function apiHeaders(token) {
  return {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'atr-status-claims-verify',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

const realSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const transient = (status) => status === 429 || status >= 500;

/** GET an API path: { body } on success, { error } otherwise. */
async function getJson(path, { fetchImpl, sleep, retries, token }) {
  let error = 'network-error';
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await sleep(1000 * 2 ** (attempt - 1));
    let res;
    try {
      res = await fetchImpl(`https://api.github.com${path}`, {
        headers: apiHeaders(token),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
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

/**
 * 'open' | 'closed' | 'merged', or an error string. An /issues/ link to a pull
 * request (GitHub redirects it) is read through the issues endpoint, which says
 * merged only in pull_request.merged_at.
 */
export async function fetchState(link, options = {}) {
  if (link.kind !== 'pr' && link.kind !== 'issue') return 'unverifiable';
  const opts = {
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
    sleep: options.sleep ?? realSleep,
    retries: options.retries ?? RETRIES,
    token: 'token' in options ? options.token : process.env.GITHUB_TOKEN,
  };
  const endpoint = link.kind === 'pr' ? 'pulls' : 'issues';
  const { body, error } = await getJson(`/repos/${link.owner}/${link.repo}/${endpoint}/${link.number}`, opts);
  if (error) return error;
  if (typeof body.state !== 'string') return 'bad-response';
  const mergedAt = link.kind === 'pr' ? body.merged_at : body.pull_request?.merged_at;
  if (mergedAt) return 'merged';
  return body.state === 'open' ? 'open' : 'closed';
}

const STATES = new Set(['open', 'closed', 'merged']);

/**
 * How a check whose observed state differs from the claim failed:
 *   'drift'      GitHub answered with a different state
 *   'gone'       404 or 410: the pull request, issue or repository is gone
 *   'unverified' anything else: GitHub could not be asked, which is not a pass
 */
export function failureKind(observed) {
  if (STATES.has(observed)) return 'drift';
  if (observed === 'api-404' || observed === 'api-410') return 'gone';
  return 'unverified';
}
