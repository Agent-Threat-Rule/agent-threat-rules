#!/usr/bin/env npx tsx
/**
 * sync-github-mcp-topic.ts
 *
 * Wild-scan data collector for the GitHub repository-topic corpus. This is
 * one source among several the wild-scan pipeline pulls from (see
 * docs/research/wild-scan-findings-2026-04-methodology.md for the prior
 * OpenClaw / ClawHub / Skills.sh / Hermes / MCP-Registry pass); this script
 * adds "public GitHub repos tagged as MCP servers" as a new source, since
 * that population was not covered by the 2026-04 scan.
 *
 * DATA SOURCE
 *   GET https://api.github.com/search/repositories?q=topic:<X>
 *   Queried topics: mcp-server, model-context-protocol, mcp-servers,
 *   mcp-tools. A repo can (and often does) carry more than one of these
 *   topics; results are deduped by full_name and matched_query_topics
 *   records every topic query that surfaced it.
 *
 * THE 1000-RESULT CAP
 *   GitHub's search API caps any single query at 1000 results (10 pages x
 *   100 per page); requesting page 11 returns a 422. Two of the four topics
 *   here (mcp-server, model-context-protocol) exceed that on their own
 *   (~20.4K and ~16.8K raw hits, respectively, verified 2026-07-12). This
 *   script implements two coverage modes:
 *     - "top" (default): paginate the first 1000 results sorted by
 *       stars desc. Since noise (forks, tutorials, zero-star toy repos)
 *       concentrates at the bottom of the star distribution, star-sorted
 *       top-1000 is a reasonable high-signal sample even when it is not
 *       exhaustive.
 *     - "full" (--full-coverage): recursively bisect the query by a
 *       `stars:min..max` qualifier (and, if a single star VALUE still
 *       exceeds 1000 results, by a `pushed:` date-range qualifier as a
 *       second axis) until every leaf query is <=1000 results, then
 *       paginates each leaf. This is the standard GitHub-search
 *       "sub-1000 partition" technique. Verified working against this
 *       repo's own small topics; unit-tested against a mocked
 *       count-returning fetch for the >1000 case (tests/sync-github-mcp-
 *       topic.test.ts) since actually invoking it against the live 20K
 *       corpus is a multi-hour crawl (see README in the output dir for the
 *       coverage decision made for the checked-in data pull).
 *
 * NOISE FILTERING (this source is explicitly the noisiest wild-scan input)
 *   1. Forks — GitHub search excludes forks by default (verified:
 *      `topic:mcp-server` and `topic:mcp-server fork:false` return the
 *      identical total_count, 20392, on 2026-07-12). We do not pass
 *      fork:true, so forks are already absent from the raw pool; a
 *      defensive `item.fork` check still runs in case that ever changes.
 *      We deliberately do NOT special-case "meaningfully diverged" forks
 *      (e.g. more stars than parent) — confirming divergence needs one
 *      extra API call per fork to look up the parent, and GitHub's default
 *      exclusion already removes ~98% of forks for these topics (355 of
 *      20747 for mcp-server), so the marginal value did not justify the
 *      extra request volume at this corpus size.
 *   2. Staleness — repos with no push in the last RECENCY_MONTHS (default
 *      12) months are dropped. Applied at the QUERY level via a
 *      `pushed:>=<cutoff>` qualifier (not just post-filtered), which both
 *      shrinks the raw pool before pagination and keeps the star-sorted
 *      "top" mode biased toward active projects.
 *   3. Template / tutorial / demo junk — repos whose name OR description
 *      contains one of TEMPLATE_JUNK_KEYWORDS (see below) as a bounded
 *      token are dropped. This is a blunt heuristic (a repo named
 *      "mcp-server-example-client" could theoretically be a real project)
 *      but is the standard signal for "not a deployable server" in this
 *      ecosystem; false negatives here just mean noise makes it to the
 *      scan phase, which the ATR engine itself must then reject cleanly.
 *
 * CONTENT FETCH (what the scan phase actually needs)
 *   For every surviving repo:
 *     - README (any common casing/extension) via raw.githubusercontent.com.
 *     - A root-level MCP descriptor file, if present: server.json, mcp.json,
 *       mcp-server.json, .mcp.json, smithery.yaml, smithery.yml.
 *     - A best-guess entrypoint file, if present at the root and under
 *       MAX_ENTRYPOINT_BYTES: common JS/TS/Python/Go entrypoint names, or
 *       (for JS/TS projects) the "main"/"module"/"bin" path declared in a
 *       root package.json.
 *   Root-level listing uses one GitHub Contents-API call per repo (counts
 *   against the 5000/hr core quota, NOT the 30/min search quota); file
 *   bodies are fetched from raw.githubusercontent.com, which is not subject
 *   to the REST API quota at all. This keeps the expensive "search" quota
 *   reserved for discovery and lets content collection scale to thousands
 *   of repos per run.
 *
 * RATE LIMITS
 *   - Search API: ~30 req/min, enforced client-side via SEARCH_DELAY_MS,
 *     plus reactive backoff (sleep until x-ratelimit-reset) if the
 *     response headers show the remaining quota is low.
 *   - Core API (repo contents listing): 5000/hr with a token, enforced via
 *     CORE_DELAY_MS plus the same reactive backoff.
 *   - raw.githubusercontent.com: no documented API quota; still throttled
 *     via RAW_DELAY_MS to be a polite crawler.
 *
 * AUTH
 *   GITHUB_TOKEN / GH_TOKEN read from env only. Without one, `gh api` (if
 *   invoked via the CLI wrapper) still authenticates via the logged-in gh
 *   session; this script itself calls `fetch` directly and falls back to
 *   the unauthenticated limits if neither env var is set.
 *
 * OUTPUT
 *   One JSON file per surviving repo:
 *     data/wild-scan/github-topic/<owner>__<repo>.json
 *   Writing is idempotent/resumable: an existing output file is skipped
 *   (not re-fetched) unless --force.
 *
 * Usage:
 *   npx tsx scripts/sync-github-mcp-topic.ts                      # dry-run
 *   npx tsx scripts/sync-github-mcp-topic.ts --write              # collect for real
 *   npx tsx scripts/sync-github-mcp-topic.ts --write --limit 20   # small sample
 *   npx tsx scripts/sync-github-mcp-topic.ts --write --topics mcp-servers,mcp-tools
 *   npx tsx scripts/sync-github-mcp-topic.ts --write --full-coverage --topics mcp-tools
 *   npx tsx scripts/sync-github-mcp-topic.ts --write --skip-content   # metadata only
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 rate-limited past the point a client-side backoff can recover from
 */

import { existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const DATA_DIR = resolve(REPO_ROOT, "data/wild-scan/github-topic");

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const FORCE = flag("--force");
const VERBOSE = flag("--verbose");
const FULL_COVERAGE = flag("--full-coverage");
const SKIP_CONTENT = flag("--skip-content");
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : Infinity;
const RECENCY_MONTHS = opt("--recency-months")
  ? parseInt(opt("--recency-months")!, 10)
  : 12;
const MAX_ENTRYPOINT_BYTES = opt("--max-entrypoint-bytes")
  ? parseInt(opt("--max-entrypoint-bytes")!, 10)
  : 60_000;
const TOPICS = (opt("--topics") ?? "mcp-server,model-context-protocol,mcp-servers,mcp-tools")
  .split(",")
  .map((t) => t.trim())
  .filter(Boolean);

// ---------------------------------------------------------------------------
// Auth / rate-limit plumbing
// ---------------------------------------------------------------------------

const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
const POLITE_UA =
  "ATR-WildScan/1.0 (+https://github.com/Agent-Threat-Rule/agent-threat-rules)";

const SEARCH_DELAY_MS = 2200; // ~27/min, under the documented 30/min search cap
const CORE_DELAY_MS = 400; // ~2.5/sec sustained, well under 5000/hr with a token
const RAW_DELAY_MS = 200; // polite pacing for raw.githubusercontent.com

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function apiHeaders(): Record<string, string> {
  const h: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": POLITE_UA,
  };
  if (TOKEN) h.Authorization = `Bearer ${TOKEN}`;
  return h;
}

// Reactive backoff: if the response headers show the quota is nearly gone,
// sleep until reset rather than immediately hammering a 403.
async function backoffIfLow(res: Response, floor: number): Promise<void> {
  const remaining = parseInt(res.headers.get("x-ratelimit-remaining") ?? "", 10);
  const reset = parseInt(res.headers.get("x-ratelimit-reset") ?? "", 10);
  if (!Number.isNaN(remaining) && remaining <= floor && !Number.isNaN(reset)) {
    const waitMs = Math.max(0, reset * 1000 - Date.now()) + 1000;
    if (VERBOSE)
      console.error(`  near rate-limit floor (remaining=${remaining}); sleeping ${Math.round(waitMs / 1000)}s`);
    await sleep(waitMs);
  }
}

async function ghSearchGet(url: string): Promise<Response> {
  const res = await fetch(url, { headers: apiHeaders() });
  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get("x-ratelimit-remaining");
    const reset = res.headers.get("x-ratelimit-reset");
    console.error(
      `search API rate limited: remaining=${remaining}, reset=${reset}` +
        (TOKEN ? "" : " (set GITHUB_TOKEN to raise the limit)"),
    );
    process.exit(2);
  }
  await backoffIfLow(res, 3);
  return res;
}

async function ghCoreGet(url: string): Promise<Response> {
  const res = await fetch(url, { headers: apiHeaders() });
  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get("x-ratelimit-remaining");
    const reset = res.headers.get("x-ratelimit-reset");
    console.error(
      `core API rate limited: remaining=${remaining}, reset=${reset}` +
        (TOKEN ? "" : " (set GITHUB_TOKEN to raise the limit)"),
    );
    process.exit(2);
  }
  await backoffIfLow(res, 50);
  return res;
}

// ---------------------------------------------------------------------------
// GitHub search types + query building
// ---------------------------------------------------------------------------

interface GhSearchRepoItem {
  id: number;
  full_name: string;
  html_url: string;
  description: string | null;
  fork: boolean;
  topics?: string[];
  stargazers_count: number;
  forks_count: number;
  open_issues_count: number;
  language: string | null;
  license: { spdx_id?: string } | null;
  default_branch: string;
  created_at: string;
  pushed_at: string;
}
interface GhSearchResponse {
  total_count: number;
  incomplete_results: boolean;
  items: GhSearchRepoItem[];
}

function recencyCutoffISO(months: number): string {
  const d = new Date();
  d.setMonth(d.getMonth() - months);
  return d.toISOString().slice(0, 10);
}

function buildTopicQuery(topic: string, extraQualifiers: string[] = []): string {
  const parts = [`topic:${topic}`, "fork:false", ...extraQualifiers];
  return parts.join(" ");
}

async function searchCount(q: string): Promise<number> {
  const u = `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&per_page=1`;
  const res = await ghSearchGet(u);
  await sleep(SEARCH_DELAY_MS);
  if (!res.ok) {
    if (VERBOSE) console.error(`  count query failed (${res.status}) for: ${q}`);
    return 0;
  }
  const body = (await res.json()) as GhSearchResponse;
  return body.total_count ?? 0;
}

// Fetch up to 1000 results (10 pages x 100) for a single query, sorted by
// stars desc. This is the GitHub search hard cap; page 11 would 422.
async function searchPaginate(q: string, cap = 1000): Promise<GhSearchRepoItem[]> {
  const out: GhSearchRepoItem[] = [];
  const maxPages = Math.min(10, Math.ceil(cap / 100));
  for (let page = 1; page <= maxPages; page++) {
    const u =
      `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}` +
      `&sort=stars&order=desc&per_page=100&page=${page}`;
    const res = await ghSearchGet(u);
    await sleep(SEARCH_DELAY_MS);
    if (!res.ok) {
      if (VERBOSE) console.error(`  page ${page} failed (${res.status}) for: ${q}`);
      break;
    }
    const body = (await res.json()) as GhSearchResponse;
    if (!Array.isArray(body.items) || body.items.length === 0) break;
    out.push(...body.items);
    if (out.length >= cap || body.items.length < 100) break;
  }
  return out.slice(0, cap);
}

// ---------------------------------------------------------------------------
// Full-coverage mode: recursive star-range (then pushed-date) bisection so a
// >1000-result topic can be fully paginated in <=1000-result leaf queries.
// ---------------------------------------------------------------------------

// Returns a bisection point strictly between min and max, or null if the
// range cannot be split any further (min == max, i.e. a single star value).
export function bisectStarRange(
  minStars: number,
  maxStars: number,
): { left: [number, number]; right: [number, number] } | null {
  if (maxStars <= minStars) return null;
  const mid = Math.floor((minStars + maxStars) / 2);
  if (mid < minStars || mid >= maxStars) return null;
  return { left: [minStars, mid], right: [mid + 1, maxStars] };
}

// Returns a bisection point strictly between two ISO dates (YYYY-MM-DD), or
// null if the range is already a single day.
export function bisectDateRange(
  fromISO: string,
  toISO: string,
): { left: [string, string]; right: [string, string] } | null {
  const from = new Date(fromISO).getTime();
  const to = new Date(toISO).getTime();
  const oneDay = 86_400_000;
  if (to - from < oneDay) return null;
  const midMs = from + Math.floor((to - from) / 2 / oneDay) * oneDay;
  const mid = new Date(midMs).toISOString().slice(0, 10);
  if (mid === fromISO || mid === toISO) return null;
  return {
    left: [fromISO, mid],
    right: [new Date(midMs + oneDay).toISOString().slice(0, 10), toISO],
  };
}

function starQualifier(minStars: number, maxStars: number): string {
  if (maxStars === Infinity) return `stars:>=${minStars}`;
  if (minStars === maxStars) return `stars:${minStars}`;
  return `stars:${minStars}..${maxStars}`;
}

interface FullCoverageJob {
  minStars: number;
  maxStars: number; // Infinity for the open-ended top bucket
  pushedFrom?: string;
  pushedTo?: string;
}

// Recursively partitions a topic query until every leaf is <=1000 results,
// then paginates each leaf. Star range is the primary axis; if a single star
// VALUE still exceeds 1000 (all-zero-star long tail, most likely), falls
// back to bisecting the pushed-date window as a second axis.
async function collectFullCoverage(
  topic: string,
  pushedCutoffISO: string,
  onLeafPaginated?: (n: number) => void,
): Promise<GhSearchRepoItem[]> {
  const results: GhSearchRepoItem[] = [];
  const queue: FullCoverageJob[] = [
    { minStars: 0, maxStars: Infinity, pushedFrom: pushedCutoffISO },
  ];

  while (queue.length > 0) {
    const job = queue.shift()!;
    const extra = [starQualifier(job.minStars, job.maxStars)];
    if (job.pushedFrom && job.pushedTo) extra.push(`pushed:${job.pushedFrom}..${job.pushedTo}`);
    else if (job.pushedFrom) extra.push(`pushed:>=${job.pushedFrom}`);
    const q = buildTopicQuery(topic, extra);
    const total = await searchCount(q);
    if (total === 0) continue;

    if (total <= 1000) {
      const page = await searchPaginate(q, total);
      results.push(...page);
      onLeafPaginated?.(page.length);
      continue;
    }

    const starSplit = bisectStarRange(job.minStars, job.maxStars === Infinity ? job.minStars + 1_000_000 : job.maxStars);
    if (starSplit) {
      queue.push(
        { minStars: starSplit.left[0], maxStars: starSplit.left[1], pushedFrom: job.pushedFrom, pushedTo: job.pushedTo },
        { minStars: starSplit.right[0], maxStars: job.maxStars === Infinity ? Infinity : starSplit.right[1], pushedFrom: job.pushedFrom, pushedTo: job.pushedTo },
      );
      continue;
    }

    // Star range is already a single value and still >1000 — bisect by
    // pushed-date window instead (default to [cutoff, today] on first entry).
    const dateFrom = job.pushedFrom ?? pushedCutoffISO;
    const dateTo = job.pushedTo ?? new Date().toISOString().slice(0, 10);
    const dateSplit = bisectDateRange(dateFrom, dateTo);
    if (dateSplit) {
      queue.push(
        { minStars: job.minStars, maxStars: job.maxStars, pushedFrom: dateSplit.left[0], pushedTo: dateSplit.left[1] },
        { minStars: job.minStars, maxStars: job.maxStars, pushedFrom: dateSplit.right[0], pushedTo: dateSplit.right[1] },
      );
      continue;
    }

    // Cannot split further on either axis (single star value, single day)
    // and still >1000 results for that instant — take the first 1000 and
    // report the shortfall honestly rather than looping forever.
    console.error(
      `  WARNING: leaf query irreducible at >1000 results (${q}); truncating to first 1000`,
    );
    const page = await searchPaginate(q, 1000);
    results.push(...page);
    onLeafPaginated?.(page.length);
  }

  return results;
}

// ---------------------------------------------------------------------------
// Noise filters (exported for unit tests)
// ---------------------------------------------------------------------------

export function isForkItem(item: Pick<GhSearchRepoItem, "fork">): boolean {
  return item.fork === true;
}

export function isStaleItem(
  item: Pick<GhSearchRepoItem, "pushed_at">,
  cutoffISO: string,
): boolean {
  if (!item.pushed_at) return true;
  return item.pushed_at.slice(0, 10) < cutoffISO;
}

// Bounded-token keyword list for "this is a tutorial/demo/template, not a
// deployable server". Treats [-_./ ] and string boundaries as separators so
// "mcp-server-example-client" matches on "example" but "exemplary-mcp-tool"
// does not. Deliberately excludes generic words that legitimate minimal
// servers commonly use in good faith ("quickstart", "minimal", "simple").
export const TEMPLATE_JUNK_KEYWORDS = [
  "tutorial",
  "tutorials",
  "example",
  "examples",
  "boilerplate",
  "workshop",
  "workshops",
  "demo",
  "demos",
  "starter",
  "sample",
  "samples",
  "learning",
  "course",
  "courses",
  "training",
  "scaffold",
  "skeleton",
  "cookiecutter",
  "awesome", // link-list repos ("awesome-mcp-servers"), not servers themselves
  "hello-world",
  "helloworld",
  "playground",
  "sandbox",
  "walkthrough",
  "bootcamp",
  "exercise",
  "exercises",
  "practice",
  "toy",
];

const TEMPLATE_JUNK_RX = new RegExp(
  `(?:^|[-_./\\s])(?:${TEMPLATE_JUNK_KEYWORDS.join("|")})(?:[-_./\\s]|$)`,
  "i",
);

export interface TemplateJunkVerdict {
  junk: boolean;
  matched?: string;
  field?: "name" | "description";
}

export function templateJunkVerdict(
  fullName: string,
  description: string | null,
): TemplateJunkVerdict {
  const name = fullName.split("/").pop() ?? fullName;
  const nameMatch = name.match(TEMPLATE_JUNK_RX);
  if (nameMatch) return { junk: true, matched: nameMatch[0].trim(), field: "name" };
  if (description) {
    const descMatch = description.match(TEMPLATE_JUNK_RX);
    if (descMatch) return { junk: true, matched: descMatch[0].trim(), field: "description" };
  }
  return { junk: false };
}

// ---------------------------------------------------------------------------
// Content fetch (README + descriptor + entrypoint)
// ---------------------------------------------------------------------------

interface ContentsEntry {
  name: string;
  path: string;
  type: "file" | "dir" | "symlink" | "submodule";
  size: number;
}

async function listRootContents(fullName: string): Promise<ContentsEntry[] | null> {
  const u = `https://api.github.com/repos/${fullName}/contents`;
  const res = await ghCoreGet(u);
  await sleep(CORE_DELAY_MS);
  if (!res.ok) return null;
  const body = (await res.json()) as unknown;
  return Array.isArray(body) ? (body as ContentsEntry[]) : null;
}

async function fetchRaw(fullName: string, branch: string, path: string): Promise<string | null> {
  const u = `https://raw.githubusercontent.com/${fullName}/${encodeURIComponent(branch)}/${path
    .split("/")
    .map(encodeURIComponent)
    .join("/")}`;
  const res = await fetch(u, { headers: { "User-Agent": POLITE_UA } });
  await sleep(RAW_DELAY_MS);
  if (!res.ok) return null;
  return await res.text();
}

const README_RX = /^readme(\.(md|mdx|rst|txt))?$/i;
const DESCRIPTOR_NAMES = new Set(
  ["server.json", "mcp.json", "mcp-server.json", ".mcp.json", "smithery.yaml", "smithery.yml"].map((s) =>
    s.toLowerCase(),
  ),
);
const ENTRYPOINT_ROOT_CANDIDATES = [
  "server.py",
  "main.py",
  "app.py",
  "__main__.py",
  "index.js",
  "index.ts",
  "index.mjs",
  "server.js",
  "server.ts",
  "main.js",
  "main.ts",
  "main.go",
];

function pickReadme(listing: ContentsEntry[]): ContentsEntry | null {
  return listing.find((e) => e.type === "file" && README_RX.test(e.name)) ?? null;
}
function pickDescriptor(listing: ContentsEntry[]): ContentsEntry | null {
  return listing.find((e) => e.type === "file" && DESCRIPTOR_NAMES.has(e.name.toLowerCase())) ?? null;
}
function pickEntrypoint(listing: ContentsEntry[], maxBytes: number): ContentsEntry | null {
  for (const candidate of ENTRYPOINT_ROOT_CANDIDATES) {
    const found = listing.find((e) => e.type === "file" && e.name === candidate);
    if (found && found.size > 0 && found.size <= maxBytes) return found;
  }
  return null;
}

// Root package.json commonly declares the real entrypoint via main/module/bin
// for JS/TS projects whose actual file lives under src/ or dist/ (not visible
// in a root-only listing). One extra contents-API lookup resolves its size.
async function pickEntrypointFromPackageJson(
  fullName: string,
  branch: string,
  listing: ContentsEntry[],
  maxBytes: number,
): Promise<ContentsEntry | null> {
  const pkgEntry = listing.find((e) => e.type === "file" && e.name === "package.json");
  if (!pkgEntry) return null;
  const raw = await fetchRaw(fullName, branch, "package.json");
  if (!raw) return null;
  let parsed: { main?: string; module?: string; bin?: string | Record<string, string> };
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const binPath = typeof parsed.bin === "string" ? parsed.bin : Object.values(parsed.bin ?? {})[0];
  const candidatePath = parsed.main ?? parsed.module ?? binPath;
  if (!candidatePath) return null;
  const cleanPath = candidatePath.replace(/^\.\//, "");
  const u = `https://api.github.com/repos/${fullName}/contents/${cleanPath
    .split("/")
    .map(encodeURIComponent)
    .join("/")}`;
  const res = await ghCoreGet(u);
  await sleep(CORE_DELAY_MS);
  if (!res.ok) return null;
  const body = (await res.json()) as ContentsEntry;
  if (body.type !== "file" || body.size <= 0 || body.size > maxBytes) return null;
  return { name: cleanPath.split("/").pop() ?? cleanPath, path: cleanPath, type: "file", size: body.size };
}

interface FetchedContent {
  readme: { path: string; content: string } | null;
  descriptor: { path: string; content: string } | null;
  entrypoint: { path: string; size: number; content: string } | null;
  notes: string[];
}

async function fetchRepoContent(item: GhSearchRepoItem): Promise<FetchedContent> {
  const notes: string[] = [];
  const branch = item.default_branch || "main";
  const listing = await listRootContents(item.full_name);
  if (!listing) {
    notes.push("root contents listing failed (private, empty, or rate limited)");
    // Best-effort README without a listing: try the most common casing.
    const raw = await fetchRaw(item.full_name, branch, "README.md");
    return {
      readme: raw ? { path: "README.md", content: raw } : null,
      descriptor: null,
      entrypoint: null,
      notes,
    };
  }

  const readmeEntry = pickReadme(listing);
  const descriptorEntry = pickDescriptor(listing);
  let entrypointEntry = pickEntrypoint(listing, MAX_ENTRYPOINT_BYTES);
  if (!entrypointEntry) {
    entrypointEntry = await pickEntrypointFromPackageJson(item.full_name, branch, listing, MAX_ENTRYPOINT_BYTES);
  }

  const readme = readmeEntry
    ? { path: readmeEntry.path, content: (await fetchRaw(item.full_name, branch, readmeEntry.path)) ?? "" }
    : null;
  if (!readmeEntry) notes.push("no README found at root");

  const descriptor = descriptorEntry
    ? { path: descriptorEntry.path, content: (await fetchRaw(item.full_name, branch, descriptorEntry.path)) ?? "" }
    : null;

  const entrypoint = entrypointEntry
    ? {
        path: entrypointEntry.path,
        size: entrypointEntry.size,
        content: (await fetchRaw(item.full_name, branch, entrypointEntry.path)) ?? "",
      }
    : null;
  if (!entrypointEntry) notes.push("no small root-level entrypoint candidate found");

  return { readme, descriptor, entrypoint, notes };
}

// ---------------------------------------------------------------------------
// Output record + file writer
// ---------------------------------------------------------------------------

interface WildScanGithubRecord {
  full_name: string;
  html_url: string;
  description: string | null;
  topics: string[];
  matched_query_topics: string[];
  stars: number;
  forks: number;
  open_issues: number;
  language: string | null;
  license: string | null;
  default_branch: string;
  created_at: string;
  last_pushed_at: string;
  fetched_at: string;
  readme: { path: string; content: string } | null;
  descriptor_file: { path: string; content: string } | null;
  entrypoint_file: { path: string; size: number; content: string } | null;
  content_fetch_notes: string[];
}

function outputPath(fullName: string): string {
  const [owner, repo] = fullName.split("/");
  return resolve(DATA_DIR, `${owner}__${repo}.json`);
}

function alreadyCollected(fullName: string): boolean {
  const p = outputPath(fullName);
  return existsSync(p) && statSync(p).size > 0;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  topics_queried: string[];
  recency_cutoff: string;
  raw_total_count_per_topic: Record<string, number>;
  raw_after_recency_filter_count_per_topic: Record<string, number>;
  raw_items_collected_per_topic: Record<string, number>;
  coverage_mode_per_topic: Record<string, "top-1000" | "full">;
  deduped_candidates: number;
  excluded_fork: number;
  excluded_stale: number;
  excluded_template_junk: number;
  survivors: number;
  already_collected_skipped: number;
  content_fetch_failures: number;
  written_files: number;
}

async function main(): Promise<void> {
  if (WRITE && !existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

  const cutoffISO = recencyCutoffISO(RECENCY_MONTHS);
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    topics_queried: TOPICS,
    recency_cutoff: cutoffISO,
    raw_total_count_per_topic: {},
    raw_after_recency_filter_count_per_topic: {},
    raw_items_collected_per_topic: {},
    coverage_mode_per_topic: {},
    deduped_candidates: 0,
    excluded_fork: 0,
    excluded_stale: 0,
    excluded_template_junk: 0,
    survivors: 0,
    already_collected_skipped: 0,
    content_fetch_failures: 0,
    written_files: 0,
  };

  const byFullName = new Map<string, { item: GhSearchRepoItem; topics: Set<string> }>();

  for (const topic of TOPICS) {
    console.error(`== topic:${topic} ==`);
    const rawTotal = await searchCount(buildTopicQuery(topic));
    const rawAfterRecency = await searchCount(buildTopicQuery(topic, [`pushed:>=${cutoffISO}`]));
    summary.raw_total_count_per_topic[topic] = rawTotal;
    summary.raw_after_recency_filter_count_per_topic[topic] = rawAfterRecency;

    let items: GhSearchRepoItem[];
    if (FULL_COVERAGE) {
      summary.coverage_mode_per_topic[topic] = "full";
      items = await collectFullCoverage(topic, cutoffISO, (n) => {
        if (VERBOSE) console.error(`  leaf paginated: +${n}`);
      });
    } else {
      summary.coverage_mode_per_topic[topic] = "top-1000";
      const q = buildTopicQuery(topic, [`pushed:>=${cutoffISO}`]);
      items = await searchPaginate(q, 1000);
    }
    summary.raw_items_collected_per_topic[topic] = items.length;
    console.error(
      `  raw_total=${rawTotal} raw_after_recency=${rawAfterRecency} collected=${items.length} mode=${summary.coverage_mode_per_topic[topic]}`,
    );

    for (const item of items) {
      const existing = byFullName.get(item.full_name);
      if (existing) existing.topics.add(topic);
      else byFullName.set(item.full_name, { item, topics: new Set([topic]) });
    }
  }

  summary.deduped_candidates = byFullName.size;

  const survivors: { item: GhSearchRepoItem; topics: string[] }[] = [];
  for (const { item, topics } of byFullName.values()) {
    if (isForkItem(item)) {
      summary.excluded_fork += 1;
      continue;
    }
    if (isStaleItem(item, cutoffISO)) {
      summary.excluded_stale += 1;
      continue;
    }
    const verdict = templateJunkVerdict(item.full_name, item.description);
    if (verdict.junk) {
      summary.excluded_template_junk += 1;
      if (VERBOSE)
        console.error(`  skip (template/junk, ${verdict.field}="${verdict.matched}") ${item.full_name}`);
      continue;
    }
    survivors.push({ item, topics: [...topics] });
  }
  summary.survivors = survivors.length;

  let processed = 0;
  for (const { item, topics } of survivors) {
    if (processed >= LIMIT) break;
    if (!FORCE && alreadyCollected(item.full_name)) {
      summary.already_collected_skipped += 1;
      continue;
    }
    processed += 1;

    let content: FetchedContent = { readme: null, descriptor: null, entrypoint: null, notes: ["--skip-content set"] };
    if (!SKIP_CONTENT) {
      try {
        content = await fetchRepoContent(item);
        if (!content.readme) summary.content_fetch_failures += 1;
      } catch (e) {
        summary.content_fetch_failures += 1;
        content.notes.push(`content fetch threw: ${e}`);
      }
    }

    const record: WildScanGithubRecord = {
      full_name: item.full_name,
      html_url: item.html_url,
      description: item.description,
      topics: item.topics ?? [],
      matched_query_topics: topics,
      stars: item.stargazers_count,
      forks: item.forks_count,
      open_issues: item.open_issues_count,
      language: item.language,
      license: item.license?.spdx_id ?? null,
      default_branch: item.default_branch,
      created_at: item.created_at,
      last_pushed_at: item.pushed_at,
      fetched_at: new Date().toISOString(),
      readme: content.readme,
      descriptor_file: content.descriptor,
      entrypoint_file: content.entrypoint,
      content_fetch_notes: content.notes,
    };

    if (WRITE) {
      writeFileSync(outputPath(item.full_name), JSON.stringify(record, null, 2), "utf-8");
      summary.written_files += 1;
    } else if (VERBOSE) {
      console.log(`would write ${outputPath(item.full_name)}`);
    }
    if (VERBOSE || processed % 50 === 0)
      console.error(`  [${processed}/${Math.min(survivors.length, LIMIT)}] ${item.full_name}`);
  }

  console.log(JSON.stringify(summary, null, 2));
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
