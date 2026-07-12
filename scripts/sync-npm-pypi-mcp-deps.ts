#!/usr/bin/env npx tsx
/**
 * sync-npm-pypi-mcp-deps.ts
 *
 * Wild-scan package discovery: finds npm and PyPI packages that DEPEND ON
 * the official MCP SDKs (`@modelcontextprotocol/sdk` on npm, `mcp` on PyPI)
 * and writes their registry metadata (name, version, description,
 * repository URL, README content) to
 * data/wild-scan/package-deps/<ecosystem>__<package-name>.json.
 *
 * Rationale: many MCP servers are distributed as ordinary npm/PyPI packages
 * rather than being listed in any dedicated MCP directory. "Depends on the
 * official SDK" is a much higher-signal, lower-noise discovery method than
 * free-text keyword search ("mcp", "model context protocol", ...) because it
 * captures packages that genuinely implement the protocol instead of just
 * mentioning it in a description. The output feeds the next wild-scan pass
 * (running the ATR engine over each package's README/description content to
 * look for prompt-injection / tool-poisoning / exfiltration payloads).
 *
 * Data source strategy -- attempted in order, first real success kept:
 *
 *   TRIED, REJECTED: deps.dev v3alpha `GetDependents` RPC
 *     (`/v3alpha/systems/{system}/packages/{name}/versions/{version}:dependents`).
 *     Free, keyless, well documented -- but confirmed (both by reading the
 *     public proto at github.com/google/deps.dev, api/v3alpha/apiv3alpha.proto,
 *     and by a live query) to return ONLY aggregate counts
 *     (dependent_count / direct_dependent_count / indirect_dependent_count),
 *     never the actual list of dependent package names. Not usable for this
 *     task's "enumerate the dependents" requirement.
 *
 *   TRIED, REJECTED: npmjs.com package page `?activeTab=dependents` (the
 *     human-facing dependents tab suggested as a scrape target). A live
 *     fetch returns a Cloudflare "Just a moment..." managed-challenge page,
 *     not the dependents HTML. Scraping past that would mean solving a bot
 *     challenge, which is out of bounds regardless of feasibility.
 *
 *   TRIED, REJECTED: pypi.org web search (`/search/?q=...`), considered as
 *     the PyPI-side equivalent of the npm keyword-search fallback. A live
 *     fetch returns a Fastly "Client Challenge" bot-detection page (PyPI's
 *     XML-RPC search API was also permanently disabled in 2023 for abuse).
 *     Same reasoning as above: not scraped.
 *
 *   NOT AVAILABLE: Libraries.io API. Needs `LIBRARIES_IO_API_KEY`; not
 *     present in this environment. If a maintainer adds that key later, it
 *     is a strictly better dependents source than what follows below and
 *     this script should be extended to prefer it.
 *
 *   NOT AVAILABLE: GitHub code search (`GET /search/code`) as a way to find
 *     `"@modelcontextprotocol/sdk"` inside package.json files across all of
 *     GitHub. Confirmed to return 401 "Requires authentication" even for
 *     tiny/unauthenticated volumes -- GitHub requires a token for code
 *     search specifically, unlike most other REST endpoints.
 *
 *   USED (PRIMARY, both ecosystems): repos.ecosyste.ms
 *     `GET /api/v1/usage/<ecosystem>/<package>/dependencies` -- a free,
 *     keyless, documented API run by the ecosyste.ms project (the actively
 *     maintained, modern, FOSS-funded successor to Libraries.io-style
 *     ecosystem data, by the same original author). It returns real GitHub
 *     repositories whose parsed manifest/lockfile declares a dependency on
 *     the target package, each tagged `direct: true/false` and
 *     `kind: runtime/development/...`. This IS a genuine "depends on the
 *     SDK" signal (derived from actually parsing package.json /
 *     package-lock.json / pyproject.toml across a large GitHub crawl), not
 *     a keyword match -- exactly the higher-signal source this task wants.
 *     We keep only `direct === true && kind === "runtime"` entries.
 *
 *     Caveats found while integration-testing against this repo:
 *       - Paging beyond roughly page 15-20 (per_page=100) intermittently
 *         returns `{"error":"internal server error"}` instead of an empty
 *         array. Handled as "stop paginating, log a warning" rather than a
 *         fatal error, since it is a service-side limitation, not ours.
 *       - `per_page` silently stops behaving above ~200-300; capped at 100
 *         here to stay inside the well-behaved range.
 *       - This endpoint returns GitHub REPOSITORIES, not registry package
 *         names. Each repo is resolved to a real published package name by
 *         reading its own manifest (see resolveNpmPackageName /
 *         resolvePypiPackageName below) via raw.githubusercontent.com (a
 *         plain static CDN, not an authenticated API), then confirmed
 *         against the actual registry. Repos with no self-declared name, or
 *         whose name does not resolve on the registry (unpublished / private
 *         packages -- common for PyPI in particular, since many Python MCP
 *         servers ship only as GitHub source, never `pip`-published), are
 *         skipped and counted separately. This is a real, honestly-reported
 *         coverage gap, not a bug.
 *
 *   USED (SUPPLEMENTARY, npm only): npm registry search API
 *     (`registry.npmjs.org/-/v1/search?text=...`), a free, keyless,
 *     documented endpoint. Used as the lower-precision keyword fallback the
 *     task explicitly allows, to catch packages whose GitHub repo is
 *     private / not yet crawled by ecosyste.ms. There is no keyless
 *     equivalent for PyPI (see above), so PyPI coverage relies solely on the
 *     repos.ecosyste.ms pass; this asymmetry is reported in the run summary.
 *
 * Rate-limit discipline: every remote call goes through a single
 * rate-limited fetch helper with a per-source minimum delay
 * (repos.ecosyste.ms documents a generous 5000 req/hour anonymous tier via
 * its `x-ratelimit-*` response headers, observed live; raw.githubusercontent.com
 * and the npm/PyPI registries do not publish a formal limit but are treated
 * with the same courtesy). Calls are strictly sequential (no concurrency)
 * on purpose.
 *
 * Usage:
 *   npx tsx scripts/sync-npm-pypi-mcp-deps.ts                  # dry-run
 *   npx tsx scripts/sync-npm-pypi-mcp-deps.ts --write          # write files
 *   npx tsx scripts/sync-npm-pypi-mcp-deps.ts --ecosystem npm  # one ecosystem
 *   npx tsx scripts/sync-npm-pypi-mcp-deps.ts --limit 20       # cap output
 *   npx tsx scripts/sync-npm-pypi-mcp-deps.ts --no-keyword     # skip npm keyword pass
 *   npx tsx scripts/sync-npm-pypi-mcp-deps.ts --force          # overwrite existing
 *   npx tsx scripts/sync-npm-pypi-mcp-deps.ts --verbose
 *
 * Exit codes:
 *   0 success (including "ran fine, found zero new packages")
 *   1 fatal (no source reachable at all for either ecosystem)
 */

import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const OUT_DIR = resolve(REPO_ROOT, "data/wild-scan/package-deps");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const FORCE = flag("--force");
const VERBOSE = flag("--verbose");
const NO_KEYWORD = flag("--no-keyword");
const ECOSYSTEM_FILTER = opt("--ecosystem"); // "npm" | "pypi"
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : Infinity;
const MAX_PAGES = opt("--max-pages") ? parseInt(opt("--max-pages")!, 10) : 20;

const README_MAX_CHARS = 50_000;
const USER_AGENT =
  "atr-wildscan-sync (github.com/Agent-Threat-Rule/agent-threat-rules)";

// Target SDK packages -- the discovery seed for each ecosystem.
const SDK_PACKAGE: Record<"npm" | "pypi", string> = {
  npm: "@modelcontextprotocol/sdk",
  pypi: "mcp",
};

// Supplementary npm keyword search terms (task-authorized lower-precision
// fallback). No PyPI equivalent exists keylessly -- see header comment.
const NPM_KEYWORD_QUERIES = [
  "keywords:mcp-server",
  "keywords:model-context-protocol",
  "mcp server sdk",
];

function log(msg: string): void {
  console.error(msg);
}

function vlog(msg: string): void {
  if (VERBOSE) console.error(msg);
}

async function sleep(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// Generic rate-limited fetch helpers
// ---------------------------------------------------------------------------

interface FetchResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
}

async function fetchJson<T>(
  url: string,
  delayAfterMs: number,
): Promise<FetchResult<T>> {
  let status = 0;
  try {
    const resp = await fetch(url, {
      headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
    });
    status = resp.status;
    if (!resp.ok) {
      vlog(`  non-200 (${status}) for ${url}`);
      return { ok: false, status, data: null };
    }
    const data = (await resp.json()) as T;
    return { ok: true, status, data };
  } catch (e) {
    vlog(`  fetch error for ${url}: ${e}`);
    return { ok: false, status, data: null };
  } finally {
    await sleep(delayAfterMs);
  }
}

async function fetchText(
  url: string,
  delayAfterMs: number,
): Promise<string | null> {
  try {
    const resp = await fetch(url, { headers: { "User-Agent": USER_AGENT } });
    if (!resp.ok) return null;
    return await resp.text();
  } catch (e) {
    vlog(`  fetch error for ${url}: ${e}`);
    return null;
  } finally {
    await sleep(delayAfterMs);
  }
}

// ---------------------------------------------------------------------------
// repos.ecosyste.ms -- primary "depends on the SDK" discovery
// ---------------------------------------------------------------------------

interface EcosysteRepository {
  full_name: string;
  default_branch: string | null;
  description: string | null;
}

interface EcosysteDependencyItem {
  package_name: string;
  ecosystem: string;
  requirements: string;
  direct: boolean;
  kind: string;
  repository: EcosysteRepository;
}

interface DependentRepo {
  fullName: string;
  defaultBranch: string;
  requirement: string;
}

// Pages through repos.ecosyste.ms's usage/dependencies endpoint for one
// ecosystem/package, keeping only direct runtime dependents, deduped by
// repo. Stops on an empty page, a malformed page (the intermittent
// "internal server error" observed above ~page 15-20), or maxPages,
// whichever comes first -- and reports which one via the returned reason.
async function fetchSdkDependentRepos(
  ecosystem: "npm" | "pypi",
  sdkPackage: string,
  maxPages: number,
): Promise<{ repos: DependentRepo[]; pagesFetched: number; stopReason: string }> {
  const seen = new Map<string, DependentRepo>();
  const encodedPkg = encodeURIComponent(sdkPackage);
  let page = 1;
  let stopReason = "exhausted (empty page)";

  while (page <= maxPages) {
    const url =
      `https://repos.ecosyste.ms/api/v1/usage/${ecosystem}/${encodedPkg}/dependencies` +
      `?per_page=100&page=${page}`;
    const res = await fetchJson<EcosysteDependencyItem[] | { error: string }>(
      url,
      300,
    );
    if (!res.ok || res.data === null) {
      stopReason = `fetch failed at page ${page} (status ${res.status})`;
      break;
    }
    if (!Array.isArray(res.data)) {
      stopReason = `non-array response at page ${page}: ${JSON.stringify(res.data).slice(0, 100)}`;
      break;
    }
    if (res.data.length === 0) {
      stopReason = `exhausted (empty page ${page})`;
      break;
    }
    for (const item of res.data) {
      if (!item.direct || item.kind !== "runtime") continue;
      const fullName = item.repository?.full_name;
      if (!fullName || seen.has(fullName)) continue;
      seen.set(fullName, {
        fullName,
        defaultBranch: item.repository.default_branch || "main",
        requirement: item.requirements,
      });
    }
    vlog(
      `  ${ecosystem}/${sdkPackage} page ${page}: ${res.data.length} raw, ${seen.size} unique direct-runtime repos so far`,
    );
    if (res.data.length < 100) {
      stopReason = `exhausted (short page ${page})`;
      break;
    }
    page += 1;
  }
  if (page > maxPages) stopReason = `hit --max-pages cap (${maxPages})`;

  return { repos: Array.from(seen.values()), pagesFetched: page, stopReason };
}

// ---------------------------------------------------------------------------
// Resolve a dependent GitHub repo to a real, published registry package name
// ---------------------------------------------------------------------------

async function fetchRawFile(
  repoFullName: string,
  branch: string,
  path: string,
): Promise<string | null> {
  const url = `https://raw.githubusercontent.com/${repoFullName}/${branch}/${path}`;
  return fetchText(url, 200);
}

async function resolveNpmPackageName(
  repo: DependentRepo,
): Promise<string | null> {
  const branchCandidates = [...new Set([repo.defaultBranch, "main", "master"])];
  for (const branch of branchCandidates) {
    const raw = await fetchRawFile(repo.fullName, branch, "package.json");
    if (!raw) continue;
    try {
      const doc = JSON.parse(raw) as { name?: string };
      if (doc.name) return doc.name;
    } catch {
      // malformed package.json -- try next branch guess, else give up below
    }
    break; // got a response on this branch (even if unparsable); don't retry other branches
  }
  return null;
}

// Minimal, dependency-free extraction of a PEP 621 / Poetry project name.
// Deliberately NOT a full TOML parser -- we only need one scalar field and
// adding a TOML dependency for that would be overkill for a data-collection
// script that already treats "no name found" as a normal, counted outcome.
function extractTomlProjectName(toml: string): string | null {
  const projectMatch = toml.match(/\[project\]([\s\S]*?)(?:\n\[|$)/);
  const poetryMatch = toml.match(/\[tool\.poetry\]([\s\S]*?)(?:\n\[|$)/);
  for (const block of [projectMatch?.[1], poetryMatch?.[1]]) {
    if (!block) continue;
    const nameMatch = block.match(/^\s*name\s*=\s*["']([^"']+)["']/m);
    if (nameMatch) return nameMatch[1];
  }
  return null;
}

function extractSetupPyName(setupPy: string): string | null {
  const m = setupPy.match(/\bname\s*=\s*["']([^"']+)["']/);
  return m ? m[1] : null;
}

function extractSetupCfgName(setupCfg: string): string | null {
  const metadataBlock = setupCfg.match(/\[metadata\]([\s\S]*?)(?:\n\[|$)/);
  if (!metadataBlock) return null;
  const m = metadataBlock[1].match(/^\s*name\s*=\s*(.+)$/m);
  return m ? m[1].trim() : null;
}

async function resolvePypiPackageName(
  repo: DependentRepo,
): Promise<string | null> {
  const branch = repo.defaultBranch;
  const pyproject = await fetchRawFile(repo.fullName, branch, "pyproject.toml");
  if (pyproject) {
    const name = extractTomlProjectName(pyproject);
    if (name) return name;
  }
  const setupCfg = await fetchRawFile(repo.fullName, branch, "setup.cfg");
  if (setupCfg) {
    const name = extractSetupCfgName(setupCfg);
    if (name) return name;
  }
  const setupPy = await fetchRawFile(repo.fullName, branch, "setup.py");
  if (setupPy) {
    const name = extractSetupPyName(setupPy);
    if (name) return name;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Registry metadata fetchers -- canonical name/version/description/readme
// ---------------------------------------------------------------------------

interface CollectedPackage {
  package: string;
  ecosystem: "npm" | "pypi";
  version: string;
  description: string;
  repository_url: string | null;
  readme: string;
  discovery: {
    method: "sdk-dependent" | "keyword-search";
    source: string;
    sdk_dependency?: string;
    dependent_repo?: string;
    matched_query?: string;
  };
  collected_at: string;
}

interface NpmRegistryDoc {
  name: string;
  "dist-tags"?: { latest?: string };
  versions?: Record<
    string,
    {
      description?: string;
      repository?: { url?: string } | string;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    }
  >;
  readme?: string;
  description?: string;
  repository?: { url?: string } | string;
}

// Fetched metadata plus a verification flag, kept separate from
// CollectedPackage so it never leaks into the written JSON file (which only
// documents name/version/description/repo/readme, per the task's schema).
interface ResolvedMeta {
  meta: Omit<CollectedPackage, "discovery" | "collected_at" | "ecosystem">;
  dependsOnSdk: boolean;
}

function truncateReadme(text: string): string {
  if (text.length <= README_MAX_CHARS) return text;
  return (
    text.slice(0, README_MAX_CHARS) +
    `\n\n... (truncated at ${README_MAX_CHARS} chars by sync-npm-pypi-mcp-deps.ts)`
  );
}

function normalizeRepoUrl(
  repo: { url?: string } | string | undefined,
): string | null {
  if (!repo) return null;
  const raw = typeof repo === "string" ? repo : repo.url;
  if (!raw) return null;
  return raw
    .replace(/^git\+/, "")
    .replace(/\.git$/, "")
    .replace(/^git:\/\//, "https://");
}

async function fetchNpmRegistryMeta(name: string): Promise<ResolvedMeta | null> {
  const url = `https://registry.npmjs.org/${encodeURIComponent(name)}`;
  const res = await fetchJson<NpmRegistryDoc>(url, 200);
  if (!res.ok || !res.data) return null;
  const doc = res.data;
  const latest = doc["dist-tags"]?.latest;
  const versionMeta = latest ? doc.versions?.[latest] : undefined;
  const allDeps = {
    ...versionMeta?.dependencies,
    ...versionMeta?.devDependencies,
    ...versionMeta?.peerDependencies,
  };
  return {
    meta: {
      package: doc.name || name,
      version: latest || "unknown",
      description: versionMeta?.description || doc.description || "",
      repository_url: normalizeRepoUrl(versionMeta?.repository || doc.repository),
      readme: truncateReadme(doc.readme || ""),
    },
    dependsOnSdk: SDK_PACKAGE.npm in allDeps,
  };
}

interface PypiJson {
  info?: {
    name?: string;
    version?: string;
    summary?: string;
    description?: string;
    home_page?: string | null;
    project_urls?: Record<string, string> | null;
    requires_dist?: string[] | null;
  };
}

// A requires_dist entry looks like "mcp>=1.0" or "fastmcp-slim[client]==3.4.4;
// extra == \"foo\"" -- strip version specifiers / extras / markers to get the
// bare distribution name for a dependency-name comparison.
function bareDistName(requirement: string): string {
  return requirement
    .split(/[\s\[(<>=!~;]/, 1)[0]
    .trim()
    .toLowerCase();
}

async function fetchPypiMeta(name: string): Promise<ResolvedMeta | null> {
  const url = `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
  const res = await fetchJson<PypiJson>(url, 200);
  if (!res.ok || !res.data?.info) return null;
  const info = res.data.info;
  const repoUrl =
    info.project_urls?.Repository ||
    info.project_urls?.Source ||
    info.project_urls?.Homepage ||
    info.home_page ||
    null;
  const distNames = (info.requires_dist ?? []).map(bareDistName);
  return {
    meta: {
      package: info.name || name,
      version: info.version || "unknown",
      description: info.summary || "",
      repository_url: repoUrl || null,
      readme: truncateReadme(info.description || ""),
    },
    dependsOnSdk: distNames.includes(SDK_PACKAGE.pypi),
  };
}

// ---------------------------------------------------------------------------
// npm registry keyword search (supplementary discovery, npm only)
// ---------------------------------------------------------------------------

interface NpmSearchResponse {
  objects: Array<{ package: { name: string } }>;
}

async function npmKeywordSearch(query: string, size = 50): Promise<string[]> {
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(query)}&size=${size}`;
  const res = await fetchJson<NpmSearchResponse>(url, 300);
  if (!res.ok || !res.data) return [];
  return res.data.objects.map((o) => o.package.name);
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

function slugifyPackageName(name: string): string {
  return name.replace(/^@/, "").replace(/\//g, "__");
}

function outputPath(ecosystem: "npm" | "pypi", name: string): string {
  return join(OUT_DIR, `${ecosystem}__${slugifyPackageName(name)}.json`);
}

function existingOutputs(): Set<string> {
  if (!existsSync(OUT_DIR)) return new Set();
  return new Set(readdirSync(OUT_DIR));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  ecosystems_run: string[];
  sources_used: string[];
  npm: {
    sdk_dependent_repos_found: number;
    sdk_dependent_pages_fetched: number;
    sdk_dependent_stop_reason: string;
    name_resolution_failed: number;
    not_published_on_registry: number;
    name_collision_false_positive: number;
    keyword_candidates: number;
  };
  pypi: {
    sdk_dependent_repos_found: number;
    sdk_dependent_pages_fetched: number;
    sdk_dependent_stop_reason: string;
    name_resolution_failed: number;
    not_published_on_registry: number;
    name_collision_false_positive: number;
  };
  unique_packages_seen: number;
  already_collected_skipped: number;
  new_files_written: number;
  written_files: string[];
}

async function collectEcosystem(
  ecosystem: "npm" | "pypi",
  summary: RunSummary,
  existing: Set<string>,
  writtenCount: { n: number },
): Promise<void> {
  const eco = summary[ecosystem];
  const seedPackage = SDK_PACKAGE[ecosystem];

  log(`\n=== ${ecosystem}: dependents of ${seedPackage} (repos.ecosyste.ms) ===`);
  const { repos, pagesFetched, stopReason } = await fetchSdkDependentRepos(
    ecosystem,
    seedPackage,
    MAX_PAGES,
  );
  eco.sdk_dependent_repos_found = repos.length;
  eco.sdk_dependent_pages_fetched = pagesFetched;
  eco.sdk_dependent_stop_reason = stopReason;
  log(`  ${repos.length} unique direct-runtime dependent repos (${stopReason})`);

  const candidateNames = new Map<
    string,
    { method: "sdk-dependent" | "keyword-search"; source: string; dependentRepo?: string; matchedQuery?: string }
  >();

  for (const repo of repos) {
    if (writtenCount.n >= LIMIT) break;
    const name =
      ecosystem === "npm"
        ? await resolveNpmPackageName(repo)
        : await resolvePypiPackageName(repo);
    if (!name) {
      eco.name_resolution_failed += 1;
      vlog(`  ${repo.fullName}: could not resolve a self-declared package name`);
      continue;
    }
    candidateNames.set(name, {
      method: "sdk-dependent",
      source: "repos.ecosyste.ms usage/dependencies",
      dependentRepo: repo.fullName,
    });
  }

  if (ecosystem === "npm" && !NO_KEYWORD) {
    log(`  supplementary keyword search (npm registry search API)`);
    for (const q of NPM_KEYWORD_QUERIES) {
      const names = await npmKeywordSearch(q);
      summary.npm.keyword_candidates += names.length;
      for (const name of names) {
        if (!candidateNames.has(name)) {
          candidateNames.set(name, {
            method: "keyword-search",
            source: "registry.npmjs.org/-/v1/search",
            matchedQuery: q,
          });
        }
      }
    }
  }

  log(`  ${candidateNames.size} unique candidate package names to resolve on the registry`);

  for (const [name, provenance] of candidateNames) {
    if (writtenCount.n >= LIMIT) break;
    summary.unique_packages_seen += 1;
    const outPath = outputPath(ecosystem, name);
    const outBasename = `${ecosystem}__${slugifyPackageName(name)}.json`;
    if (existing.has(outBasename) && !FORCE) {
      summary.already_collected_skipped += 1;
      continue;
    }

    const resolved =
      ecosystem === "npm"
        ? await fetchNpmRegistryMeta(name)
        : await fetchPypiMeta(name);
    if (!resolved) {
      eco.not_published_on_registry += 1;
      vlog(`  ${name}: not resolvable on the ${ecosystem} registry, skipping`);
      continue;
    }

    // Guard against a repo whose self-declared manifest name happens to
    // collide with an unrelated real registry package (observed live: a repo
    // with a never-renamed `"name": "package"` in package.json resolved to
    // an unrelated npm package called "package" with zero MCP relevance).
    // Only enforced for the sdk-dependent method, which is the one making
    // the stronger "this depends on the SDK" claim.
    if (provenance.method === "sdk-dependent" && !resolved.dependsOnSdk) {
      eco.name_collision_false_positive += 1;
      vlog(
        `  ${name}: resolved on the registry but does not declare a dependency on ${seedPackage}, skipping (name collision)`,
      );
      continue;
    }

    const record: CollectedPackage = {
      ...resolved.meta,
      ecosystem,
      discovery: {
        method: provenance.method,
        source: provenance.source,
        ...(provenance.dependentRepo
          ? { sdk_dependency: seedPackage, dependent_repo: provenance.dependentRepo }
          : {}),
        ...(provenance.matchedQuery
          ? { matched_query: provenance.matchedQuery }
          : {}),
      },
      collected_at: new Date().toISOString(),
    };

    if (WRITE) {
      writeFileSync(outPath, JSON.stringify(record, null, 2) + "\n", "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
    } else if (VERBOSE) {
      log(`  would write ${outPath}`);
    }
    summary.new_files_written += 1;
    writtenCount.n += 1;
  }
}

async function main(): Promise<void> {
  if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });
  const existing = existingOutputs();

  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    ecosystems_run: [],
    sources_used: [
      "repos.ecosyste.ms usage/dependencies (primary, both ecosystems)",
      ...(NO_KEYWORD
        ? []
        : ["registry.npmjs.org/-/v1/search (supplementary, npm only)"]),
    ],
    npm: {
      sdk_dependent_repos_found: 0,
      sdk_dependent_pages_fetched: 0,
      sdk_dependent_stop_reason: "",
      name_resolution_failed: 0,
      not_published_on_registry: 0,
      name_collision_false_positive: 0,
      keyword_candidates: 0,
    },
    pypi: {
      sdk_dependent_repos_found: 0,
      sdk_dependent_pages_fetched: 0,
      sdk_dependent_stop_reason: "",
      name_resolution_failed: 0,
      not_published_on_registry: 0,
      name_collision_false_positive: 0,
    },
    unique_packages_seen: 0,
    already_collected_skipped: 0,
    new_files_written: 0,
    written_files: [],
  };

  const ecosystems: Array<"npm" | "pypi"> = ECOSYSTEM_FILTER
    ? [ECOSYSTEM_FILTER as "npm" | "pypi"]
    : ["npm", "pypi"];

  const writtenCount = { n: 0 };
  let anySourceReachable = false;

  for (const ecosystem of ecosystems) {
    summary.ecosystems_run.push(ecosystem);
    try {
      await collectEcosystem(ecosystem, summary, existing, writtenCount);
      anySourceReachable = true;
    } catch (e) {
      log(`fatal error collecting ${ecosystem}: ${e}`);
    }
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::wildscan-summary::${JSON.stringify({
      ecosystems_run: summary.ecosystems_run,
      unique_packages_seen: summary.unique_packages_seen,
      new_files_written: summary.new_files_written,
      already_collected_skipped: summary.already_collected_skipped,
      npm_sdk_dependent_repos_found: summary.npm.sdk_dependent_repos_found,
      pypi_sdk_dependent_repos_found: summary.pypi.sdk_dependent_repos_found,
    })}`,
  );

  if (!anySourceReachable) {
    log("fatal: no data source was reachable for any ecosystem");
    process.exit(1);
  }
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
