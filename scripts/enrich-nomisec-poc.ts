#!/usr/bin/env npx tsx
/**
 * enrich-nomisec-poc.ts
 *
 * NOT a proposal emitter. This script ANNOTATES existing CVE proposals with
 * links to public proof-of-concept (PoC) GitHub repositories, so that CVE
 * proposals which have a real exploit available jump the crystallization
 * queue (real PoC == an authorable, precision-safe rule).
 *
 * Source: nomi-sec/PoC-in-GitHub -- a community-maintained index of GitHub
 * repos that host PoCs, organized one JSON file per CVE:
 *
 *   https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/<YEAR>/<CVE-ID>.json
 *
 * Verified 2026-06-12:
 *   - default branch is `master` (NOT main; main 404s)
 *   - path shape is `<YEAR>/<CVE-ID>.json` (year parsed from the CVE id)
 *   - each file is a JSON array of repo records with at least
 *       { full_name, html_url, description, created_at, stargazers_count }
 *   - most CVEs have NO file (404) -- nomi-sec only indexes CVEs that have
 *     at least one public PoC repo.
 *
 * What it does, per CVE found in proposals/:
 *   - Fetch nomi-sec's <year>/<cve>.json.
 *   - On 200 with >=1 PoC repo: add/refresh a top-level `_poc_repos:` block
 *     on every proposal that references that CVE -- a list of
 *       { repo, url, stars, created_at } (capped ~5, sorted by stars desc).
 *   - If the proposal's `_triage.detection_ready` is currently false AND PoC
 *     repos now exist, set `_triage.poc_repos_available: true`. We do NOT
 *     flip detection_ready -- that is promote-detection-ready.ts's call. We
 *     only flag that a human/LLM could now fetch a real PoC and author a rule.
 *   - On 404: record the CVE as "checked, no PoC" so re-runs skip it cheaply.
 *
 * Purely additive: never touches detection.conditions, title, severity, etc.
 * Edits are done as targeted text injection of the `_poc_repos:` block and a
 * single `_triage.poc_repos_available:` line, so the rest of the file (and any
 * hand-authored YAML comments / PoC excerpts) is preserved byte-for-byte.
 *
 * Idempotency / cheap re-runs:
 *   - A small cache at data/nomisec-checked.json records every CVE we have
 *     already queried, with { has_poc, checked_at }. CVEs in the cache are
 *     skipped on subsequent runs (re-check only with --recheck).
 *   - A proposal that already carries an up-to-date `_poc_repos:` block is
 *     left untouched unless its repo list would change.
 *
 * Politeness: nomi-sec is one HTTP request per CVE. We rate-limit, cap each
 * run with --limit (default 100 CVEs/run), and use GITHUB_TOKEN from env if
 * present (raw.githubusercontent.com is unauthenticated, but the token raises
 * any incidental api.github.com fallback limits and is good hygiene).
 *
 * Secret: GITHUB_TOKEN is read from process.env ONLY. Never a CLI arg, never
 * echoed.
 *
 * Usage:
 *   npx tsx scripts/enrich-nomisec-poc.ts                  # dry-run
 *   npx tsx scripts/enrich-nomisec-poc.ts --write          # apply annotations
 *   npx tsx scripts/enrich-nomisec-poc.ts --limit 50       # cap CVEs/run
 *   npx tsx scripts/enrich-nomisec-poc.ts --recheck        # ignore cache
 *   npx tsx scripts/enrich-nomisec-poc.ts --verbose
 *
 * Summary marker (always last line):
 *   ::nomisec-enrich-summary::{cves_checked, with_poc, proposals_annotated}
 *
 * Exit codes:
 *   0 success
 *   1 fatal (unexpected error)
 *   2 no data path (e.g. no proposals/ or no CVEs found -- recoverable)
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const PROPOSALS_BASE = resolve(REPO_ROOT, "proposals");
const DATA_DIR = resolve(REPO_ROOT, "data");
const CACHE_PATH = resolve(DATA_DIR, "nomisec-checked.json");

// --- CLI ------------------------------------------------------------------
const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const VERBOSE = flag("--verbose");
const RECHECK = flag("--recheck");
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : 100;

// --- constants ------------------------------------------------------------
const NOMISEC_OWNER = "nomi-sec";
const NOMISEC_REPO = "PoC-in-GitHub";
const NOMISEC_BRANCH = "master"; // verified 2026-06-12; main 404s
const POLITE_UA =
  "ATR-Enrich/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";

// Secret: env-only. Never a CLI arg, never echoed.
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;

// raw.githubusercontent.com is generous, but we stay polite: one file per CVE
// means a lot of requests, so we throttle.
const RATE_LIMIT_MS = 250;
const MAX_REPOS = 5;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// --- types ----------------------------------------------------------------
interface NomisecRepo {
  full_name?: string;
  html_url?: string;
  description?: string | null;
  created_at?: string;
  stargazers_count?: number;
}

interface PocRepo {
  repo: string;
  url: string;
  stars: number;
  created_at: string;
}

interface CacheEntry {
  has_poc: boolean;
  checked_at: string;
}
type Cache = Record<string, CacheEntry>;

// --- file walking ---------------------------------------------------------
function walkYaml(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    let st;
    try {
      st = statSync(f);
    } catch {
      continue;
    }
    if (st.isDirectory()) out.push(...walkYaml(f));
    else if (st.isFile() && (e.endsWith(".yaml") || e.endsWith(".yml")))
      out.push(f);
  }
  return out;
}

const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/g;

/**
 * Collect references.cve from a proposal file. We parse the small
 * `references.cve` list with a tolerant regex rather than full YAML load --
 * we never mutate via YAML serialization (that would reformat the file and
 * lose hand-authored comments), so we only need the CVE ids here.
 */
function cvesInFile(raw: string): string[] {
  const refsIdx = raw.indexOf("\nreferences:");
  if (refsIdx === -1) {
    // Fall back to scanning the whole file; still keyed by CVE primary key.
    return uniq(raw.match(CVE_RE) ?? []);
  }
  // Limit to the references: block (until the next top-level key) so we only
  // pick up declared CVEs, not stray mentions in prose.
  const after = raw.slice(refsIdx + 1);
  const nextTop = after.search(/\n[a-z_][a-zA-Z0-9_]*:/);
  const block = nextTop === -1 ? after : after.slice(0, nextTop + 1);
  const cveBlock = block.match(/cve:\s*([\s\S]*?)(?:\n\s*[a-z_]+:|$)/);
  const hay = cveBlock ? cveBlock[1] : block;
  return uniq(hay.match(CVE_RE) ?? []);
}

function uniq(a: string[]): string[] {
  return Array.from(new Set(a));
}

function yearOfCve(cve: string): string | null {
  const m = cve.match(/^CVE-(\d{4})-/);
  return m ? m[1] : null;
}

// --- nomi-sec fetch -------------------------------------------------------
async function fetchNomisec(
  cve: string,
): Promise<{ status: number; repos: PocRepo[] }> {
  const year = yearOfCve(cve);
  if (!year) return { status: 0, repos: [] };
  const url = `https://raw.githubusercontent.com/${NOMISEC_OWNER}/${NOMISEC_REPO}/${NOMISEC_BRANCH}/${year}/${cve}.json`;
  const headers: Record<string, string> = { "User-Agent": POLITE_UA };
  if (GITHUB_TOKEN) headers.Authorization = `Bearer ${GITHUB_TOKEN}`;
  let res: Response;
  try {
    res = await fetch(url, { headers });
  } catch (e) {
    if (VERBOSE) console.error(`  fetch error ${cve}: ${(e as Error).message}`);
    return { status: -1, repos: [] };
  }
  if (res.status === 404) return { status: 404, repos: [] };
  if (!res.ok) {
    if (VERBOSE) console.error(`  unexpected ${res.status} for ${cve}`);
    return { status: res.status, repos: [] };
  }
  let data: unknown;
  try {
    data = await res.json();
  } catch {
    return { status: res.status, repos: [] };
  }
  if (!Array.isArray(data)) return { status: res.status, repos: [] };
  const repos: PocRepo[] = (data as NomisecRepo[])
    .filter((r) => r && typeof r.full_name === "string" && r.full_name)
    .map((r) => ({
      repo: r.full_name as string,
      url: (r.html_url as string) || `https://github.com/${r.full_name}`,
      stars: typeof r.stargazers_count === "number" ? r.stargazers_count : 0,
      created_at: typeof r.created_at === "string" ? r.created_at : "",
    }))
    .sort((a, b) => b.stars - a.stars)
    .slice(0, MAX_REPOS);
  return { status: res.status, repos };
}

// --- proposal annotation (text-surgical, additive only) -------------------

function renderPocBlock(repos: PocRepo[]): string {
  const lines: string[] = [];
  lines.push("");
  lines.push("# === nomi-sec PoC index (enrich-nomisec-poc.ts) ===");
  lines.push("# Public proof-of-concept repos for this CVE. Real PoC present");
  lines.push("# => this proposal jumps the crystallization queue: a human/LLM");
  lines.push("# can fetch one of these repos and author a precision-safe rule.");
  lines.push(`_poc_repos:`);
  for (const r of repos) {
    lines.push(`  - repo: "${r.repo.replace(/"/g, '\\"')}"`);
    lines.push(`    url: "${r.url.replace(/"/g, '\\"')}"`);
    lines.push(`    stars: ${r.stars}`);
    lines.push(`    created_at: "${r.created_at}"`);
  }
  return lines.join("\n") + "\n";
}

/**
 * Strip any previously-injected `_poc_repos:` block (and its leading comment
 * banner) so re-runs are idempotent and refresh in place.
 */
function stripExistingPocBlock(raw: string): string {
  // Consume any run of blank lines that precede the banner too, so re-runs do
  // not accumulate extra blank lines before the (re-)appended block.
  const bannerRe =
    /\n+# === nomi-sec PoC index \(enrich-nomisec-poc\.ts\) ===\n(?:#[^\n]*\n)*_poc_repos:\n(?:(?:  [^\n]*\n)+)?/;
  let out = raw.replace(bannerRe, "\n");
  // Also handle a bare `_poc_repos:` block written without the banner.
  const bareRe = /\n+_poc_repos:\n(?:(?:  [^\n]*\n)+)?/;
  out = out.replace(bareRe, "\n");
  return out;
}

/**
 * Ensure `_triage.poc_repos_available: true` is present when detection_ready
 * is currently false. We only ADD the line; we never touch detection_ready.
 * Returns the (possibly) modified text and whether a change was made.
 */
function ensureTriageFlag(raw: string): { text: string; added: boolean } {
  const triageIdx = raw.indexOf("\n_triage:");
  if (triageIdx === -1) return { text: raw, added: false };
  // Extract the _triage block (until next top-level key or EOF).
  const after = raw.slice(triageIdx + 1);
  const rest = after.slice("_triage:".length);
  const nextTop = rest.search(/\n[a-z_][a-zA-Z0-9_]*:/);
  const blockEndInRest = nextTop === -1 ? rest.length : nextTop;
  const block = "_triage:" + rest.slice(0, blockEndInRest);

  if (/detection_ready:\s*true/.test(block)) {
    // Already detection-ready -- nothing to flag.
    return { text: raw, added: false };
  }
  if (/poc_repos_available:\s*true/.test(block)) {
    // Flag already present.
    return { text: raw, added: false };
  }
  // Insert the flag as a new line right after the `_triage:` header line.
  const insertAt = triageIdx + 1 + "_triage:".length;
  const newText =
    raw.slice(0, insertAt) +
    "\n  poc_repos_available: true" +
    raw.slice(insertAt);
  return { text: newText, added: true };
}

interface AnnotateResult {
  changed: boolean;
  text: string;
  triageFlagged: boolean;
}

function annotateProposal(raw: string, repos: PocRepo[]): AnnotateResult {
  const cleaned = stripExistingPocBlock(raw);
  // Normalize to exactly one trailing newline so the block's leading blank
  // line (renderPocBlock starts with "") yields a single separating blank
  // line, and re-runs are byte-stable.
  const base = cleaned.replace(/\n+$/, "\n");
  let withBlock = base + renderPocBlock(repos);

  const { text: withTriage, added } = ensureTriageFlag(withBlock);
  withBlock = withTriage;

  const changed = withBlock !== raw;
  return { changed, text: withBlock, triageFlagged: added };
}

// --- cache ----------------------------------------------------------------
function loadCache(): Cache {
  if (!existsSync(CACHE_PATH)) return {};
  try {
    const parsed = JSON.parse(readFileSync(CACHE_PATH, "utf-8"));
    return parsed && typeof parsed === "object" ? (parsed as Cache) : {};
  } catch {
    return {};
  }
}

function saveCache(cache: Cache): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
  const sorted: Cache = {};
  for (const k of Object.keys(cache).sort()) sorted[k] = cache[k];
  writeFileSync(CACHE_PATH, JSON.stringify(sorted, null, 2) + "\n", "utf-8");
}

// --- main -----------------------------------------------------------------
interface RunSummary {
  cves_checked: number;
  with_poc: number;
  proposals_annotated: number;
  triage_flagged: number;
  cached_skipped: number;
  not_found_404: number;
  errors: number;
  cve_examples_with_poc: string[];
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    cves_checked: 0,
    with_poc: 0,
    proposals_annotated: 0,
    triage_flagged: 0,
    cached_skipped: 0,
    not_found_404: 0,
    errors: 0,
    cve_examples_with_poc: [],
  };

  console.error("=== enrich-nomisec-poc.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);
  console.error(`source: ${NOMISEC_OWNER}/${NOMISEC_REPO}@${NOMISEC_BRANCH}`);
  console.error(`auth: ${GITHUB_TOKEN ? "GITHUB_TOKEN present" : "anonymous"}`);
  console.error(`limit: ${LIMIT} CVEs/run`);

  if (!existsSync(PROPOSALS_BASE)) {
    console.error(`fatal-recoverable: no proposals/ dir at ${PROPOSALS_BASE}`);
    emitSummary(summary);
    process.exit(2);
  }

  // 1) Map every CVE -> the proposal files that reference it.
  const cveToFiles = new Map<string, string[]>();
  for (const f of walkYaml(PROPOSALS_BASE)) {
    let raw: string;
    try {
      raw = readFileSync(f, "utf-8");
    } catch {
      continue;
    }
    for (const cve of cvesInFile(raw)) {
      const arr = cveToFiles.get(cve) ?? [];
      arr.push(f);
      cveToFiles.set(cve, arr);
    }
  }

  const allCves = Array.from(cveToFiles.keys()).sort();
  console.error(`found ${allCves.length} distinct CVEs across proposals`);
  if (allCves.length === 0) {
    console.error("fatal-recoverable: no CVEs in proposals/");
    emitSummary(summary);
    process.exit(2);
  }

  // 2) Walk CVEs, skipping cached ones, up to LIMIT new queries.
  const cache = loadCache();
  let queried = 0;

  for (const cve of allCves) {
    if (queried >= LIMIT) break;

    if (!RECHECK && cache[cve]) {
      summary.cached_skipped += 1;
      // If the cache says it had a PoC, the proposal was (or will be)
      // annotated; we do not re-fetch. Re-annotation needs --recheck.
      continue;
    }

    const { status, repos } = await fetchNomisec(cve);
    queried += 1;
    summary.cves_checked += 1;

    if (status === -1) {
      summary.errors += 1;
      // Do not cache transient errors.
      await sleep(RATE_LIMIT_MS);
      continue;
    }

    const hasPoc = status === 200 && repos.length > 0;
    cache[cve] = { has_poc: hasPoc, checked_at: new Date().toISOString() };

    if (status === 404 || !hasPoc) {
      summary.not_found_404 += status === 404 ? 1 : 0;
      if (VERBOSE && status !== 404)
        console.error(`  ${cve}: ${status} no usable PoC repos`);
      await sleep(RATE_LIMIT_MS);
      continue;
    }

    // Has PoC repos.
    summary.with_poc += 1;
    if (summary.cve_examples_with_poc.length < 12)
      summary.cve_examples_with_poc.push(
        `${cve} (${repos.length} repos, top ${repos[0].stars}* ${repos[0].repo})`,
      );
    console.error(
      `  PoC ${cve}: ${repos.length} repo(s), top=${repos[0].repo} (${repos[0].stars}*)`,
    );

    // Annotate every proposal that references this CVE.
    for (const f of cveToFiles.get(cve)!) {
      let raw: string;
      try {
        raw = readFileSync(f, "utf-8");
      } catch {
        continue;
      }
      const { changed, text, triageFlagged } = annotateProposal(raw, repos);
      if (!changed) {
        if (VERBOSE)
          console.error(`    = ${rel(f)} already up to date`);
        continue;
      }
      summary.proposals_annotated += 1;
      if (triageFlagged) summary.triage_flagged += 1;
      if (WRITE) {
        writeFileSync(f, text, "utf-8");
        console.error(
          `    + annotated ${rel(f)}${triageFlagged ? " (+triage flag)" : ""}`,
        );
      } else {
        console.error(
          `    ~ would annotate ${rel(f)}${triageFlagged ? " (+triage flag)" : ""}`,
        );
      }
    }

    await sleep(RATE_LIMIT_MS);
  }

  // 3) Persist cache (only when writing -- a dry-run must not poison the
  //    cache, or subsequent --write runs would skip everything).
  if (WRITE) saveCache(cache);

  emitSummary(summary);
  process.exit(0);
}

function rel(f: string): string {
  return f.startsWith(REPO_ROOT + "/") ? f.slice(REPO_ROOT.length + 1) : f;
}

function emitSummary(s: RunSummary): void {
  console.error("--- summary ---");
  console.error(JSON.stringify(s, null, 2));
  console.log(
    `::nomisec-enrich-summary::${JSON.stringify({
      cves_checked: s.cves_checked,
      with_poc: s.with_poc,
      proposals_annotated: s.proposals_annotated,
    })}`,
  );
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
