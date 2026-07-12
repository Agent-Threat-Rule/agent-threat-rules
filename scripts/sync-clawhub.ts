#!/usr/bin/env npx tsx
/**
 * sync-clawhub.ts
 *
 * Pulls the ClawHub (clawhub.ai) skill catalog and writes one raw-content
 * JSON file per skill to data/wild-scan/clawhub/<slug>.json. This is a data
 * COLLECTION script for the wild-scan pipeline, not a rule-proposal
 * generator: it does not touch rules/ or proposals/. A later scan pass reads
 * these files and runs the ATR engine (dist/engine.js) over the `content`
 * field to find malicious skills.
 *
 * Why ClawHub: one of the largest AI-agent skill marketplaces, and the site
 * of a confirmed real-world supply-chain attack ("ClawHavoc", reported by
 * Koi Security, Feb 2026 — see docs/research or the write-up at
 * https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting).
 * 341 malicious skills were found in an initial audit of 2,857 skills
 * (11.9%), growing to 824 by 2026-02-16 as the registry grew past 10,700.
 * ClawHub added VirusTotal-based scanning + removal on 2026-02-07. Several
 * ATR rules (e.g. rules/skill-compromise/ATR-2026-00121-skill-dangerous-script.yaml)
 * already encode ClawHavoc IOCs (C2 IP 91.92.242.30, base64-curl-bash chain,
 * password-protected ZIP evasion) as test_cases. NOTE: a figure of "12
 * compromised publisher accounts / 1,184 malicious skills" was passed in as
 * task background but is NOT corroborated by the primary Koi Security /
 * TheHackerNews / Trend Micro coverage found during research for this
 * script (which report 341 -> 824). Treat "1,184 / 12 accounts" as
 * unverified until a primary source is found.
 *
 * Data source (verified 2026-07-12):
 *   Site:            https://clawhub.ai  (canonical; clawhub.com 307-redirects here)
 *   List endpoint:   GET https://clawhub.ai/api/v1/skills?limit=<n>&cursor=<opaque>
 *                     Cursor-based pagination. Server caps the effective page
 *                     size around ~190-200 items regardless of a larger
 *                     `limit` value. Response: { items: [...], nextCursor }.
 *                     nextCursor is `null`/absent on the last page.
 *                     Each list item carries only shallow fields: slug,
 *                     displayName, summary, description (== the SKILL.md
 *                     frontmatter `description:` field, NOT the full body),
 *                     topics, tags.latest (version), stats {comments,
 *                     downloads, installs, stars, versions}, createdAt,
 *                     updatedAt (epoch-ms numbers).
 *   Detail endpoint: GET https://clawhub.ai/api/v1/skills/<slug>
 *                     Returns { skill: {...same shallow fields...},
 *                     latestVersion: {version, createdAt, changelog,
 *                     license}, metadata: {...} | null, owner: {handle,
 *                     userId, displayName, image}, moderation }. Critically,
 *                     skill.description here IS the full raw SKILL.md
 *                     source (YAML frontmatter + markdown body) — this is
 *                     the only way to get real scannable content; the list
 *                     endpoint's `description` is a short duplicate of
 *                     `summary`. owner.handle is the publisher account,
 *                     also only present in the detail response.
 *   robots.txt:      Disallows crawling /api/ for well-behaved search-engine
 *                     crawlers, but explicitly Allows /v1/feeds/skills and
 *                     /v1/feeds/plugins. Those feed endpoints were checked
 *                     and only list "verified official publisher" skills
 *                     (schemaVersion 1, sequence-numbered manifest) — a small
 *                     curated subset, NOT the full ~3,000+ skill catalog, so
 *                     they cannot serve this task's "pull the whole catalog"
 *                     requirement. /api/v1/skills is served with
 *                     access-control-allow-origin: * and a generous published
 *                     rate limit (ratelimit-limit: 3000 per short window,
 *                     via response headers) — i.e. it is the same endpoint
 *                     the site's own frontend calls, is CORS-open to any
 *                     origin, and is what data/clawhub-scan/clawhub-registry.json
 *                     in this repo (committed 2026-03-26, pre-dating this
 *                     script) was already built from. This script still
 *                     self-throttles well under the published limit (see
 *                     --delay-ms) out of caution, since the crawl directive
 *                     is ambiguous for a research fetch vs. a search-engine
 *                     crawl.
 *
 * Pipeline (two phases, because content only lives behind the detail call):
 *   1. List phase  — paginate the list endpoint to enumerate every slug +
 *      shallow stats. Cheap: ~17-18 requests for the whole catalog.
 *   2. Detail phase — for each slug not already collected (unless --force),
 *      GET the detail endpoint to pull owner + full raw content, merge with
 *      the list-phase stats, and write one JSON file.
 *
 * Idempotency: skip writing a slug whose output file already exists unless
 * --force. This makes the full run resumable after an interruption/rate
 * limit without re-fetching everything.
 *
 * Usage:
 *   npx tsx scripts/sync-clawhub.ts                      # dry-run (list only, no writes)
 *   npx tsx scripts/sync-clawhub.ts --write               # write files for real
 *   npx tsx scripts/sync-clawhub.ts --write --limit 20    # small sample run
 *   npx tsx scripts/sync-clawhub.ts --write --force       # re-fetch + overwrite existing
 *   npx tsx scripts/sync-clawhub.ts --write --delay-ms 300
 *   npx tsx scripts/sync-clawhub.ts --write --verbose
 *
 * Override the base URL (e.g. if the site moves) via env CLAWHUB_BASE_URL.
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network unreachable on first list page, schema mismatch)
 *   2 partial (some detail fetches failed after retries — see summary.errors)
 */

import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const OUT_DIR = resolve(REPO_ROOT, "data/wild-scan/clawhub");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const FORCE = flag("--force");
const VERBOSE = flag("--verbose");
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : Infinity;
const DELAY_MS = opt("--delay-ms") ? parseInt(opt("--delay-ms")!, 10) : 200;

const POLITE_UA =
  "ATR-WildScan-Research/1.0 (+https://github.com/Agent-Threat-Rule/agent-threat-rules; security research data collection; contact: adam@agentthreatrule.org)";

const DEFAULT_BASE_URL = "https://clawhub.ai";
const BASE_URL = (process.env.CLAWHUB_BASE_URL || DEFAULT_BASE_URL).replace(/\/$/, "");
const LIST_URL = `${BASE_URL}/api/v1/skills`;
const DETAIL_URL = (slug: string) => `${BASE_URL}/api/v1/skills/${encodeURIComponent(slug)}`;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Source schema (verified against live responses 2026-07-12).
// ---------------------------------------------------------------------------

interface ClawHubStats {
  comments?: number;
  downloads?: number;
  installs?: number;
  stars?: number;
  versions?: number;
}

interface ClawHubListItem {
  slug: string;
  displayName?: string;
  summary?: string;
  description?: string | null; // shallow (frontmatter description), NOT full body
  topics?: string[];
  tags?: { latest?: string };
  stats?: ClawHubStats;
  createdAt?: number; // epoch ms
  updatedAt?: number; // epoch ms
}

interface ClawHubListResponse {
  items: ClawHubListItem[];
  nextCursor?: string | null;
}

interface ClawHubOwner {
  handle?: string;
  userId?: string;
  displayName?: string;
  image?: string;
}

interface ClawHubLatestVersion {
  version?: string;
  createdAt?: number;
  changelog?: string;
  license?: string | null;
}

interface ClawHubDetailResponse {
  skill: ClawHubListItem; // description here IS the full raw SKILL.md content
  latestVersion?: ClawHubLatestVersion;
  metadata?: unknown;
  owner?: ClawHubOwner;
  moderation?: unknown;
}

// ---------------------------------------------------------------------------
// Networking: fetch with retry/backoff. ClawHub's Convex backend returns
// transient 503s under load; 429 carries a documented rate-limit window.
// ---------------------------------------------------------------------------

// A slug is not always a unique key: two different publishers may publish a
// skill under the same slug. The detail endpoint then returns 409 with a
// `matches` array (one entry per {ownerHandle, slug, ref, url}) instead of a
// skill. Discovered empirically (2026-07-12) via a real 409 on "session-cleanup"
// (two independent owners both used that slug). Disambiguate by re-issuing
// the request with ?owner=<ownerHandle>, which is confirmed to return the
// correct owner's skill.
interface AmbiguousMatch {
  ownerHandle: string;
  slug: string;
  ref: string;
  url: string;
}

class AmbiguousSlugError extends Error {
  matches: AmbiguousMatch[];
  constructor(matches: AmbiguousMatch[]) {
    super(`ambiguous slug: ${matches.length} owners`);
    this.matches = matches;
  }
}

async function fetchJsonWithRetry<T>(
  url: string,
  opts: { maxRetries?: number; label?: string; allow409?: boolean } = {},
): Promise<T> {
  const maxRetries = opts.maxRetries ?? 5;
  let lastErr: Error | null = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const resp = await fetch(url, {
        headers: { "User-Agent": POLITE_UA, Accept: "application/json" },
        signal: AbortSignal.timeout(20_000),
      });

      if (resp.status === 429 || resp.status === 503 || resp.status === 502) {
        const retryAfter = resp.headers.get("retry-after");
        const waitMs = retryAfter
          ? parseFloat(retryAfter) * 1000
          : Math.min(1000 * 2 ** attempt, 15_000);
        if (VERBOSE)
          console.error(
            `  [retry] ${resp.status} on ${opts.label ?? url} — waiting ${waitMs}ms (attempt ${attempt + 1}/${maxRetries + 1})`,
          );
        await sleep(waitMs);
        continue;
      }

      if (resp.status === 409 && opts.allow409) {
        const body = (await resp.json()) as { code?: string; matches?: AmbiguousMatch[] };
        if (body.code === "AMBIGUOUS_SKILL_SLUG" && Array.isArray(body.matches)) {
          throw new AmbiguousSlugError(body.matches);
        }
        throw new Error(`HTTP 409 (unrecognized shape) for ${opts.label ?? url}`);
      }

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} ${resp.statusText} for ${opts.label ?? url}`);
      }

      return (await resp.json()) as T;
    } catch (e) {
      if (e instanceof AmbiguousSlugError) throw e; // not retryable, propagate immediately
      lastErr = e as Error;
      if (attempt < maxRetries) {
        const waitMs = Math.min(1000 * 2 ** attempt, 15_000);
        if (VERBOSE)
          console.error(
            `  [retry] ${lastErr.message} — waiting ${waitMs}ms (attempt ${attempt + 1}/${maxRetries + 1})`,
          );
        await sleep(waitMs);
      }
    }
  }
  throw lastErr ?? new Error(`fetch failed after ${maxRetries} retries: ${url}`);
}

// Fetch one skill's detail, transparently resolving slug ambiguity. Returns
// one detail record per distinct owner (almost always exactly one).
async function fetchSkillDetails(slug: string): Promise<
  Array<{ detail: ClawHubDetailResponse; ownerHandle: string | null }>
> {
  try {
    const detail = await fetchJsonWithRetry<ClawHubDetailResponse>(DETAIL_URL(slug), {
      label: `detail ${slug}`,
      allow409: true,
    });
    return [{ detail, ownerHandle: detail.owner?.handle ?? null }];
  } catch (e) {
    if (!(e instanceof AmbiguousSlugError)) throw e;
    const out: Array<{ detail: ClawHubDetailResponse; ownerHandle: string | null }> = [];
    for (const m of e.matches) {
      await sleep(DELAY_MS);
      const url = new URL(DETAIL_URL(slug));
      url.searchParams.set("owner", m.ownerHandle);
      const detail = await fetchJsonWithRetry<ClawHubDetailResponse>(url.toString(), {
        label: `detail ${slug} (owner=${m.ownerHandle})`,
      });
      out.push({ detail, ownerHandle: m.ownerHandle });
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// List phase.
// ---------------------------------------------------------------------------

async function fetchAllSlugs(): Promise<Map<string, ClawHubListItem>> {
  const bySlug = new Map<string, ClawHubListItem>();
  let cursor: string | undefined;
  let page = 0;

  while (true) {
    page += 1;
    const url = new URL(LIST_URL);
    url.searchParams.set("limit", "200");
    if (cursor) url.searchParams.set("cursor", cursor);

    const data = await fetchJsonWithRetry<ClawHubListResponse>(url.toString(), {
      label: `list page ${page}`,
    });

    const items = Array.isArray(data.items) ? data.items : [];
    for (const it of items) {
      if (it && typeof it.slug === "string") bySlug.set(it.slug, it);
    }

    console.error(`  list page ${page}: +${items.length} items (running total ${bySlug.size})`);

    if (bySlug.size >= LIMIT) break;
    if (!data.nextCursor || items.length === 0) break;
    cursor = data.nextCursor;
    await sleep(DELAY_MS);
  }

  return bySlug;
}

// ---------------------------------------------------------------------------
// Frontmatter parsing (best-effort). ClawHub skill content follows the
// OpenClaw SKILL.md convention: a leading `---\n<yaml>\n---` block. We only
// need a handful of scalar fields for category/tags enrichment; a full YAML
// parser is unnecessary and would fail on the many non-standard/loose
// frontmatter blocks seen in the corpus (unquoted colons, multi-line
// folded scalars, etc.) — so this is deliberately a light regex scan, not a
// YAML.load(). Absence of a field is not an error.
// ---------------------------------------------------------------------------

interface ParsedFrontmatter {
  category: string | null;
  tags: string[];
  frontmatterDescription: string | null;
}

// Extracts a top-level YAML scalar field, including the literal (|) and
// folded (>) block-scalar forms (common for `description:` in these
// SKILL.md files). This is intentionally not a general YAML parser (the
// corpus has too much non-standard/loose frontmatter for that to be
// reliable) — just enough to read one named field's value.
function extractYamlScalarField(block: string, field: string): string | null {
  const lines = block.split("\n");
  for (let idx = 0; idx < lines.length; idx++) {
    const m = lines[idx].match(new RegExp(`^${field}:[ \\t]*(.*)$`));
    if (!m) continue;
    const raw = m[1].trim();
    const blockScalar = raw.match(/^([|>])[-+0-9]*$/);
    if (blockScalar) {
      const collected: string[] = [];
      for (let j = idx + 1; j < lines.length; j++) {
        const next = lines[j];
        if (next.trim() === "") {
          collected.push("");
          continue;
        }
        if (!/^\s/.test(next)) break; // dedent -> next top-level key, block ends
        collected.push(next.replace(/^\s{1,4}/, ""));
      }
      const joined =
        blockScalar[1] === ">"
          ? collected.join(" ").replace(/\s+/g, " ").trim()
          : collected.join("\n").trim();
      return joined || null;
    }
    const unquoted = raw.replace(/^["']|["']$/g, "").trim();
    return unquoted || null;
  }
  return null;
}

function parseFrontmatter(content: string): ParsedFrontmatter {
  const result: ParsedFrontmatter = {
    category: null,
    tags: [],
    frontmatterDescription: null,
  };
  if (!content.startsWith("---")) return result;
  const end = content.indexOf("\n---", 3);
  if (end === -1) return result;
  const block = content.slice(3, end);

  result.category = extractYamlScalarField(block, "category");
  result.frontmatterDescription = extractYamlScalarField(block, "description");

  const tagsInlineMatch = block.match(/^tags:\s*\[([^\]]*)\]\s*$/m);
  if (tagsInlineMatch) {
    result.tags = tagsInlineMatch[1]
      .split(",")
      .map((s) => s.trim().replace(/^["']|["']$/g, ""))
      .filter(Boolean);
  } else {
    const tagsBlockMatch = block.match(/^tags:\s*\n((?:\s*-\s*.+\n?)+)/m);
    if (tagsBlockMatch) {
      result.tags = tagsBlockMatch[1]
        .split("\n")
        .map((l) => l.replace(/^\s*-\s*/, "").trim().replace(/^["']|["']$/g, ""))
        .filter(Boolean);
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Output shape + filename sanitization.
// ---------------------------------------------------------------------------

function sanitizeSlug(slug: string): string {
  return slug
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 150) || "unnamed-skill";
}

function toIso(epochMs: number | undefined): string | null {
  if (typeof epochMs !== "number" || !Number.isFinite(epochMs)) return null;
  try {
    return new Date(epochMs).toISOString();
  } catch {
    return null;
  }
}

interface WildScanRecord {
  source: "clawhub";
  api_shape: "clawhub-api-v1-skills-detail-2026-07";
  slug: string;
  display_name: string | null;
  publisher: {
    handle: string | null;
    display_name: string | null;
    user_id: string | null;
  };
  summary: string | null;
  description: string | null; // short frontmatter description, best-effort parsed
  content: string; // full raw SKILL.md source — the scannable field
  category: string | null; // best-effort parsed from frontmatter
  tags: string[]; // best-effort parsed from frontmatter; falls back to topics
  topics: string[];
  latest_version: string | null;
  license: string | null;
  stats: {
    downloads: number | null;
    installs: number | null;
    stars: number | null;
    versions: number | null;
    comments: number | null;
  };
  created_at: string | null;
  updated_at: string | null;
  fetched_at: string;
  source_url: string;
}

function buildRecord(
  listItem: ClawHubListItem | undefined,
  detail: ClawHubDetailResponse,
  slug: string,
): WildScanRecord {
  const s = detail.skill ?? listItem ?? ({} as ClawHubListItem);
  const content = typeof s.description === "string" ? s.description : "";
  const fm = parseFrontmatter(content);
  const stats = s.stats ?? listItem?.stats ?? {};

  return {
    source: "clawhub",
    api_shape: "clawhub-api-v1-skills-detail-2026-07",
    slug,
    display_name: s.displayName ?? listItem?.displayName ?? null,
    publisher: {
      handle: detail.owner?.handle ?? null,
      display_name: detail.owner?.displayName ?? null,
      user_id: detail.owner?.userId ?? null,
    },
    summary: s.summary ?? listItem?.summary ?? null,
    description: fm.frontmatterDescription ?? s.summary ?? listItem?.summary ?? null,
    content,
    category: fm.category,
    tags: fm.tags.length > 0 ? fm.tags : (s.topics ?? listItem?.topics ?? []),
    topics: s.topics ?? listItem?.topics ?? [],
    latest_version: detail.latestVersion?.version ?? s.tags?.latest ?? null,
    license: detail.latestVersion?.license ?? null,
    stats: {
      downloads: typeof stats.downloads === "number" ? stats.downloads : null,
      installs: typeof stats.installs === "number" ? stats.installs : null,
      stars: typeof stats.stars === "number" ? stats.stars : null,
      versions: typeof stats.versions === "number" ? stats.versions : null,
      comments: typeof stats.comments === "number" ? stats.comments : null,
    },
    created_at: toIso(s.createdAt ?? listItem?.createdAt),
    updated_at: toIso(s.updatedAt ?? listItem?.updatedAt),
    fetched_at: new Date().toISOString(),
    source_url: detail.owner?.handle
      ? `${BASE_URL}/${encodeURIComponent(detail.owner.handle)}/skills/${encodeURIComponent(slug)}`
      : `${BASE_URL}/skills/${encodeURIComponent(slug)}`,
  };
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  base_url: string;
  list_items: number;
  attempted: number;
  written: number;
  skipped_existing: number;
  no_content: number;
  errors: Array<{ slug: string; error: string }>;
}

function newSummary(): RunSummary {
  return {
    run_date: new Date().toISOString(),
    base_url: BASE_URL,
    list_items: 0,
    attempted: 0,
    written: 0,
    skipped_existing: 0,
    no_content: 0,
    errors: [],
  };
}

function printFinalSummary(summary: RunSummary): void {
  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::clawhub-summary::${JSON.stringify({
      list_items: summary.list_items,
      attempted: summary.attempted,
      written: summary.written,
      skipped_existing: summary.skipped_existing,
      no_content: summary.no_content,
      error_count: summary.errors.length,
      base_url: BASE_URL,
    })}`,
  );
}

// One slug's worth of work: resolve (possibly ambiguous) detail records,
// write each one that isn't already on disk, and fold outcomes into
// `summary` in place (mutated by design — this is a running accumulator
// shared across the whole detail-phase loop, mirroring the convention used
// by the repo's other sync-*.ts scripts).
async function processSlug(
  slug: string,
  progress: string,
  bySlug: Map<string, ClawHubListItem>,
  existingFiles: Set<string>,
  summary: RunSummary,
): Promise<void> {
  const plainOutName = `${sanitizeSlug(slug)}.json`;
  summary.attempted += 1;

  const results = await fetchSkillDetails(slug);
  const multi = results.length > 1;

  for (const { detail, ownerHandle } of results) {
    const outName = multi
      ? `${sanitizeSlug(ownerHandle ?? "unknown-owner")}--${sanitizeSlug(slug)}.json`
      : plainOutName;

    if (!FORCE && existingFiles.has(outName)) {
      if (VERBOSE) console.error(`  [${progress}] skip (have) ${outName}`);
      continue;
    }

    const record = buildRecord(bySlug.get(slug), detail, slug);
    if (!record.content) {
      summary.no_content += 1;
      if (VERBOSE) console.error(`  [${progress}] no-content ${slug}`);
    }

    if (WRITE) {
      writeFileSync(join(OUT_DIR, outName), JSON.stringify(record, null, 2), "utf-8");
      summary.written += 1;
    }
    console.error(
      `  [${progress}] ${WRITE ? "wrote" : "would-write"} ${outName}` +
        (multi ? " [disambiguated]" : "") +
        (record.content ? ` (${record.content.length} chars)` : " (EMPTY)"),
    );
  }
}

async function runDetailPhase(
  bySlug: Map<string, ClawHubListItem>,
  summary: RunSummary,
): Promise<void> {
  console.error("--- detail phase ---");
  const slugs = Array.from(bySlug.keys()).slice(0, LIMIT === Infinity ? undefined : LIMIT);
  const existingFiles = new Set<string>(
    existsSync(OUT_DIR) ? readdirSync(OUT_DIR).filter((f) => f.endsWith(".json")) : [],
  );

  for (let i = 0; i < slugs.length; i++) {
    const slug = slugs[i];
    const progress = `${i + 1}/${slugs.length}`;
    const plainOutName = `${sanitizeSlug(slug)}.json`;

    // Fast pre-skip for the common (non-ambiguous) case: if we already wrote
    // the plain-slug file, this slug was previously resolved as unique and
    // there is nothing more to do. Ambiguous slugs never produce a plain
    // file, so this check is always safe.
    if (!FORCE && existingFiles.has(plainOutName)) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  [${progress}] skip (have) ${slug}`);
      continue;
    }

    try {
      await processSlug(slug, progress, bySlug, existingFiles, summary);
    } catch (e) {
      summary.errors.push({ slug, error: (e as Error).message });
      console.error(`  [${progress}] ERROR ${slug}: ${(e as Error).message}`);
    }

    await sleep(DELAY_MS);
  }
}

async function main(): Promise<void> {
  console.error("=== sync-clawhub.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run (list only, no files written)"}`);
  console.error(`base: ${BASE_URL}`);
  console.error(`delay: ${DELAY_MS}ms between requests`);
  if (LIMIT !== Infinity) console.error(`limit: ${LIMIT} skills`);

  const summary = newSummary();

  console.error("--- list phase ---");
  let bySlug: Map<string, ClawHubListItem>;
  try {
    bySlug = await fetchAllSlugs();
  } catch (e) {
    console.error(`fatal: list phase failed: ${(e as Error).message}`);
    printFinalSummary(summary);
    process.exit(1);
  }
  summary.list_items = bySlug.size;
  console.error(`list phase complete: ${bySlug.size} unique slugs`);

  if (bySlug.size === 0) {
    console.error("fatal: source returned 0 skills — schema may have changed");
    printFinalSummary(summary);
    process.exit(1);
  }

  if (WRITE && !existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

  await runDetailPhase(bySlug, summary);

  printFinalSummary(summary);

  if (summary.errors.length > 0) {
    process.exit(2); // partial (or total) failure in the detail phase
  }
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
