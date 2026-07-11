#!/usr/bin/env npx tsx
/**
 * sync-mcp-official-registry.ts
 *
 * Pulls the FULL server listing from the official Model Context Protocol
 * Registry (https://registry.modelcontextprotocol.io) and writes one raw
 * metadata file per UNIQUE UNDERLYING PACKAGE to
 * data/wild-scan/official-registry/<sanitized-package-id>--<hash8>.json.
 *
 * This is a DATA-COLLECTION script for the wild-scan pipeline. It does not
 * write ATR rule proposals (unlike sync-ghsa.ts / sync-nvd-ai.ts / etc.) --
 * the output here is raw registry content that a later phase will run the
 * detection engine over, looking for malicious skill/tool patterns.
 *
 * REAL API (verified live 2026-07-12 against registry.modelcontextprotocol.io
 * -- the task brief's assumed shape was close but two things needed
 * confirmation, both now nailed down below):
 *
 *   - Path IS `/v0/servers` (not `/v0.1/servers`). Confirmed via
 *     GET /v0/health -> {"status":"ok",...} and the live OpenAPI doc at
 *     /openapi.yaml (operationId: list-servers-v0).
 *   - Pagination: `cursor` (opaque token = "<lastServerName>:<lastVersion>"
 *     in practice) + `limit` (default 30, SERVER-ENFORCED MAX 100 --
 *     requesting more than 100 returns HTTP 422 "expected number <= 100").
 *     Response shape: { servers: [ { server: {...}, _meta: {...} } ],
 *     metadata: { nextCursor?: string, count: number } }. No `nextCursor`
 *     (or an empty page) means the listing is exhausted.
 *   - `search=` substring-matches server name (confirmed).
 *   - `updated_since=` (RFC3339) supports incremental re-pulls; wired up
 *     here as --since for future scheduled runs (this run is a one-time
 *     full pull per the wild-scan revival task, so --since is unused by
 *     default).
 *   - No documented/observed rate-limit headers (no x-ratelimit-* on a
 *     plain 200). We still add a small delay between pages and retry with
 *     exponential backoff + Retry-After on 429/503, because the registry's
 *     own docs suggest hourly polling is enough for aggregators and this is
 *     a full one-shot crawl, not a tight loop.
 *
 * IMPORTANT SCHEMA CORRECTION vs. the task brief: the registry's
 * ServerJSON schema (see /openapi.yaml, schema `ServerJSON`) has NO
 * tool/capability manifest field. A registry entry only describes how to
 * install/run a server (name, description, title, version, packages[],
 * remotes[], repository, websiteUrl, icons) -- it does NOT enumerate the
 * MCP tools the server exposes or their descriptions. There is therefore
 * no "tool description" content to capture beyond what's below; the
 * richest scan-relevant fields actually present are `packages[].identifier`
 * (npm/pypi/oci/nuget/mcpb package name or direct-download URL),
 * `packages[].runtimeArguments` / `packageArguments` (CLI args passed to
 * the server binary -- a real injection surface) and
 * `packages[].environmentVariables` (declared env vars, including
 * isSecret flags). All of these are captured verbatim, unsummarized.
 *
 * DEDUP KEY (the core ask -- prior research found ~30K raw registry ROWS
 * collapse to on the order of ~1-2K unique underlying packages once you
 * dedup correctly):
 *   A raw "row" from GET /v0/servers is one (server name, version) pair --
 *   NOT a unique package. The same underlying npm/PyPI package is commonly
 *   registered multiple times: once per published version (the registry
 *   keeps full version history, `isLatest` marks the current one) AND
 *   sometimes under more than one reverse-DNS server `name` (re-publishes,
 *   forks, renamed namespaces). Dedup MUST key on the underlying package
 *   identity, not on server name or registry row id:
 *     1. packages[] present (npm/pypi/oci/nuget/mcpb/...): key per
 *        DISTINCT PACKAGE ENTRY = `pkg:<registryType>:<identifier>`
 *        (lowercased). This is the primary key -- it's what actually gets
 *        downloaded and run, and is the closest analogue to "the artifact
 *        that will get scanned for malicious patterns."
 *     2. No packages[], but repository.url present (remote-only HTTP MCP
 *        servers whose source is on a forge): key = `repo:<normalized
 *        repository url>`. This is the underlying "package" for a
 *        source-hosted remote server.
 *     3. No packages[], no repository, but remotes[] present (hosted SaaS
 *        MCP endpoint with no visible source): key = `remote:<first
 *        remote url, normalized>`.
 *     4. None of the above (malformed/minimal entry): key =
 *        `servername:<server.name>` -- last-resort fallback, logged as a
 *        parse-shortfall so it's visible in the summary, not silently
 *        merged into noise.
 *   A server row can carry >1 packages[] entries (multi-registry publish,
 *   e.g. both npm and a Docker/oci image for the same server) -- each
 *   distinct (registryType, identifier) pair becomes its OWN unique-package
 *   file, and the full raw server row is attached to every key it
 *   contributes to (so cross-references stay intact; no data is dropped).
 *
 * Idempotency / dedup-by-existing-file: on a re-run, an existing output
 * file for a dedup key is left untouched unless --force is passed (matches
 * the convention in sync-ghsa.ts / sync-nvd-ai.ts). Since this is a
 * one-time full pull the directory starts empty, so this mostly matters
 * for future incremental runs.
 *
 * Usage:
 *   npx tsx scripts/sync-mcp-official-registry.ts                  # dry-run, full pull
 *   npx tsx scripts/sync-mcp-official-registry.ts --write          # write files for real
 *   npx tsx scripts/sync-mcp-official-registry.ts --force          # overwrite existing files
 *   npx tsx scripts/sync-mcp-official-registry.ts --limit 500      # cap raw entries processed (testing)
 *   npx tsx scripts/sync-mcp-official-registry.ts --search filesystem
 *   npx tsx scripts/sync-mcp-official-registry.ts --since 2026-07-01T00:00:00Z
 *   npx tsx scripts/sync-mcp-official-registry.ts --verbose
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network / schema mismatch that isn't a rate-limit)
 *   2 rate-limited (recoverable; retried with backoff first, then gave up)
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const OUTPUT_DIR = resolve(
  REPO_ROOT,
  "data",
  "wild-scan",
  "official-registry",
);

const REGISTRY_BASE = "https://registry.modelcontextprotocol.io";
const SERVERS_PATH = "/v0/servers";
const API_MAX_LIMIT = 100; // server-enforced hard cap; see header note above

// --- CLI ---------------------------------------------------------------

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const FORCE = flag("--force");
const VERBOSE = flag("--verbose");
const SINCE = opt("--since"); // RFC3339, maps to updated_since
const SEARCH = opt("--search");
const INCLUDE_DELETED = flag("--include-deleted");
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : Infinity;
const DELAY_MS = opt("--delay-ms") ? parseInt(opt("--delay-ms")!, 10) : 200;
const MAX_PAGES = opt("--max-pages")
  ? parseInt(opt("--max-pages")!, 10)
  : 10_000; // safety cap against a pagination bug looping forever

// --- Registry response types (per /openapi.yaml, verified live) --------

interface RegistryKeyValueInput {
  name: string;
  description?: string;
  isRequired?: boolean;
  isSecret?: boolean;
  default?: string;
  value?: string;
}

interface RegistryArgument {
  type?: string;
  value?: string;
  name?: string;
  description?: string;
  isRequired?: boolean;
}

interface RegistryTransport {
  type: string;
  url?: string;
  headers?: RegistryKeyValueInput[] | null;
  variables?: Record<string, unknown>;
}

interface RegistryPackage {
  registryType: string;
  registryBaseUrl?: string;
  identifier: string;
  version?: string;
  runtimeHint?: string;
  transport: RegistryTransport;
  fileSha256?: string;
  runtimeArguments?: RegistryArgument[] | null;
  packageArguments?: RegistryArgument[] | null;
  environmentVariables?: RegistryKeyValueInput[] | null;
}

interface RegistryRepository {
  url?: string;
  source?: string;
  id?: string;
  subfolder?: string;
}

interface RegistryIcon {
  src: string;
  sizes?: string;
  theme?: string;
}

interface ServerJSON {
  $schema?: string;
  name: string;
  description: string;
  title?: string;
  version: string;
  packages?: RegistryPackage[] | null;
  remotes?: RegistryTransport[] | null;
  repository?: RegistryRepository;
  websiteUrl?: string;
  icons?: RegistryIcon[] | null;
  _meta?: Record<string, unknown>;
}

interface RegistryExtensions {
  status: "active" | "deprecated" | "deleted" | string;
  statusChangedAt: string;
  publishedAt: string;
  updatedAt: string;
  isLatest: boolean;
  statusMessage?: string;
}

interface ServerEntry {
  server: ServerJSON;
  _meta?: {
    "io.modelcontextprotocol.registry/official"?: RegistryExtensions;
    "io.modelcontextprotocol.registry/publisher-provided"?: unknown;
    [k: string]: unknown;
  };
}

interface ServerListResponse {
  servers: ServerEntry[] | null;
  metadata: {
    nextCursor?: string;
    count: number;
  };
}

// --- Dedup key derivation (exported for tests) --------------------------

export type PackageIdentityType = "package" | "repository" | "remote" | "server_name";

export interface PackageIdentity {
  type: PackageIdentityType;
  key: string; // full dedup key, e.g. "pkg:npm:@scope/name"
  registryType?: string;
  identifier?: string;
  repositoryUrl?: string;
  remoteUrl?: string;
}

function normalizeUrl(u: string): string {
  return u.trim().replace(/\/+$/, "").toLowerCase();
}

// A single server row can yield MULTIPLE package identities (e.g. it
// publishes both an npm package and an oci image). Falls back through
// repository -> remote -> server name when there is no packages[] array,
// so every row contributes at least one identity and nothing is silently
// dropped.
export function derivePackageIdentities(entry: ServerEntry): PackageIdentity[] {
  const s = entry.server;
  const pkgs = s.packages ?? [];
  if (pkgs.length > 0) {
    return pkgs
      .filter((p) => p && p.registryType && p.identifier)
      .map((p) => {
        const registryType = p.registryType.trim().toLowerCase();
        const identifier = p.identifier.trim().toLowerCase();
        return {
          type: "package" as const,
          key: `pkg:${registryType}:${identifier}`,
          registryType,
          identifier: p.identifier.trim(),
        };
      });
  }
  if (s.repository?.url) {
    const repositoryUrl = normalizeUrl(s.repository.url);
    return [{ type: "repository", key: `repo:${repositoryUrl}`, repositoryUrl: s.repository.url }];
  }
  const remotes = s.remotes ?? [];
  const firstRemoteUrl = remotes.find((r) => r.url)?.url;
  if (firstRemoteUrl) {
    const remoteUrl = normalizeUrl(firstRemoteUrl);
    return [{ type: "remote", key: `remote:${remoteUrl}`, remoteUrl: firstRemoteUrl }];
  }
  return [{ type: "server_name", key: `servername:${s.name.toLowerCase()}`, }];
}

// Filesystem-safe slug + short content hash suffix so sanitization
// collisions (e.g. two identifiers that differ only in stripped
// characters) can never overwrite each other silently.
export function sanitizeKeyToFilename(key: string): string {
  const slug = key
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 120);
  const hash = createHash("sha256").update(key).digest("hex").slice(0, 8);
  return `${slug || "unknown"}--${hash}.json`;
}

// --- HTTP with polite backoff --------------------------------------------

async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

interface FetchPageResult {
  data: ServerListResponse | null;
  rateLimited: boolean;
  fatal: boolean;
}

async function fetchPage(cursor: string | null): Promise<FetchPageResult> {
  const u = new URL(SERVERS_PATH, REGISTRY_BASE);
  u.searchParams.set("limit", String(API_MAX_LIMIT));
  if (cursor) u.searchParams.set("cursor", cursor);
  if (SEARCH) u.searchParams.set("search", SEARCH);
  if (SINCE) u.searchParams.set("updated_since", SINCE);
  if (INCLUDE_DELETED) u.searchParams.set("include_deleted", "true");

  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "atr-sync-mcp-official-registry (agent-threat-rules wild-scan collector)",
  };

  let attempt = 0;
  const maxRetries = 4;
  while (attempt <= maxRetries) {
    let resp: Response;
    try {
      resp = await fetch(u.toString(), { headers });
    } catch (e) {
      if (VERBOSE) console.error(`network error fetching ${u.toString()}: ${e}`);
      attempt++;
      if (attempt > maxRetries) return { data: null, rateLimited: false, fatal: true };
      await sleep(1000 * Math.pow(2, attempt));
      continue;
    }
    if (resp.status === 429 || resp.status === 503) {
      const retryAfterHeader = resp.headers.get("retry-after");
      const retryAfterMs = retryAfterHeader
        ? parseInt(retryAfterHeader, 10) * 1000
        : 1000 * Math.pow(2, attempt + 1); // 2s, 4s, 8s, 16s
      attempt++;
      if (VERBOSE)
        console.error(
          `${resp.status} on cursor=${cursor ?? "(start)"} -- backoff ${retryAfterMs}ms (attempt ${attempt}/${maxRetries})`,
        );
      if (attempt > maxRetries) return { data: null, rateLimited: true, fatal: false };
      await sleep(retryAfterMs);
      continue;
    }
    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      console.error(
        `non-OK response ${resp.status} ${resp.statusText} for cursor=${cursor ?? "(start)"}: ${body.slice(0, 300)}`,
      );
      return { data: null, rateLimited: false, fatal: true };
    }
    const data = (await resp.json()) as ServerListResponse;
    return { data, rateLimited: false, fatal: false };
  }
  return { data: null, rateLimited: true, fatal: false };
}

// --- Aggregation ----------------------------------------------------------

interface AggregatedPackage {
  identity: PackageIdentity;
  serverNames: Set<string>;
  versionsSeen: Set<string>;
  entries: ServerEntry[]; // full raw rows, unsummarized
  latestEntry: ServerEntry | null; // the row with isLatest === true, if any
}

interface RunSummary {
  run_date: string;
  source: string;
  endpoint: string;
  filters: { since: string | null; search: string | null; include_deleted: boolean };
  pages_fetched: number;
  raw_entries_seen: number;
  entries_with_packages: number;
  entries_with_repository_only: number;
  entries_with_remote_only: number;
  entries_with_no_identity_signal: number;
  unique_package_keys: number;
  package_identity_type_counts: Record<string, number>;
  registry_type_counts: Record<string, number>;
  files_written: number;
  files_skipped_existing: number;
  parse_failures: number;
  rate_limited: boolean;
  fatal_error: string | null;
}

async function main(): Promise<void> {
  if (WRITE && !existsSync(OUTPUT_DIR)) mkdirSync(OUTPUT_DIR, { recursive: true });

  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    source: REGISTRY_BASE,
    endpoint: SERVERS_PATH,
    filters: { since: SINCE ?? null, search: SEARCH ?? null, include_deleted: INCLUDE_DELETED },
    pages_fetched: 0,
    raw_entries_seen: 0,
    entries_with_packages: 0,
    entries_with_repository_only: 0,
    entries_with_remote_only: 0,
    entries_with_no_identity_signal: 0,
    unique_package_keys: 0,
    package_identity_type_counts: {},
    registry_type_counts: {},
    files_written: 0,
    files_skipped_existing: 0,
    parse_failures: 0,
    rate_limited: false,
    fatal_error: null,
  };

  const aggregated = new Map<string, AggregatedPackage>();
  let cursor: string | null = null;
  let processedRawEntries = 0;

  for (let page = 0; page < MAX_PAGES; page++) {
    const { data, rateLimited, fatal } = await fetchPage(cursor);
    summary.pages_fetched += 1;

    if (fatal) {
      summary.fatal_error = `fetch failed on page ${page + 1} (cursor=${cursor ?? "start"})`;
      console.error(summary.fatal_error);
      console.log(JSON.stringify(summary, null, 2));
      process.exit(1);
    }
    if (rateLimited) {
      summary.rate_limited = true;
      console.error(`gave up after retries on page ${page + 1} (cursor=${cursor ?? "start"}) -- rate limited`);
      break;
    }
    if (!data) break;

    const rows = data.servers ?? [];
    if (rows.length === 0) {
      if (VERBOSE) console.error(`page ${page + 1}: empty -- listing exhausted`);
      break;
    }

    for (const row of rows) {
      if (processedRawEntries >= LIMIT) break;
      processedRawEntries += 1;
      summary.raw_entries_seen += 1;

      let identities: PackageIdentity[];
      try {
        identities = derivePackageIdentities(row);
      } catch (e) {
        summary.parse_failures += 1;
        if (VERBOSE) console.error(`parse failure on row (name=${row?.server?.name}): ${e}`);
        continue;
      }

      const primaryType = identities[0]?.type ?? "server_name";
      if (primaryType === "package") summary.entries_with_packages += 1;
      else if (primaryType === "repository") summary.entries_with_repository_only += 1;
      else if (primaryType === "remote") summary.entries_with_remote_only += 1;
      else summary.entries_with_no_identity_signal += 1;

      const official = row._meta?.["io.modelcontextprotocol.registry/official"];
      const isLatest = official?.isLatest === true;

      for (const identity of identities) {
        summary.package_identity_type_counts[identity.type] =
          (summary.package_identity_type_counts[identity.type] ?? 0) + 1;
        if (identity.registryType) {
          summary.registry_type_counts[identity.registryType] =
            (summary.registry_type_counts[identity.registryType] ?? 0) + 1;
        }

        let agg = aggregated.get(identity.key);
        if (!agg) {
          agg = {
            identity,
            serverNames: new Set(),
            versionsSeen: new Set(),
            entries: [],
            latestEntry: null,
          };
          aggregated.set(identity.key, agg);
        }
        agg.serverNames.add(row.server.name);
        agg.versionsSeen.add(row.server.version);
        agg.entries.push(row);
        if (isLatest || agg.latestEntry === null) agg.latestEntry = row;
      }
    }

    if (processedRawEntries >= LIMIT) break;
    const nextCursor = data.metadata?.nextCursor;
    if (!nextCursor) {
      if (VERBOSE) console.error(`page ${page + 1}: no nextCursor -- listing exhausted`);
      break;
    }
    cursor = nextCursor;
    await sleep(DELAY_MS);
  }

  summary.unique_package_keys = aggregated.size;

  // Build an index of already-known dedup keys so re-runs are idempotent
  // (matches the dedup-by-existing-file convention in sync-ghsa.ts /
  // sync-nvd-ai.ts). Existing files carry their own dedup_key field.
  const existingKeys = new Set<string>();
  if (existsSync(OUTPUT_DIR)) {
    for (const f of readdirSync(OUTPUT_DIR)) {
      if (!f.endsWith(".json") || f === "README.md") continue;
      try {
        const raw = JSON.parse(readFileSync(join(OUTPUT_DIR, f), "utf-8"));
        if (raw && typeof raw.dedup_key === "string") existingKeys.add(raw.dedup_key);
      } catch {
        // ignore unreadable/foreign files in the directory
      }
    }
  }

  const writtenFiles: string[] = [];
  for (const [key, agg] of aggregated) {
    const filename = sanitizeKeyToFilename(key);
    const outPath = join(OUTPUT_DIR, filename);

    if (existingKeys.has(key) && !FORCE) {
      summary.files_skipped_existing += 1;
      continue;
    }

    const output = {
      dedup_key: key,
      package_identity: agg.identity,
      server_names: Array.from(agg.serverNames).sort(),
      versions_seen: Array.from(agg.versionsSeen).sort(),
      registry_row_count: agg.entries.length,
      latest_registry_entry: agg.latestEntry,
      // Every raw registry row that resolved to this dedup key, verbatim --
      // this is the actual content a later phase scans for malicious
      // patterns, so nothing here is summarized or truncated.
      all_registry_entries: agg.entries,
      collected_at: new Date().toISOString(),
      source: `${REGISTRY_BASE}${SERVERS_PATH}`,
    };

    if (WRITE) {
      writeFileSync(outPath, JSON.stringify(output, null, 2), "utf-8");
      writtenFiles.push(outPath.replace(REPO_ROOT + "/", ""));
      summary.files_written += 1;
    } else if (VERBOSE) {
      console.log(`would write ${outPath}`);
    }
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::mcp-official-registry-summary::${JSON.stringify({
      raw_entries_seen: summary.raw_entries_seen,
      unique_package_keys: summary.unique_package_keys,
      files_written: summary.files_written,
      files_skipped_existing: summary.files_skipped_existing,
      parse_failures: summary.parse_failures,
      rate_limited: summary.rate_limited,
    })}`,
  );

  if (summary.rate_limited) process.exit(2);
}

// Run if invoked as a script (not when imported as a module for tests)
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
