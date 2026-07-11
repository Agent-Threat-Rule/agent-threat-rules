# Official MCP Registry — Wild Scan Collector Output

Raw server metadata pulled from the **official Model Context Protocol
Registry** (`https://registry.modelcontextprotocol.io`), one file per unique
underlying package. This is raw CONTENT for the wild-scan pipeline (revival
of the one-time April 2026 snapshot, see
`docs/research/wild-scan-findings-2026-04-methodology.md`) — a later phase
runs the ATR detection engine over these files looking for malicious
skill/tool patterns. Nothing here is filtered, scored, or triaged yet.

## Source

- API: `https://registry.modelcontextprotocol.io/v0/servers` (public,
  unauthenticated, read-only REST; cursor pagination; server-enforced max
  `limit=100`; `search=` and `updated_since=` query params supported).
- Collector: `scripts/sync-mcp-official-registry.ts`.
- Pull date: 2026-07-12 (one-time full pull; run with `--since` on a
  future invocation for an incremental re-pull).

## Schema note (differs from the initial task assumption)

The registry's `ServerJSON` schema (see the registry's own `/openapi.yaml`)
has **no tool/capability manifest field**. A registry entry only describes
how to install/run a server — name, description, title, version,
`packages[]`, `remotes[]`, `repository`, `websiteUrl`, `icons` — it does
**not** enumerate the MCP tools a server exposes or their descriptions.
There is no tool-level content to capture beyond what's below. The
richest scan-relevant fields actually present are:

- `packages[].identifier` / `registryType` — the npm/PyPI/OCI/NuGet/MCPB
  package or direct-download URL that gets installed and run.
- `packages[].runtimeArguments` / `packageArguments` — CLI args passed to
  the server binary (a real injection surface).
- `packages[].environmentVariables` — declared env vars, including
  `isSecret` flags.
- `description` / `title` — free-text server description (the closest
  analogue to a "capability description" in this schema version).

All of the above, and every other field the API returns, is captured
**verbatim and unsummarized** in `all_registry_entries` (see below).

## Dedup methodology

A raw row from `GET /v0/servers` is one **(server name, version)** pair —
not one unique package. The registry keeps full version history and the
same underlying npm/PyPI package is frequently registered more than once
(re-publishes, forks, renamed reverse-DNS namespaces), which is why a raw
entry count vastly overstates the number of distinct things worth scanning.

Dedup key, in priority order:

1. **`packages[]` present** → one dedup key per **distinct
   `(registryType, identifier)` pair**, lowercased:
   `pkg:<registryType>:<identifier>`. This is the primary key — it is the
   artifact that actually gets downloaded and executed. A single server
   row can contribute more than one key (e.g. it publishes both an npm
   package and an OCI image); each becomes its own output file.
2. **No `packages[]`, but `repository.url` present** (remote-only HTTP MCP
   servers with a source repo) → `repo:<normalized repository url>`.
3. **No `packages[]`, no `repository`, but `remotes[]` present** (hosted
   SaaS MCP endpoint with no visible source) → `remote:<normalized first
   remote url>`.
4. **None of the above** (malformed/minimal entry) → `servername:<server
   name>`, last-resort fallback — tracked separately in the run summary so
   it stays visible rather than silently blending into the package count.

Filenames are `<sanitized-key-slug>--<sha256-hash8>.json`. The hash suffix
guarantees two different keys can never collide onto the same file even if
their sanitized slugs collapse (e.g. differing only in stripped special
characters).

## Per-file contents

Each file holds:

```
{
  "dedup_key":            the full key described above
  "package_identity":     { type, key, registryType?, identifier?, repositoryUrl?, remoteUrl? }
  "server_names":         every reverse-DNS server name that mapped to this key
  "versions_seen":        every distinct version string seen for this key
  "registry_row_count":   how many raw registry rows contributed
  "latest_registry_entry":the row marked isLatest=true (or the first row seen, if none marked)
  "all_registry_entries": EVERY raw row (server + _meta), verbatim, unsummarized
  "collected_at":         ISO timestamp of this collector run
  "source":               the API endpoint pulled from
}
```

## Counts (this pull, 2026-07-12)

- Raw entries seen: **49,827** (across 499 pages of 100)
- Unique dedup keys after collapse: **22,619** (2.2x collapse ratio overall)
  - `pkg:` (real installable package — npm/pypi/oci/nuget/mcpb): **15,150**
    - npm: 5,648 · mcpb: 3,578 · oci: 3,348 · pypi: 2,497 · nuget: 79
  - `repo:` (no packages[], but a repository.url — remote-only server with
    visible source): 4,843
  - `remote:` (no packages[], no repository — hosted endpoint only): 2,560
  - `servername:` (last-resort fallback — malformed/minimal entry): 66
- Parse failures: **0**
- Rate limited: **no** (no 429/503 encountered across the full pull)
- Files written: 22,619 data files + this README

### Note on the collapse ratio vs. the task's prior estimate

The task brief cited an earlier analysis finding "~1,691 truly unique
underlying npm/PyPI packages" behind tens of thousands of registry rows.
This pull's verified, code-level dedup (see `derivePackageIdentities()`,
unit-tested in `tests/sync-mcp-official-registry.test.ts`) found **15,150**
unique real packages (npm+pypi+oci+nuget+mcpb combined; 5,648 npm + 2,497
pypi alone already exceeds 1,691). Spot-checks confirm the dedup logic
itself is correct (e.g. `pkg:npm:remote-filesystem-mcp-server` correctly
collapses 3 raw rows for versions 0.1.2/0.1.3/0.1.5 into one file). The
most likely explanation is registry growth: this pull's raw row count
(49,827) is already above the task's assumed upper bound of ~30,000, and
every timestamp sampled during development fell within 2026-04 through
2026-07, consistent with the registry roughly tripling in size since
whatever earlier snapshot produced the 1,691 figure. A secondary factor:
`mcpb` platform-specific release binaries (e.g. one server publishing
separate macOS-arm64/macOS-x64/Windows/Linux `.mcpb` download URLs as
distinct `packages[]` entries) each get their own dedup key since each is
a genuinely distinct downloadable artifact — this inflates the `mcpb`
bucket specifically relative to a coarser "one row per server title"
count, but does not affect the npm/pypi buckets, which alone already
exceed the prior estimate.

Full machine-readable summary is the stdout JSON from the collector run
(see the commit message for the captured copy).

## Reproduce

```
npx tsx scripts/sync-mcp-official-registry.ts --write
```

Add `--force` to overwrite existing per-package files, `--since <RFC3339>`
for an incremental re-pull, `--search <term>` to scope to a name substring,
`--limit <n>` to cap raw entries processed (useful for a quick dry-run).
Omit `--write` for a dry-run that only prints the summary.

## License / responsible use

This is public registry metadata (server names, descriptions, package
identifiers, declared env var names) — no attack payloads or scan results
are included in this directory; it is the pre-scan raw corpus, not
findings. Downstream scan output belongs under a separate
`data/wild-scan/` results file once the engine has run over this corpus,
following the pattern of `data/full-scan-v2-2026-04-14.json`.
