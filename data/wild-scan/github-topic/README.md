# Wild-scan source: GitHub repository-topic corpus

Companion source for the wild-scan pipeline (see
`docs/research/wild-scan-findings-2026-04-methodology.md` for the prior
OpenClaw / ClawHub / Skills.sh / Hermes / MCP-Registry pass, which did not
cover public GitHub repos). Collected with `scripts/sync-github-mcp-topic.ts`.

## Source

`GET https://api.github.com/search/repositories?q=topic:<X>` for four
topics, queried in a single script run so cross-topic overlap is deduped by
`full_name` and every matching topic is recorded per repo
(`matched_query_topics`):

- `mcp-server`
- `model-context-protocol`
- `mcp-servers`
- `mcp-tools`

## Pull date

PULL_DATE_PLACEHOLDER (America/UTC timestamps in each record's `fetched_at`)

## Coverage decision (read this before treating the corpus as complete)

`mcp-server` (~20.4K raw hits) and `model-context-protocol` (~16.8K raw
hits) both exceed GitHub search's hard 1000-result cap per query. This pull
used **top-1000-by-stars** for those two topics rather than the script's
`--full-coverage` recursive star/date-partitioning mode (implemented and
unit-tested in `scripts/sync-github-mcp-topic.ts`, but not invoked live
against the full ~37K combined raw pool in this pass — see the script's
header comment for why, and `tests/sync-github-mcp-topic.test.ts` for the
partition-logic tests). `mcp-servers` (816) and `mcp-tools` (836 after the
recency filter) are both already under 1000, so those two topics ARE fully
covered.

Net effect: this is a star-ranked partial pull of the two largest topics,
not an exhaustive one. Noise (forks, tutorials, zero-star toy repos)
concentrates at the low-star long tail, so star-sorted top-1000 is a
reasonable high-signal sample of those two topics even though it is not
exhaustive — but a genuinely complete GitHub-topic wild-scan corpus would
need a `--full-coverage` run, which is a multi-hour crawl at this corpus
size and rate limit and was out of scope for this first pass.

## Filter criteria (applied in this order)

1. **Forks** — GitHub search excludes forks by default; confirmed
   (`topic:mcp-server` and `topic:mcp-server fork:false` return the
   identical total_count on 2026-07-12). No "meaningfully diverged fork"
   carve-out is implemented — see the script header for why.
2. **Staleness** — repos with no push in the last 12 months are dropped,
   enforced at the GitHub search QUERY level via `pushed:>=<cutoff>` (not
   just post-filtered), so it also shrinks the raw pool before the
   top-1000 star sort.
3. **Template / tutorial / demo junk** — a repo is dropped if its name OR
   description contains, as a bounded token (not a bare substring), any of:
   `tutorial(s)`, `example(s)`, `boilerplate`, `workshop(s)`, `demo(s)`,
   `starter`, `sample(s)`, `learning`, `course(s)`, `training`, `scaffold`,
   `skeleton`, `cookiecutter`, `awesome` (link-list repos, not servers),
   `hello-world`, `playground`, `sandbox`, `walkthrough`, `bootcamp`,
   `exercise(s)`, `practice`, `toy`. This is a blunt heuristic — a real
   project could in principle use one of these words in good faith — but
   it is the standard signal for "not a deployable server" in this
   ecosystem. See `TEMPLATE_JUNK_KEYWORDS` in the script for the exact,
   exhaustive list.

## Counts

RAW_AND_FILTER_COUNTS_PLACEHOLDER

## Record schema

One JSON file per surviving repo: `<owner>__<repo>.json` containing
`full_name`, `html_url`, `description`, `topics`, `matched_query_topics`,
`stars`, `forks`, `open_issues`, `language`, `license`, `default_branch`,
`created_at`, `last_pushed_at`, `fetched_at`, and the content the scan phase
needs to actually run detection rules against:

- `readme` — `{ path, content }` for the first README-shaped file found at
  repo root (any of `.md`/`.mdx`/`.rst`/`.txt`/no extension), or `null`.
- `descriptor_file` — `{ path, content }` for a root-level MCP descriptor
  (`server.json`, `mcp.json`, `mcp-server.json`, `.mcp.json`,
  `smithery.yaml`/`.yml`), or `null` if none present.
- `entrypoint_file` — `{ path, size, content }` for a best-guess entrypoint
  under 60,000 bytes: a common root-level JS/TS/Python/Go entrypoint name,
  or (for JS/TS projects) the path declared by a root `package.json`'s
  `main`/`module`/`bin` field. `null` if no small root-level candidate was
  found — this is a known limitation for monorepos / workspace roots where
  the real entrypoint lives several directories deep; the README content is
  still collected for those repos regardless.
- `content_fetch_notes` — human-readable notes on what content fetch did or
  did not find (e.g. "no small root-level entrypoint candidate found").

## Reproduce / extend

```
export GITHUB_TOKEN="$(gh auth token)"   # script's own fetch() needs a real
                                          # token; gh api's keyring auth is
                                          # not visible to plain fetch()
npx tsx scripts/sync-github-mcp-topic.ts --write                 # resume/extend this pull
npx tsx scripts/sync-github-mcp-topic.ts --write --full-coverage # full coverage (slow)
npx tsx scripts/sync-github-mcp-topic.ts --write --limit 20      # small sample
```

The collector is idempotent/resumable: an existing `<owner>__<repo>.json`
is left untouched (not re-fetched) unless `--force` is passed.

## License / provenance

MIT (matches repo license). Data is public GitHub repository metadata +
README/descriptor/entrypoint file content, all already public in each
repo. No attack payloads are embedded — this is raw source material for a
later scan pass, not a curated malware list.
