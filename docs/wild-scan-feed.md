# Wild-scan feed — from frozen snapshot to live discovery

The wild scan is ATR's unique discovery asset: agent-skill registries crawled,
flagged, and confirmed as malware. But until now it was a one-shot snapshot
(`data/public-blacklist.json`, scanned 2026-04-14). A snapshot is not a feed —
nothing surfaced what changed since. This wires the missing loop.

## The loop

```
crawl + scan  ->  diff vs published baseline  ->  cluster to campaign  ->  review PR  ->  publish
```

- `scripts/wild-scan-diff.ts` — the diff engine. Compares a fresh scan against
  the published baseline and emits new / gone / changed malicious skills.
- `.github/workflows/wild-scan-refresh.yml` — runs the re-scan + diff weekly
  (and on demand), opening a PR when anything changed.

## Why a PR, not auto-publish

Publishing a permanent malware label against a named third-party author is an
accusation, not a metric. New attributions go through a human-reviewed PR
(`needs-human-review`) before they reach the public blacklist. This is the same
discipline that the ATI instance-identifier layer will need: the numbering /
publishing function must be reviewable and, eventually, sit inside a neutral
legal entity — not auto-fire from a scanner.

## Campaign clustering (one signal per actor, never one id per skill)

A single threat actor shipping 354 near-identical variants is ONE campaign, not
354 findings. The diff clusters new and changed entries by `threat_actor` and
reports campaign-level counts. This is a hard requirement for the future ATI
namespace: an actor's variant flood must collapse to a campaign-level instance,
or the index becomes id spam.

## Usage

```
# Diff a fresh scan (or the daily cumulative) against the published baseline.
npx tsx scripts/wild-scan-diff.ts \
  --baseline data/public-blacklist.json \
  --current  <scan-output>.json \
  --out data/wild-scan [--confirmed-only] [--no-scope]
```

Inputs accept three shapes: a bare entry array, `{ entries: [...] }` (published
blacklist), or `{ results: [...] }` (scan-cumulative — only CRITICAL/HIGH rows
become entries). The baseline is auto-scoped to the sources the current scan
covered, so a partial re-scan does not report other registries as "removed";
pass `--no-scope` only for a full multi-registry re-scan.

Output: `data/wild-scan/diff-<date>.json` (full) and `diff-<date>.md` (feed
summary). A `::wild-scan-diff::` line carries machine-readable counts for CI.

## Hardening TODO (next, not in this change)

1. Anchor on an immutable content hash. Entries are keyed on `source::skill`
   (author/name), which is mutable — an actor can rename a skill and evade the
   diff. Record `skill_sha256` at scan time and key on it; the engine already
   carries an optional `sha256` field for this.
2. Normalize source names. The published baseline uses `OpenClaw` while the
   cumulative scan uses `ClawHub`; cross-source diffs need a canonical source
   map so the same skill on the same registry compares correctly.
3. Feed the ATI layer. Each confirmed new campaign is a candidate
   `ATI-YYYY-NNNNN` instance once the namespace + neutral governance exist (see
   the north-star blueprint). This feed is the discovery input to that layer.
