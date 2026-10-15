# ATR Benchmark Measurements

Versioned, immutable measurements of ATR engine performance against external
red-team benchmarks. Every public-facing recall/precision/FP-rate claim must
reference a file under this directory.

## Layout

```
data/measurements/
├── <source>/
│   ├── <YYYY-MM-DD>_<source>-<source-version>_atr-<atr-version>.json
│   ├── ...
│   └── latest.json     <- pointer to most recent measurement
└── README.md           <- this file
```

One sub-directory per benchmark source. One JSON file per measurement run.
`latest.json` mirrors the most recent measurement for fast reads (used by
`scripts/sync-stats-from-measurements.ts` and the website's `lib/stats.ts`).

## Invariants

These rules MUST hold for every file under this directory:

1. **Append-only.** Measurement files are never edited after write. If a
   measurement is wrong, write a new measurement; do not modify the old
   file. The historical record is part of the contract — academic citations,
   grant due-diligence, and reproducibility audits depend on it.

2. **Self-describing filenames.** The filename encodes the measurement date,
   the source identifier, the source version, and the ATR version. Anyone
   reading the directory listing can answer "what was measured when" without
   opening the file.

3. **Every claim is anchored.** Public-facing recall numbers (README badges,
   `stats.json`, website, LinkedIn posts, papers, grant applications) MUST
   reference a specific measurement file. Stating "ATR recall is 97.1%" with
   no source/version/date triple is considered a bug.

4. **Schema-valid.** Every file conforms to the Zod schema in
   `scripts/measurement/schema.ts`. CI fails the build if any file under this
   directory does not parse cleanly.

5. **Reproducibility metadata captured.** Each measurement records the source
   version, ATR version, ATR git commit, rule count at measurement time, and
   measurement timestamp. Given these, anyone re-running the same eval against
   the same source version should converge to the same metrics (modulo
   non-determinism in the source corpus).

## Adding a new source

1. Create `data/measurements/<source>/` (lowercase, hyphen-separated).
2. Pick a stable identifier for `source_version` — prefer upstream git tag,
   npm version, or GitHub release tag. If the source is a dated corpus
   without a version, use `corpus-YYYY-MM-DD` of the fetch date.
3. Update the eval script to call `writeMeasurement()` from
   `scripts/measurement/write.ts` at the end of its run.
4. Run the eval once to produce the first measurement and `latest.json`.
5. Add the source to the README badges section via `sync-stats-from-measurements.ts`.

## Schema (summary)

The full schema is defined in `scripts/measurement/schema.ts`. Required
top-level fields:

| Field            | Type     | Notes                                                  |
|------------------|----------|--------------------------------------------------------|
| `schema_version` | string   | Currently `"1"`. Bumped if the schema breaks compat.   |
| `source`         | string   | Stable identifier (e.g. `"garak"`, `"pint"`).          |
| `source_version` | string   | Upstream version (e.g. `"v0.10.3"`).                   |
| `source_url`     | string   | Optional. Link to the exact upstream release / commit. |
| `atr_version`    | string   | From `package.json` at measurement time.               |
| `atr_commit`     | string   | Short git SHA at measurement time.                     |
| `rules_loaded`   | integer  | Number of rules in the engine at measurement time.     |
| `measured_at`    | string   | ISO 8601 UTC.                                          |
| `samples`        | integer  | Total sample count in the corpus.                      |
| `metrics`        | object   | `{recall, precision, f1, fp_rate, ...}`                |
| `confusion`      | object   | `{tp, fp, tn, fn}` (optional but strongly recommended) |
| `latency_ms`    | object   | `{p50, p95, p99, mean, max}` (optional)                |
| `breakdown`      | object   | Optional bespoke per-source structure (by category,    |
|                  |          | by family, by severity, by layer — source-defined).    |
| `notes`          | string   | Optional human-readable context.                       |

## The enforce lane: `breakdown.enforce_lane`

`metrics.recall` is a **hunt**-lane figure: the runners construct the engine
with no lane, and an engine with no lane loads every maturity. Since
2026-10-15 every runner `.github/workflows/measure-all.yml` calls also runs the
same samples through the same detection loop on an engine constructed with
`lane: 'enforce'` (only `maturity: stable` rules load; the lane to run with
blocking on) and records the result beside the headline:

| Field           | Notes                                                              |
|-----------------|--------------------------------------------------------------------|
| `lane`          | Always `"enforce"`.                                                |
| `detected`      | Attack samples the enforce-lane engine detected.                   |
| `attacks`       | Attack samples evaluated; equals `confusion.tp + confusion.fn`.    |
| `recall`        | `detected / attacks`.                                              |
| `rules_in_lane` | Rules the enforce lane loads: status not draft/deprecated, maturity stable. |
| `note`          | What the figure is, in the file itself.                            |

It is deliberately not a second headline: `metrics`, `latest.json` and
`data/stats.json` stay the hunt lane. README's Recall column cites both lanes
(`<hunt>% (hunt) / <enforce>% (enforce)`) and root `stats.json` cites the
enforce figure as `enforceLaneRecall`; `scripts/check-benchmark-citations.ts`
fails CI when either disagrees with the measurement. `src/measurement/schema.ts`
validates the record, which `scripts/measurement/verify.ts` runs over every
file. Measurements written before 2026-10-15 do not carry it.

## Public reference format

When citing a measurement externally, use this triple format:

> ATR `<atr_version>` against `<source>` `<source_version>` (`<sample_count>`
> samples, measured `<YYYY-MM-DD>`): recall `<X.X>%`, precision `<X.X>%`.

Example:

> ATR `3.0.0-alpha.0` against garak `v0.10.3` (666 samples, measured
> 2026-04-21): recall 97.1%, precision 100.0%.

Name the lane. The figure above is the hunt lane; a deployment with blocking
on runs the enforce lane, whose recall is `breakdown.enforce_lane.recall` in the
same file, and the two can differ by two orders of magnitude.

Always link to the underlying measurement file:
`data/measurements/garak/2026-04-21_garak-v0.10.3_atr-2.0.11.json`.

## What lives here vs. elsewhere

| Goes here                           | Goes elsewhere                                |
|-------------------------------------|-----------------------------------------------|
| One JSON per (source, version, run) | Raw corpora (gitignored, license-bound)       |
| `latest.json` pointer per source    | Per-rule unit test cases (in each rule YAML)  |
| Aggregate index in `stats.json`     | Engine regression reports (`data/eval-report.json` ← stays for CI, also gets mirrored here) |

## License

Measurement files are MIT-licensed. Anyone may cite, reproduce,
re-publish. The underlying corpora remain bound by their own licenses
(many of which prohibit redistribution — hence why they are not committed
to this repository).
