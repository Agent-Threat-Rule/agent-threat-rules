# ATR Conformance Test Suite v1.0

This directory is the normative test suite referenced by [SPEC.md §12](../../SPEC.md).
Implementations that claim "ATR-Compatible L1/L2/L3" MUST pass it.

## Layout

```
conformance/v1.0/
  README.md           ← this file
  SUITE.md            ← suite specification (what each fixture asserts)
  fixtures/
    tp/               ← true-positive fixtures (rule MUST match)
      <rule_id>/
        input.yaml    ← attack payload
        expect.json   ← expected Match per SPEC §7
    tn/               ← true-negative fixtures (rule MUST NOT match)
      <rule_id>/
        input.yaml
        expect.json
    edge/             ← ambiguous inputs (engine MUST report error gracefully)
      <case_id>/
        input.yaml
        expect.json
  runner/
    run-conformance.ts  ← reference test runner
    report-schema.json  ← schema for runner output
  registry/
    README.md         ← list of verified ATR-Compatible implementations
```

## What the suite verifies

| Level | Requirement (SPEC §11) |
|-------|------------------------|
| L1    | Engine loads the published Corpus without parse errors and emits Match output per SPEC §7 for at least one Rule. |
| L2    | 100 % pass on TP fixtures **and** zero matches on TN fixtures for the declared Spec version. |
| L3    | L2 conformance plus output emission in two or more interchange formats (JSON + one of SARIF, STIX 2.1, MISP, OpenCTI) plus published FP rate against the public benign corpus. |

## Running the suite

```bash
# Against the in-tree reference engine
npm install
npm run build
npx tsx conformance/v1.0/runner/run-conformance.ts \
  --engine ./dist \
  --rules  ./rules \
  --level  L2 \
  --out    ./conformance-report.json

# Against a third-party engine that exposes the same CLI surface
npx tsx conformance/v1.0/runner/run-conformance.ts \
  --engine /path/to/your-engine/cli.js \
  --rules  ./rules \
  --level  L2
```

`--engine` takes either a build-output directory, in which case the runner
resolves `<dir>/cli.js` inside it, or the engine executable itself. The
engine must accept the CLI surface documented in
[SUITE.md](SUITE.md#engine-cli-surface). The runner always passes
`--no-report`, so running the suite never uploads a fixture payload
anywhere.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | every fixture passed |
| 1 | at least one fixture failed |
| 2 | runner-internal error: a bad `--engine`, `--rules` or `--level` argument, an unreadable fixture, an engine that could not be spawned at all, or any unexpected fault inside the runner. The run is inconclusive and says nothing about the engine's conformance. |

A machine-readable report is written to `--out` (default
`conformance-report-<utc-timestamp>.json`) conforming to
`runner/report-schema.json`.

## Known gaps (as of 2026-09-22)

The suite does not yet pass end to end against the in-tree reference
engine. Reproduce:

```bash
npm run build
npx tsx conformance/v1.0/runner/run-conformance.ts \
  --engine ./dist --rules ./rules --level L2 \
  --out ./conformance-report.json
```

Result against `rules/` on 2026-09-22: **197 / 226** — TP 78/103, TN
103/103, edge 16/20, 0 runner-internal errors. Rerun before citing any of
these numbers; the corpus changes daily.

All 29 failures are fixture or corpus defects rather than runner defects.
They are listed rather than papered over:

1. **21 TP fixtures carry no payload.** Their `input.yaml` has
   `scan_target` and `rationale` but no `input:` key, so there is nothing
   for an engine to match: ATR-2026-00010, -00011, -00012, -00013, -00020,
   -00021, -00040, -00060, -00083, -00095, -00096, -00098, -00100, -00101,
   -00102, -00103, -00104, -00105, -00107, -00108, -00116. Re-list them
   with:

   ```bash
   for f in conformance/v1.0/fixtures/tp/*/input.yaml; do
     grep -qs '^input:' "$f" || echo "$f"
   done
   ```

   Cause: `runner/generate-fixtures.ts` reads `testCase.input`, but each of
   these 21 Rules writes its `true_positives` payload under a field-specific
   key instead — `tool_response`, `tool_description`, `tool_name`,
   `tool_args`, `tool_call`, `agent_output` or `content` — so the generator
   emitted a fixture with no payload. Repairing the generator does not
   repair the fixtures already on disk: it skips any directory that already
   has an `input.yaml`.

2. **ATR-2026-00084 is `status: draft`.** Draft Rules are excluded from
   evaluation by design, so no fixture can make this one fire
   (`grep -m1 '^status:' rules/prompt-injection/ATR-2026-00084-structured-data-injection.yaml`).

3. **ATR-2026-00070 and ATR-2026-00075 declare unreachable sources.**
   Their `agent_source.type` values (`context_window`, `memory_access`) are
   not produced by any Agent Event type, so the source-type filter excludes
   them on every channel. The TP fixture for -00070 additionally carries a
   benign payload ("What is the company refund policy?").

4. **ATR-2026-00451's TP fixture does not exercise the Rule it names.**
   Every condition requires a `bearer ...` prefix; the fixture supplies an
   `X-Admin-Key:` header instead.

5. **Four edge fixtures expect `no_match` on payloads the corpus
   legitimately detects**: `edge-051-zero-width-injection`,
   `edge-052-rtl-override`, `edge-060-null-byte-injection`,
   `edge-061-control-chars`. Their own `rationale` fields require only that
   the engine not crash ("Engines MAY normalize before matching",
   "regardless of how it treats them"), which contradicts the
   `graceful_error_or_no_match` in their `expect.json`.

Items 1, 4 and 5 are repaired by altering existing fixtures, which the
stability guarantee below defers to a v1.1 suite release. Items 2 and 3 are
corpus-side and are tracked against the Rules, not the suite.

## Submitting a certification claim

After a passing run, file a `certification-claim` issue per
[TRADEMARK.md §5](../../TRADEMARK.md). The ATR Numbering Authority will
reproduce the run on a clean environment and, on success, add your engine
to `registry/` and authorize the ATR-Certified mark per the same policy.

## Versioning

This suite is `v1.0`. It tracks `SPEC.md v1.0.x`. Patch releases of the
suite (`v1.0.1`, `v1.0.2`...) MAY add fixtures and MUST NOT remove or
alter existing ones — a passing engine at `v1.0.0` MUST continue to pass
at `v1.0.x`. Minor releases (`v1.1`) align with `SPEC.md v1.1.x` and MAY
require new conformance behavior.

## License

The suite, including all fixtures, is published under the MIT License.
