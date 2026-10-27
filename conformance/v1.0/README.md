# ATR Conformance Test Suite v1.1.0

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
    edge/             ← edge-case inputs (SUITE.md lists the outcomes each accepts)
      <case_id>/
        input.yaml
        expect.json
  runner/
    run-conformance.ts        ← reference test runner
    outcomes.ts               ← outcomes each category allows; suite and SPEC versions
    channels.ts               ← MCP event channels a payload is presented on
    generate-fixtures.ts      ← TP and TN fixtures from the rules' test_cases
    generate-edge-fixtures.ts ← the edge fixtures
    report-schema.json        ← schema for runner output
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

## Status

The reference engine passed the whole suite on 2026-10-27: **226 / 226** at
L2 (TP 103, TN 103, edge 20, no runner-internal errors), at main `0f8c6a0e9`
plus the change that introduced this section. CI runs the suite on every
change to `src/`, `rules/` or `conformance/`; the check is not a required
one, so rerun before citing. Reproduce:

```bash
npm run build
npx tsx conformance/v1.0/runner/run-conformance.ts \
  --engine ./dist --rules ./rules --level L2 \
  --out ./conformance-report.json
```

Until 2026-10-19 it did not, and no engine could. The fixes, which make up
suite v1.1.0 (see "Versioning"):

1. 41 TP and TN fixtures had no payload. The generator read only a test
   case's `input`, but 21 Rules write their payload under `tool_response`,
   `tool_description`, `tool_name`, `tool_args`, `tool_call`,
   `agent_output` or `content`. The generator now reads every key
   `src/testcase-event.ts` reads and fails when a selected test case has no
   payload, and the affected fixtures were regenerated. Until the CLI began
   refusing an empty scan, the 20 TN fixtures among them passed without
   testing anything.
2. Six Rules could not fire in the reference Engine as the runner drives
   it. ATR-2026-00083, -00084, -00095 and -00096 are `status: draft`, which
   the reference Engine does not evaluate, and ATR-2026-00075 declares
   `agent_source.type` `memory_access`, which it withholds from typed events
   (`WITHHELD_SOURCE_TYPES` in `src/engine.ts`). The generator now skips
   such Rules, and their fixtures were replaced by those of ATR-2026-00106,
   -00137, -00138, -00150 and -00161. ATR-2026-00070 declares
   `context_window`, which the Engine evaluated on no typed event until #701
   (2026-10-19) and now runs where it runs `llm_io` Rules; its TP fixture
   also carried only the benign question of its test case, not the
   `tool_response` that holds the injection. Its fixtures were regenerated.
3. ATR-2026-00451's hand-written TP put the injection in the request body,
   which no version of the Rule matched: until #251 (2026-07-05) the Rule
   looked for it in an admin URL path or an `*_id` parameter, and since then
   in the Bearer token, which is where CVE-2026-42208 puts it. The fixture
   now puts it in the Bearer token.
4. Four edge fixtures (`edge-051`, `-052`, `-060`, `-061`) carry payloads
   that the Corpus legitimately detects, yet expected `no_match`. They now
   use the `handled` outcome (SUITE.md), which tests only that the run
   finishes cleanly within budget.

The runner now also reports a fixture with no `input`, a tp or tn fixture
with no `rule_id`, and a fixture whose outcome its category does not allow
as a `harness_error`, instead of scoring it.

## Submitting a certification claim

After a passing run, file a `certification-claim` issue per
[TRADEMARK.md §5](../../TRADEMARK.md). The ATR Numbering Authority will
reproduce the run on a clean environment and, on success, add your engine
to `registry/` and authorize the ATR-Certified mark per the same policy.

## Versioning

Patch releases of the suite (`v1.1.1`, `v1.1.2`...) MAY add fixtures and
MUST NOT remove or alter existing ones: an engine that passes `v1.1.0` MUST
continue to pass every `v1.1.x`. Minor releases align with the SPEC.md minor
version and MAY require new conformance behavior.

`v1.1.0` (2026-10-27) is the current release and tracks SPEC.md 1.1.0. It
alters and removes `v1.0.0` fixtures and adds the `handled` edge outcome,
which a patch release may not do, so it is a minor release. The changes are
listed under "Status" and in SPEC.md Appendix D, and erratum
`e-2026-10-19-conformance-suite` records the defects in `v1.0.0`. No Engine
could pass `v1.0.0`: its TP fixtures without a payload could not match
anything. So no Engine that passed `v1.0.0` can fail `v1.1.0`.

The directory keeps the name `conformance/v1.0/` so that existing links,
CI paths and the report schema's `$id` stay valid. The suite version is the
one a report declares in `suite_version` (`runner/outcomes.ts`).

## License

The suite, including all fixtures, is published under the MIT License.
