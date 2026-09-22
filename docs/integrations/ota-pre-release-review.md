# Ota pre-release PINT execution review

## Status

Fork-only review package. This is not an upstream pull request and does not change Agent Threat
Rules' required CI, rules, scripts, benchmark data, or published measurements. It adds only the
review contract, the review workflow/verifier, this report, and ignored Ota-owned local state.

- upstream base: `Agent-Threat-Rule/agent-threat-rules` `main` at
  `3c20d74e75c3dbc856ab04d5a47ad41d6d2d20b3`
- review branch: `bobaikato/agent-threat-rules` `ota/pre-release-review`
- Ota review source: exact unreleased Core revision
  `b9c5d0b65eaca9d15d975e5913ba16135337e6b7`
- release gate: replace that Git revision with released `v1.6.28`, rerun this unchanged workflow,
  then decide whether to open the maintainer-invited draft PR

## Review scope

The contract declares one native Node 20 lane:

```text
npm ci -> npm run eval:pint
```

It deliberately treats `npm run eval:pint` as non-agent-safe because it replaces tracked outputs:

- `data/pint-benchmark/pint-eval-report.json`
- `data/measurements/pint/latest.json`
- one dated `data/measurements/pint/*.json` file

The workflow runs on Ubuntu, is separate from required checks, and has only `contents: read`.
Non-blocking means it is not added to branch protection; failed evidence still fails the workflow.
It does not use `continue-on-error`.

## Evidence matrix

| Review question | Fork job | Required evidence |
| --- | --- | --- |
| Does the contract match its review workflow? | `Contract-to-CI drift` | Ota validates the contract and rejects drift from the direct `ota run verify:pint --native --stream .` aggregate invocation. |
| Did the selected engine path really run now? | `Fresh PINT-format execution evidence` | A clean checkout rejects the committed report as stale, then runs the contract-selected lane through Ota and requires its recorded zero exit. |
| Does the result belong to this checkout? | `Fresh PINT-format execution evidence` | The retained manifest binds exact HEAD, rules tree, lockfile, corpus, runner source, Ota revision, Node/npm versions, the bounded execution window, and both successful command exits. |
| Did the run produce the expected ATR-shaped result? | `Fresh PINT-format execution evidence` | The verifier requires a fresh timestamp, 850 samples, `ATREngine`, a positive rule count, a 850-row confusion total, and a passing ATR regression result. |
| Did execution stay within its reviewable Git mutation boundary? | `Fresh PINT-format execution evidence` | Only the two tracked report pointers plus one new dated PINT measurement may change among non-ignored Git paths. Outputs are uploaded as artifacts, then restored or removed from the disposable checkout. |

The first fork dispatch is intentionally pending while this package is reviewed. Its GitHub Actions
run and artifacts become the evidence locator; no generated measurement is committed.

The mutation verifier observes non-ignored Git paths. It does not prove complete filesystem write
confinement: ignored dependency/setup state, ignored Ota state, and any other ignored writes remain
outside this bounded evidence claim.

## PINT naming boundary

`npm run eval:pint` uses ATR's self-built 850-sample PINT-format corpus. It is **not** a run of
Lakera's official PINT benchmark, whose corpus is private. This package makes no certification,
endorsement, benchmark-quality, generalization, or product-security claim.

## What a successful run proves

At the recorded repository commit, the workflow checked out a clean tree, installed locked
dependencies, ran the contract-selected ATR-owned PINT-format command through Ota, rejected the
pre-run report as stale, required both the Ota command and ATR regression gate to exit successfully,
retained a fresh reconciled report/measurement result, and kept the observed tracked mutations within
the declared non-ignored Git output boundary.

It does not prove Lakera PINT results, universal parser or engine correctness, absence of false
negatives, benchmark or artifact determinism, independent engine attestation, endorsement,
adoption, merge readiness, coverage by ATR's required CI on `main`, or complete filesystem write
confinement outside the observed non-ignored Git paths.

## Draft PR gate

After Ota `v1.6.28` is released:

1. change only `agent.bootstrap.ota.source` from the exact Git revision to `kind: version` /
   `version: v1.6.28`;
2. rerun the same fork workflow against the pinned release;
3. review the released-pin matrix and its artifacts with the maintainer; and
4. open the already invited draft PR only if that evidence remains valid and the maintainer wants
   the unchanged bounded scope.

Otherwise, leave this package on the fork for review and make no upstream change.
