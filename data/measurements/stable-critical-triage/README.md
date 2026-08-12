# stable-critical-triage

Hand-written **legitimate** content used to triage the `maturity: stable` +
`severity: critical` rules whose benign-gate zero is vacuous (corpus visibility
`blind` or `thin`). Full analysis: `docs/research/stable-critical-triage.md`.

## Files

| file | what it is |
| --- | --- |
| `benign-probes.jsonl` | 83 legitimate samples, one per line |
| `probe-result-20260812.json` | recorded output of `scripts/detection-boundary/stable-critical-probe.ts` at `161782bca` |

## Schema of `benign-probes.jsonl`

| field | meaning |
| --- | --- |
| `id` | `B001`… — referenced from the analysis document |
| `class` | `primitive` = legitimate content that *performs* the action a rule keys on. `quote` = legitimate content that *names* the attack string in order to defend against it. The two demand opposite fixes. |
| `targets` | rule ids the sample was written against |
| `kind` | what sort of document this is (runbook, tool docs, production code, …) |
| `why` | one sentence on why this content is legitimate |
| `text` | the sample |

## This is NOT a gate corpus

These samples are deliberately **not** under `data/skill-benchmark/benign`,
`data/benign-corpus-extended` or `data/benign-code`, the three corpora
`scripts/gate-promotion-fp.ts` and `scripts/gate-corpus-visibility.ts` read.

Adding them changes the false-positive denominator for all 784 rules. Measured
at the time of writing, by the harness itself:

```
distinct rules fired by the 83 probes: 68
  of which currently 0 FP in data/benign-fp-measurement.json: 30
  of which already have FP on record: 38
total (rule, probe) firings: 191
```

30 rules would move from clean to dirty. Most of them are outside the 24 rules
this triage examined. That is the correct outcome — their zeros are equally
vacuous — but it is a decision about what the project claims, not a side effect
of a research file, so it stays out of the gate corpora until someone decides.

## Reproducing

```bash
npx tsx scripts/detection-boundary/stable-critical-probe.ts
npx tsx scripts/detection-boundary/stable-critical-probe.ts --json
```

The harness fires every probed rule with its own declared true positive first
and aborts if none fires — `new ATREngine(...)` does not compile patterns until
`loadRules()`, and a harness that skips it reports a clean sheet for everything.
