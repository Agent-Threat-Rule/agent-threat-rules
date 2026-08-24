# One rule, most of the number

**Date:** 2026-08-24 · **Ruleset:** 785 rules at `origin/main` 53c84daaf · **Lane:** `hunt`

Two measurements in this repo have been dominated by a single rule, in opposite
directions:

- `ATR-2026-00086` produced about a third of every flag across 36,394 ClawHub
  skills by matching Cyrillic script rather than an attack
  (`clawhub-benign-fp-2026-08-19.md`).
- On the PINT-format corpus, most detection comes from one rule.

Neither is recoverable from the stored measurement artifacts, because those
break down by **family**, never by rule. Per-rule share has to be computed
during the run. `scripts/gate-detection-concentration.ts` does that.

## Measured: PINT attack half, 451 samples, 295 detected

| rule | covers | of detected | sole detector | of detected |
| --- | ---: | ---: | ---: | ---: |
| `ATR-2026-00001` | 226 | 76.6% | **113** | **38.3%** |
| `ATR-2026-00213` | 73 | 24.7% | 0 | 0.0% |
| `ATR-2026-00061` | 65 | 22.0% | 9 | 3.1% |
| `ATR-2026-00282` | 57 | 19.3% | 0 | 0.0% |
| `ATR-2026-00010` | 56 | 19.0% | 1 | 0.3% |

**Delete `ATR-2026-00001` and detection on this corpus falls by 38.3%.**
Sixty other rules fire on it; all but two of them fire only where something else
already did.

## Why two shares, and why the second is the one that matters

Share-of-hit-events makes a rule that fires alongside five others look large
while removing it would change no verdict — `ATR-2026-00213` covers a quarter of
the detected samples and is the sole detector of none. The gate thresholds on
**sole-detector share** for that reason: it is the amount the corpus figure
actually moves if the rule goes away.

## The claim this affects

The v4.0.0 release notes state `PINT benchmark: 62.7% recall, 99.7% precision`
with no attribution. Whatever that recall is, over a third of it is one rule.
A high share is not automatically wrong — a single-family corpus legitimately
concentrates — but it is a property that has to be stated deliberately rather
than discovered afterwards, and that is what the gate forces.

Reproduce:

```bash
npx tsx scripts/gate-detection-concentration.ts \
  --corpus <corpus.jsonl> --field text --max-share 0.25
```

The control prints before any figure and exits 1 if the engine loaded no rules,
a known attack does not fire, or a plain business sentence does.
