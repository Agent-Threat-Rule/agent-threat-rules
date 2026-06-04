# Semantic-validation harness

A focused, reproducible check of what the v3.1.0 optional semantic stage (Tier-2
LLM-as-judge) actually buys on the two threats its first semantic rules target:

- ATR-2026-00573 — paraphrased instruction-override
- ATR-2026-00574 — indirect system-prompt extraction

This is a validation, not an independent benchmark. Read the caveats.

## Method

Two stages, matching `scripts/scan-with-judge.mts`:

1. Stage 1 — the deterministic ATR regex engine (all rules) screens every item.
2. Stage 2 — a semantic judge adjudicates the items Stage 1 missed. Verdicts here
   were produced in worklist mode (no API key): the engine dumped the missed
   subset and a Claude Code session adjudicated each item (category + confidence),
   the same role an OpenAI-compatible judge would fill. Threshold 0.7.

## Corpus

- `attacks.json` — 20 held-out paraphrased attacks (10 instruction-override,
  10 indirect system-prompt extraction). Worded to evade the literal-keyword
  pattern rules, so the regex layer must miss most of them for the test to mean
  anything. Not reused from any rule's own `test_cases`.
- `benign.json` — 15 adversarial benign near-misses that share surface vocabulary
  with the attacks ("set this aside and focus on …", "walk me through how to
  configure nginx", "from now on use metric units", benign "ignore"/"forget").
- `verdicts-claude-run1.json` — the Stage-2 adjudication for run 1 (2026-06-04).

## Result (run 1, 2026-06-04, Claude-as-judge, threshold 0.7)

| Metric | Value |
| --- | --- |
| Attack recall — regex only | 10% (2/20) |
| Attack recall — combined (regex + semantic) | 95% (19/20) |
| Benign false positives — regex | 0/15 |
| Benign false positives — judge | 0/15 |
| Precision proxy (this corpus) | 100% |

The single attack the judge did not flag (`atk-ext-01`) is a deliberately soft
probe rated 0.65, below threshold — a genuine ambiguity between extraction and
benign curiosity, not a bug. The run also surfaced a pre-existing false positive
in ATR-2026-00001 (benign "start fresh with a new outline"), fixed in v3.1.1; the
0/15 regex FP above is post-fix.

## Caveats (read before citing)

- Small n (20 attacks / 15 benign). Focused on two narrow threats — NOT a measure
  of ATR's overall recall.
- The corpus was authored for this test and adjudicated by a Claude session acting
  as the judge. It demonstrates that the semantic stage recovers paraphrased
  attacks the regex layer misses without over-flagging adversarial benign input;
  it is not an independent, third-party benchmark.
- Different judge models / thresholds will move the numbers.

## Reproduce

```
# Stage 1 + worklist dump (no API key); then adjudicate and score:
JUDGE_SUBSET=missed WORKLIST_OUT=/tmp/wl.json npx tsx scripts/scan-with-judge.mts data/semantic-validation/attacks.json

# Or score directly against the recorded verdicts:
npx tsx scripts/semantic-validation-score.mts --verdicts data/semantic-validation/verdicts-claude-run1.json

# With your own judge backend (OpenAI-compatible):
ATR_SEMANTIC_API_KEY=sk-... npx tsx scripts/scan-with-judge.mts data/semantic-validation/attacks.json
```
