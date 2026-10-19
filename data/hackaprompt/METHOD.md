# HackAPrompt measurement: method

What a `data/measurements/hackaprompt/` file measures, and how to reproduce it.

## Source

- Paper: Schulhoff et al., "Ignore This Title and HackAPrompt: Exposing Systemic
  Vulnerabilities of LLMs Through a Global Prompt Hacking Competition", EMNLP 2023,
  pp. 4945-4977, doi:10.18653/v1/2023.emnlp-main.302
  (https://aclanthology.org/2023.emnlp-main.302/). It is listed under Best Paper
  Awards at https://2023.emnlp.org/program/best_papers/.
- Dataset: `hackaprompt/hackaprompt-dataset` on HuggingFace (gated, not
  redistributed here), revision `25b87fbedfb86840abaf8cd09af7a029208a971a`
  (unchanged upstream since 2024-01-24). Split `train`, 601,757 rows, one
  parquet file, sha256 `bedca308fbd71be57793930e4e4a0dcfbda2a27b6d0f2ad3191bb20a6a315928`.
  Target models in the rows: gpt-3.5-turbo, FlanT5-XXL, text-davinci-003.

## Sample set (4,780)

`scripts/hackaprompt-to-corpus.py` with its defaults:

1. `random.seed(20260511)`; `sorted(random.sample(range(601757), 5000))`.
2. Drop rows whose `user_input.strip()` is shorter than 3 characters (220 rows).
3. `text = user_input.strip()[:4096]`; every row labelled adversarial;
   `category` is `jailbreak` when `correct` is true (673), else
   `prompt-injection` (4,107).

The script writes the corpus (gitignored) and
`hackaprompt-corpus.manifest.json` (committed): dataset id, revision, seed, the
4,780 row indices, the corpus sha256
(`e7c3886d320e0c28f4569d06e544f2589bc58a5f7edd8c3e8d0a3707d1596364`) and the
sha256 of the newline-joined sample ids
(`9d4ee23f775b4f9429fe37215031f2d7a9fa54fba49422261fc5f26ccc8af73d`). The runner
refuses a corpus whose digest differs from the manifest.

This is the set first measured in PR #51 (2026-05-11). Re-running the PR #51
merge commit `f20d74e3` on it gives 1,367 of 4,780 detected, the same per-sample
misses its committed report lists.

## Metric

Recall = attack samples with at least one rule match / 4,780. A sample is
pushed through the evaluation harness (`src/eval/eval-harness.ts`) as an
`llm_input` event, in the harness's default event shape (`canonical` since
2026-08-05), with the regex tier and, when the local embedding model loads, the
embedding tier. The measurement file records the event shape and tiers used.
A match is not a block; enforce-lane recall is an upper bound on what blocking
stops. The corpus has no benign samples, so precision and FP rate are not
measured (the file carries the schema's convention values).

Recall is reported per detection lane: `hunt` (every maturity; the headline,
as for every source), `alert` (stable + test) and `enforce` (stable only), in
`breakdown.lanes`.

## In-sample disclosure

Rules were written from this corpus: ATR-2026-00442..00447 (PR #51) and
00452..00456 (commit `e9efefdd`) from this exact sample, others from its
false-negative residue. `breakdown.in_sample_ablation` re-measures the same
samples with (a) 00452..00456 removed and (b) every rule whose YAML names
HackAPrompt removed. Cite (b) next to the headline whenever the headline is cited.

## Reproduce

```bash
git checkout <commit that added the measurement file>   # rules/ tree = its rules_tree_sha
npm ci
npm run eval:hackaprompt   # HuggingFace access to the gated dataset required
```

Runtime is roughly 30 minutes on a laptop (seven full passes over the corpus).
