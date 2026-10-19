# HackAPrompt measurement: method

What a `data/measurements/hackaprompt/` file measures, and how to reproduce it.

## Source

- Paper: Schulhoff et al., "Ignore This Title and HackAPrompt: Exposing Systemic
  Vulnerabilities of LLMs Through a Global Prompt Hacking Competition", EMNLP 2023,
  pp. 4945-4977, doi:10.18653/v1/2023.emnlp-main.302
  (https://aclanthology.org/2023.emnlp-main.302/). It is listed under Best Paper
  Awards at EMNLP 2023 (https://2023.emnlp.org/program/best_papers/).
- Dataset: `hackaprompt/hackaprompt-dataset` on HuggingFace (gated, not
  redistributed here), revision `25b87fbedfb86840abaf8cd09af7a029208a971a`
  (unchanged upstream since 2024-01-24). Split `train`, 601,757 rows, one
  parquet file, `hackaprompt.parquet`, 150,419,795 bytes, sha256
  `bedca308fbd71be57793930e4e4a0dcfbda2a27b6d0f2ad3191bb20a6a315928` (the LFS
  object id HuggingFace reports for that file at that revision).
  Target models in the rows: gpt-3.5-turbo, FlanT5-XXL, text-davinci-003.

## Sample set (4,780 of 601,757)

A seeded subset, not the whole dataset. `scripts/hackaprompt-to-corpus.py` with
its defaults:

1. Downloads `hackaprompt.parquet` at the pinned revision through
   `huggingface_hub` and refuses to continue unless its sha256 is the value above.
2. `random.seed(20260511)`; `sorted(random.sample(range(601757), 5000))`.
3. Drops rows whose `user_input.strip()` is shorter than 3 characters (220 rows).
4. `text = user_input.strip()[:4096]`; every row labelled adversarial.

The committed manifest, `hackaprompt-corpus.manifest.json`, records the dataset
id, revision, parquet sha256, seed, the 4,780 row indices, the corpus sha256
(`e7c3886d320e0c28f4569d06e544f2589bc58a5f7edd8c3e8d0a3707d1596364`) and the
sha256 of the newline-joined sample ids
(`9d4ee23f775b4f9429fe37215031f2d7a9fa54fba49422261fc5f26ccc8af73d`).

The script checks by default: it re-draws the sample and compares
`corpus_sha256`, `sample_ids_sha256` and the row indices with the committed
manifest, and on any mismatch exits 1 without writing anything. Only on a match
does it write the corpus file (gitignored) the runner reads. `--write` rewrites
the manifest; use it only to pin a different sample set on purpose. The runner
also refuses a corpus whose sha256 differs from the manifest.

This is the set first measured in PR #51 (2026-05-11); see Historical re-runs.

## Metric

Recall = attack samples with at least one rule match / 4,780. A sample is
pushed through the evaluation harness (`src/eval/eval-harness.ts`) as an
`llm_input` event, in the harness's default event shape (`canonical` since
2026-08-05), with the regex tier and, when the local embedding model loads, the
embedding tier. A match is not a block; enforce-lane recall is an upper bound
on what blocking stops. The corpus has no benign samples, so precision and FP
rate are not measured: the measurement file carries the schema's convention
values, 1 and 0, and declares `breakdown.precision_not_citable`, so
`data/stats.json` projects precision, F1 and FP rate as null and README's cells
read "not cited".

Recall is reported per detection lane: `hunt` (every maturity; the headline,
as for every source), `alert` (stable + test) and `enforce` (stable only), in
`breakdown.lanes`.

`breakdown.by_category` groups samples by HackAPrompt's `correct` field:
`competition-outcome:succeeded` when the submission made its target model emit
the level's target output (the attack worked in the competition, 673 samples),
`competition-outcome:failed` otherwise (4,107). It is not an attack type. The
corpus file's own `category` field (`jailbreak` / `prompt-injection`) is the
label PR #51 derived from the same field; it is kept so the corpus keeps the
digest the manifest pins, and the runner does not use it.
`breakdown.by_difficulty` buckets the competition level: 0-2 easy, 3-6 medium,
7-10 hard (ATR's bucketing, not HackAPrompt's).

### Embedding tier provenance

`breakdown.provenance.embedding` records what the embedding tier loaded: model
`Xenova/all-MiniLM-L6-v2` (quantized ONNX) through `@xenova/transformers`
(version recorded, 2.17.2 at the 2026-10-19 run), requested at revision `main`;
the sha256 of `config.json`, `tokenizer.json`, `tokenizer_config.json` and
`onnx/model_quantized.onnx` as loaded from the transformers.js cache; and the
Hub commit those files belong to, `751bff37182d3f1213fa05d7196b954e230abad9`
(checked 2026-10-19: the ONNX file's sha256 equals the Hub's LFS sha256 at that
commit, and the other three files' git blob ids equal the Hub's). It also
records the sha256 of `data/attack-embeddings.json` and the similarity
threshold (0.65).

`breakdown.provenance.hunt_without_embedding_tier` re-runs the hunt lane with
the embedding tier off. At the 2026-10-19 run it detects the same 3,972 of
4,780 samples: the headline does not depend on the embedding model.

## The ablation reference (cite it beside the headline)

Rules were written from this corpus: ATR-2026-00442..00447 (PR #51) and
00452..00456 (commit `e9efefdd`) from this exact sample, others from its
false-negative residue. Recall with them loaded is in-sample.

`breakdown.in_sample_ablation` re-measures the same samples with rules removed:

- `without_rules_naming_source` (the `reference`): every rule whose YAML text
  names HackAPrompt (20 rules at the 2026-10-19 run). This is the ablation
  reference. Whenever the headline is cited, cite it beside the headline, by
  lane.
- `without_batch_2026_05_12`: only ATR-2026-00452..00456.

The ablation reference approximates an out-of-sample figure; it does not
guarantee one. A rule whose YAML does not name HackAPrompt may still have been
tuned on these samples or on near-duplicates of them (HackAPrompt submissions
recur across levels and in later prompt-injection corpora), and a removed rule
may also catch attacks it was not mined from. It is the figure the repository
can measure, labelled as what it is, not an out-of-sample result.

At ATR 4.1.5 (2026-10-19, rules tree `6113bc87`):

| | hunt | alert | enforce |
|---|---:|---:|---:|
| all rules | 3,972 (83.1%) | 3,931 (82.2%) | 2,343 (49.0%) |
| ablation reference: without the 20 rules naming HackAPrompt | 1,372 (28.7%) | | 32 (0.7%) |
| without ATR-2026-00452..00456 only | 3,685 (77.1%) | | 92 (1.9%) |

## Historical re-runs

The earlier published figures were re-run on this exact sample set (corpus
sha256 `e7c3886d...`), each at its own commit with its own runner, lockfile and
event shape. The record of every run (commit, lockfile sha256, tiers, true
positives, and the sha256 of the sorted missed-sample ids) is
[`reruns-2026-10-19.json`](reruns-2026-10-19.json):

```bash
git worktree add ../wt <commit>
cd ../wt
npm ci                                   # that commit's package-lock.json
cp <this repo>/data/hackaprompt/hackaprompt-corpus.json data/hackaprompt/
npx tsx src/eval/run-hackaprompt-benchmark.ts   # that commit's runner
```

None of these commits has the `eventShape` option: their harness presents each
sample as the single declared `llm_input` event (what the current harness calls
`legacy`). Each ran with the regex tier and the embedding tier, which loaded.

| Commit | Date | What it is | Detected of 4,780 |
|---|---|---|---:|
| `f20d74e3` | 2026-05-11 | PR #51 merge: ATR-2026-00442..00447 and the benchmark harness | 1,367 (28.6%) |
| `3a6145b7` | 2026-05-12 | head before the 2026-05-12 sprint | 1,368 (28.6%) |
| `e9efefdd` | 2026-05-12 | adds ATR-2026-00452..00456 (and promotes 00457..00509) | 3,108 (65.0%) |
| `e9efefdd` without ATR-2026-00452..00456 | | ablation at that commit | 1,369 (28.6%) |
| `92c0d0fe` | 2026-05-12 | the v2.2.0 sprint commit | 3,154 (66.0%) |

- `f20d74e3` reproduces PR #51's committed report: the same 1,367 detections
  and the same per-sample misses (equal missed-id digests in the record).
- `f20d74e3` to `3a6145b7` (+1): sample `hap-0157040` is matched by
  ATR-2026-00450 (Spring AI prompt-memory poisoning), one of four CVE rules
  (00448..00451) added in between. It is not a HackAPrompt rule.
- `e9efefdd` with and without 00452..00456: 3,108 against 1,369, so those five
  rules account for 1,739 detections at that commit. The regex-only run at
  `e9efefdd` also gives 3,108.
- The "baseline" 28.6% (1,367 / 1,368) is itself in-sample: ATR-2026-00442..00447,
  mined from this same subset in PR #51, were already loaded. It is not an
  out-of-sample starting point.
- The 2026-05-12 CHANGELOG entry and the red-team page reported 28.6% → 66.2%.
  66.2% could not be reproduced at the sprint commits `e9efefdd` and `92c0d0fe`
  (66.0% at best, at `92c0d0fe`). No commit or file records a 66.2% run.

## Reproduce

```bash
git checkout <atr_commit>   # the measured tree; its rules/ tree is breakdown.provenance.rules_tree_sha
npm ci
npm run eval:hackaprompt
```

`npm run eval:hackaprompt` is `python3 scripts/hackaprompt-to-corpus.py &&
npx tsx src/eval/run-hackaprompt-benchmark.ts`: the first step verifies the
parquet sha256 and the re-drawn sample against the committed manifest and
exits 1, writing nothing, on any mismatch; the second measures. It needs
HuggingFace access to the gated dataset (`huggingface_hub` and `pyarrow` in the
Python environment). Runtime is roughly 25 minutes on a laptop (eight passes
over the corpus: three lanes, two ablations in two lanes, and the hunt lane
without the embedding tier).
