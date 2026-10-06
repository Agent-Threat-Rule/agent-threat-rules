# browsesafe-bench

- Upstream: https://huggingface.co/datasets/perplexity-ai/browsesafe-bench
- Revision: `b506fb5bc7fd4472c8738055a67a0ef6406afdc9`
- Files: `test.parquet (via datasets-server rows API, split=test)`
- License (dataset card front matter, quoted): `license: mit`
- Retrieved: 2026-10-06
- Row filter: label == 'yes'; page projected to text units absent from every benign page of the split; projections over 6000 chars skipped; sha256 order; at most 3000 and 4500000 bytes
- Rows kept: 1012

Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --write`.
