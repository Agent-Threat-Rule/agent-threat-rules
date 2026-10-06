# browsesafe-bench

- Upstream: https://huggingface.co/datasets/perplexity-ai/browsesafe-bench
- Revision: `b506fb5bc7fd4472c8738055a67a0ef6406afdc9`
- Files: `test.parquet (via datasets-server rows API, split=test)`
- License (dataset card front matter, quoted): `license: mit`
- Retrieved: 2026-10-06
- Row filter: label == 'yes'; page projected to text units absent from every benign page of the split; projections over 6000 chars skipped; signed-URL parameters, tokens, freemail local parts and AWS account ids masked; sha256 order; at most 3000 and 4500000 bytes
- Rows kept: 1012

Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --write`.

Regeneration reads the datasets-server rows API, which serves only the main branch. It works while main equals the pinned revision and refuses otherwise. The rows come from the pinned `test.parquet` (https://huggingface.co/datasets/perplexity-ai/browsesafe-bench/resolve/b506fb5bc7fd4472c8738055a67a0ef6406afdc9/test.parquet, LFS sha256 `00cbad96b60fee46e016d79af6981fb221384c61f12cf28b4f04b5a6420573d0`), which stays available to audit them after upstream moves on.

## License

The rows in corpus.json are a portion of the upstream dataset, redistributed under its MIT license (https://huggingface.co/datasets/perplexity-ai/browsesafe-bench/blob/b506fb5bc7fd4472c8738055a67a0ef6406afdc9/LICENSE):

```
MIT License

Copyright 2025 Perplexity AI, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
