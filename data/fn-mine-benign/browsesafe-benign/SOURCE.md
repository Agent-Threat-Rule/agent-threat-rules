# browsesafe-benign

Benign tool output for the FN-mine gate (scripts/fn-mine-llm.ts) only: a candidate rule must fire on none of these, presented as tool_response. Not part of MEASUREMENT_CORPORA or any repo-wide gate, baseline or threshold.

- Upstream: https://huggingface.co/datasets/perplexity-ai/browsesafe-bench
- Revision: `b506fb5bc7fd4472c8738055a67a0ef6406afdc9`
- Files: `test.parquet (via datasets-server rows API, split=test)`
- License (dataset card front matter, quoted): `license: mit`
- Retrieved: 2026-10-06
- Row filter: label == 'no'; the whole page's text units (pageUnits, as for the attack pages); pages over 20000 chars skipped; identifiers masked as for the attack pages; NUL bytes removed; sha256 order; at most 3000 and 4500000 bytes
- Rows kept: 694

Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --source browsesafe-benign --write`.

Same split and revision as data/test-corpora/browsesafe-bench, read the same way (see its SOURCE.md); that corpus is the attack pages minus every unit these benign pages share.

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
