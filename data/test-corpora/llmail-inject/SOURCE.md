# llmail-inject

- Upstream: https://huggingface.co/datasets/microsoft/llmail-inject-challenge
- Revision: `1063bdf01ec8762b812d5e06ee768a06faa5a6f7`
- Files: `data/raw_submissions_phase1.jsonl`, `data/raw_submissions_phase2.jsonl`
- License (dataset card front matter, quoted): `license: mit`
- Retrieved: 2026-10-06
- Row filter: all five objectives true (email.retrieved, defense.undetected, exfil.sent, exfil.destination, exfil.content); deduplicated on subject+body; stratified by phase/level in sha256 order; at most 3000
- Rows kept: 1973

Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --write`.

## License

The rows in corpus.json are a portion of the upstream dataset, redistributed under its MIT license (https://github.com/microsoft/llmail-inject-challenge/blob/main/LICENSE):

```
MIT License

Copyright (c) Microsoft Corporation.

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
