# panza-emails

Benign tool output for the FN-mine gate (scripts/fn-mine-llm.ts) only: a candidate rule must fire on none of these, presented as tool_response. Not part of MEASUREMENT_CORPORA or any repo-wide gate, baseline or threshold.

- Upstream: https://huggingface.co/datasets/ISTA-DASLab/Panza-emails
- Revision: `3c972a7d1e8f747eedb5351003f4adb0cf35ffe7`
- Files: `david/train.jsonl`, `david/test.jsonl`, `isabel/train.jsonl`, `isabel/test.jsonl`, `marcus/train.jsonl`, `marcus/test.jsonl`
- License (dataset card front matter, quoted): `license: apache-2.0`
- Retrieved: 2026-10-06
- Row filter: every row; subject and body joined; CRLF to LF; email addresses replaced, phone numbers masked; deduplicated on the final text; stratified by donor/split in sha256 order
- Rows kept: 526

Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --source panza-emails --write`.

## License

The rows in corpus.json are a portion of the upstream dataset (The Panza Emails dataset, ISTA DASLab (IST Austria); emails donated by their three authors), redistributed under the
Apache License, Version 2.0, which its dataset card declares (https://huggingface.co/datasets/ISTA-DASLab/Panza-emails/blob/3c972a7d1e8f747eedb5351003f4adb0cf35ffe7/README.md). A copy of the license is in
`LICENSE-APACHE-2.0.txt` beside this file (https://www.apache.org/licenses/LICENSE-2.0.txt). The upstream ships no NOTICE file.

Changes made to the upstream rows (Apache-2.0 section 4(b)): subject and body joined as "subject, blank line,
body"; CRLF line ends converted to LF; leading and trailing whitespace trimmed; email addresses replaced by
`redacted@example.com`; phone numbers masked digit by digit; signed-URL parameters and tokens masked as in the
attack corpora; NUL bytes removed; duplicate texts dropped.
