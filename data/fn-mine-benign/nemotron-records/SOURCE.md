# nemotron-records

Benign tool output for the FN-mine gate (scripts/fn-mine-llm.ts) only: a candidate rule must fire on none of these, presented as tool_response. Not part of MEASUREMENT_CORPORA or any repo-wide gate, baseline or threshold.

- Upstream: https://huggingface.co/datasets/nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1
- Revision: `d738d4f361cc38bb4d7a42b9066776dade5332f5`
- Files: `train.jsonl`
- License (dataset card front matter, quoted): `license: cc-by-4.0`
- Retrieved: 2026-11-08
- Row filter: every record's environment strings of 40+ characters with whitespace; a field holding the record's injection kept with the injection cut out; a field holding any other record's injection skipped; deduplicated; stratified by domain in sha256 order; at most 3000 and 4500000 bytes
- Rows kept: 3000

Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --source nemotron-records --write`.

Same records and revision as data/test-corpora/nemotron-agentic-ipi (see its SOURCE.md); this is their content with every injection removed, the enterprise record text the email and page sets lack.

## License

The rows in corpus.json are adapted from nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1 (Dataset Owner(s): NVIDIA Corporation), licensed under CC BY 4.0
(https://creativecommons.org/licenses/by/4.0/).

Changes: each row is one prose field of a record's environment, extracted from its record and trimmed; a
record's injection, and any field holding one, is removed; fields under 40 characters are dropped; rows are
deduplicated and reordered as the row filter says; a label ("benign") and a family (the record's domain) are
added to each row.
