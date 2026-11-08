# nemotron-tasks

Benign tool output for the FN-mine gate (scripts/fn-mine-llm.ts) only: a candidate rule must fire on none of these, presented as tool_response. Not part of MEASUREMENT_CORPORA or any repo-wide gate, baseline or threshold.

- Upstream: https://huggingface.co/datasets/nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1
- Revision: `d738d4f361cc38bb4d7a42b9066776dade5332f5`
- Files: `train.jsonl`
- License (dataset card front matter, quoted): `license: cc-by-4.0`
- Retrieved: 2026-11-08
- Row filter: every record's user turn in responses_create_params.input, 40+ characters; deduplicated; stratified by domain in sha256 order; at most 3000 and 4500000 bytes
- Rows kept: 1271

Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --source nemotron-tasks --write`.

Same records and revision as data/test-corpora/nemotron-agentic-ipi. The benign request each record starts from: it asks for the actions the record's injection asks for, in the same words, so a rule that fires on it fires on a task or ticket a tool returns.

## License

The rows in corpus.json are adapted from nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1 (Dataset Owner(s): NVIDIA Corporation), licensed under CC BY 4.0
(https://creativecommons.org/licenses/by/4.0/).

Changes: each row is the user turn of one record's request, extracted from its record and trimmed; the rest
of each record is dropped; rows are deduplicated and reordered as the row filter says; a label ("benign")
and a family (the record's domain) are added to each row.
