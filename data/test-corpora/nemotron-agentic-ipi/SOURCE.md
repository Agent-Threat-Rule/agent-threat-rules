# nemotron-agentic-ipi

- Upstream: https://huggingface.co/datasets/nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1
- Revision: `d738d4f361cc38bb4d7a42b9066776dade5332f5`
- Files: `train.jsonl`
- License (dataset card front matter, quoted): `license: cc-by-4.0`
- Retrieved: 2026-11-08
- Row filter: every record; the environment field that contains injection.injection_text, as the read tool returns it; one row per distinct injection_text (whitespace and case folded); stratified by attack_category in sha256 order; at most 3000
- Rows kept: 675

Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --write`.

## License

The rows in corpus.json are adapted from nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1 (Dataset Owner(s): NVIDIA Corporation), licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).

Changes: each row is the one environment field that holds the record's injection, extracted from its record and trimmed of surrounding whitespace; the rest of each record is dropped; rows are deduplicated and reordered as the row filter says; a label ("attack") and a family (the record's attack_category) are added to each row.
