# Source

Hand-written injections by category (instruction override, role-play, extraction, encoding) and benign prompts.

Upstream (pinned):

- https://huggingface.co/datasets/zachz/prompt-injection-benchmark/tree/dc0072ad6af8d1be049cdb60959e3ff51df4bcae (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
