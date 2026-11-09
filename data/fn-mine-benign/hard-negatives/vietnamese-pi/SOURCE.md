# Source

Vietnamese and code-switched Vietnamese/English injections with benign prompts.

Upstream (pinned):

- https://huggingface.co/datasets/tmdeptrai3012/prompt-injection-dataset-vi-en/tree/2afeb49278455c0e17efbc76acd2581237fb6f27 (apache-2.0)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
