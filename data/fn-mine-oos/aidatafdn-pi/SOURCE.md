# Source

Injections by category (override, leakage, role play) and benign prompts.

Upstream (pinned):

- https://huggingface.co/datasets/AIDataFdn/promptinjection/tree/99426e65f23ddfb4e19efe1984618a8c61e2d1c6 (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
