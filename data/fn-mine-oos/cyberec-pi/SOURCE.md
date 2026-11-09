# Source

Injections by category and severity with benign security questions (the un-augmented core split).

Upstream (pinned):

- https://huggingface.co/datasets/cyberec/Prompt-injection-dataset/tree/cfe0ce4a4d5eb9528ffaca55cf0db27ac609b8b1 (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
