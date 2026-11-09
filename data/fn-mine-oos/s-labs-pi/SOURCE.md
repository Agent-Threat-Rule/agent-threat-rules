# Source

Labelled injections and benign prompts.

Upstream (pinned):

- https://huggingface.co/datasets/S-Labs/prompt-injection-dataset/tree/002a9dd18514abd021869823d6b0429b38606d99 (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
