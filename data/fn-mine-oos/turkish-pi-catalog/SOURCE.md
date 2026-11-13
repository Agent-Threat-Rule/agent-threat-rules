# Source

The same catalogue written in Turkish.

Upstream (pinned):

- https://huggingface.co/datasets/fevziegeyurtsevenler/turkish-prompt-injection/tree/fae488a1644a02bb8f377743e516db356b9a93c1 (cc-by-4.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
