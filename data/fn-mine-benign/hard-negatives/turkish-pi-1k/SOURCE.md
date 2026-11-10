# Source

Turkish injections by family and technique (acrostic leaks, role-play, override), with hard negatives.

Upstream (pinned):

- https://huggingface.co/datasets/3nesdeniz/turkish-prompt-injection-1k/tree/1cbd1152d9732f40148fbd5bb7cf0f58ddfe84c6 (cc-by-4.0)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
