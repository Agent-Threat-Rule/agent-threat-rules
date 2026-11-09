# Source

Paraphrased overrides and soft reframes, with hard negatives that use the same trigger words.

Upstream (pinned):

- https://huggingface.co/datasets/promptprotection/agent-security-datasets/tree/3c808d860711864f5dae99fb05f75a8139b8107d (cc-by-4.0)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
