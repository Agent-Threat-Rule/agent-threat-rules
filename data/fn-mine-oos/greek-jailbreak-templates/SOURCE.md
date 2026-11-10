# Source

StrongREJECT jailbreak templates translated into Greek.

Upstream (pinned):

- https://huggingface.co/datasets/ilsp/Jailbreak-StrongReject-el/tree/9d9fd1e5a5ab9d2f05660d605ffbd054a0bb2b5f (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
