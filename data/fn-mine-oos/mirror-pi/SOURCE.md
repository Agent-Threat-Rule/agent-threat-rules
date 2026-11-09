# Source

Each injection mirrored by a benign prompt on the same topic and category (persona, extraction, override).

Upstream (pinned):

- https://huggingface.co/datasets/watchdogsrox/Mirror-Prompt-Injection-Dataset/tree/94a434cdf958ecb91548314f478b76e72aaaa0e8 (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
