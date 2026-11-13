# Source

Role-play jailbreaks that push a model to write panic-inducing posts.

Upstream (pinned):

- https://huggingface.co/datasets/IDA-SERICS/Disaster-tweet-jailbreaking/tree/de5c165758ba7d50f43b5599c3fe7a2b08ac6e0c (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
