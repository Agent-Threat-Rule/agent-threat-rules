# Source

A catalogue of injection payloads by technique and language, each mapped to OWASP and ATLAS.

Upstream (pinned):

- https://huggingface.co/datasets/fevziegeyurtsevenler/multilingual-prompt-injection/tree/9cfe5ab6c61da76f1292f6f91cd7894a40010f55 (cc-by-4.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
