# Source

Hand-written injections by category, including agent exfiltration through tool URLs.

Upstream (pinned):

- https://huggingface.co/datasets/mukunda1729/prompt-injection-patterns-extended/tree/818f58cfa4fbeac35faba3789fd47075dcdba28c (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
