# Source

Turkish customer-service conversations with injected turns, each paired with the benign turn.

Upstream (pinned):

- https://huggingface.co/datasets/3nesdeniz/turkish-conversation-prompt-injection/tree/29d7593984f563c4ad56876aa800b9ffd948a2fb (cc-by-4.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
