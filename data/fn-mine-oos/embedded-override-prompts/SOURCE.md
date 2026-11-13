# Source

A system prompt and user request with an injection embedded in the user content ([SYSTEM OVERRIDE], "Actual instruction:").

Upstream (pinned):

- https://huggingface.co/datasets/stindardlogic/prompt-injection-defense-dpo-3k/tree/c76036d292901f7e0d4b6a8137c33185a3a96227 (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
