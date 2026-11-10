# Source

Injections (mostly German) each with two safe rewrites, the rewrites as benign.

Upstream (pinned):

- https://huggingface.co/datasets/hse-llm/prompt-injections/tree/6619b5e0f7a907404b8b81df6aa97c2114dd27a1 (mit)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
