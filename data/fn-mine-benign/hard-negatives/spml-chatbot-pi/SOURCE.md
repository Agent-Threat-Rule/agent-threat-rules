# Source

User turns that try to pull a system-prompted chatbot out of its role (persona swaps, scope breaks), with the in-scope turns as benign.

Upstream (pinned):

- https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection/tree/02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5 (mit)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
