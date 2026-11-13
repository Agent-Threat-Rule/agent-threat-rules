# Source

Injections by attack type with benign prompts.

Upstream (pinned):

- https://huggingface.co/datasets/darkknight25/Prompt_Injection_Benign_Prompt_Dataset/tree/a0fc54fb563468a7fd64a9412718ce7cdb366666 (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
