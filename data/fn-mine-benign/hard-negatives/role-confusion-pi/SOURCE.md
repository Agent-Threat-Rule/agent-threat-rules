# Source

Injections labelled by type (role confusion, developer-mode claims, extraction), with benign prompts.

Upstream (pinned):

- https://huggingface.co/datasets/AhmetHalil/prompt_injections/tree/127b21b0c5d1d1c43ae399b65ed141a7d2402b89 (mit)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
