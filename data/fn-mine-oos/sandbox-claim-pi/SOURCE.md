# Source

Injections that claim a sandbox, test mode or new authority, with benign prompts.

Upstream (pinned):

- https://huggingface.co/datasets/Shomi28/prompt-injection-dataset/tree/0146454c8404a347ccc170a0291bcec932252fef (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
