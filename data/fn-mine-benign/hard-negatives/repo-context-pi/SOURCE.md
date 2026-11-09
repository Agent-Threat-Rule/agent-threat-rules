# Source

Injections in repository files (README, config, PR templates) that steer a code-review agent; the dataset's [FILETYPE=]/[ATTACK=] tags removed.

Upstream (pinned):

- https://huggingface.co/datasets/ShieldX/Context-Aware-Repository-Prompt-Injection/tree/668bf56216cd33fd6dabf6703f35edf4f4469811 (apache-2.0)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
