# Source

Labelled injections across categories, with security-adjacent hard negatives (research-licensed WildGuard rows and HarmBench goals left out).

Upstream (pinned):

- https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset/tree/7d70432dfcf47a821612cbf9d34e9d9e3ad20e75 (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
