# Source

Injections and benign prompts for a classifier, including placeholder-secret extraction.

Upstream (pinned):

- https://huggingface.co/datasets/fevziegeyurtsevenler/prompt-injection-classification/tree/26fe7a9a346c6eb47c620386e45bb64a814e758e (cc-by-4.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
