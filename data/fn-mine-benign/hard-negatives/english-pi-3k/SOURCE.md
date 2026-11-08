# Source

Injections labelled by family and technique (delimiter injection, authority impersonation, prompt extraction), with hard negatives about those techniques.

Upstream (pinned):

- https://huggingface.co/datasets/3nesdeniz/english-prompt-injection-3k/tree/87f017347aff7887b1de0d9457c9ec01bf7ba8b5 (cc-by-4.0)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
