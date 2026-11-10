# Source

Benign only: everyday requests by task type and domain, written as negatives for an injection classifier.

Upstream (pinned):

- https://huggingface.co/datasets/axiotic/ogma-prompt-injection-benign/tree/089327b0977e1296e4992d9b83a5248d1616edd4 (apache-2.0)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
