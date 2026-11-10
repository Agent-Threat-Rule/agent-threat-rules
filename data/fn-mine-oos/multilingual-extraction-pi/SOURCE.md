# Source

Short prompt-extraction and protocol-bypass requests in several European languages.

Upstream (pinned):

- https://huggingface.co/datasets/yanismiraoui/prompt_injections/tree/bd55359f2f332afc35f277ac3dd08f7111b024c9 (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
