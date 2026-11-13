# Source

Injections in several languages.

Upstream (pinned):

- https://huggingface.co/datasets/rikka-snow/prompt-injection-multilingual/tree/f1ad1f3dd44581f53a4c67e96a9dde2fb419ee5b (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
