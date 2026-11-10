# Source

Machine-written direct and indirect injections with benign prompts.

Upstream (pinned):

- https://huggingface.co/datasets/Lilbullet/prompt-injection-artificial-GPTOSS120b/tree/f229cac7c36139a592b35b4dc4e190ff70ecc0e0 (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
