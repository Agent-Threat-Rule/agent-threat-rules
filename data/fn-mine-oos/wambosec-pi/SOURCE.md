# Source

Injections by category (format-string, encoding, override) and benign prompts.

Upstream (pinned):

- https://huggingface.co/datasets/wambosec/prompt-injections/tree/071ee17a60112b7f9f808398156b430aadfaf1d2 (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
