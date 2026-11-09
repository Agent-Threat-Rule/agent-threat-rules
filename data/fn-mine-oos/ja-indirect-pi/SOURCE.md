# Source

Japanese documents (email, news, minutes) with an injected instruction, as a reading tool returns them.

Upstream (pinned):

- https://huggingface.co/datasets/masahiroid/japanese-indirect-prompt-injection-probes/tree/c6cf9746f76f58468c0979a3c50596e6958c7f79 (cc-by-4.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
