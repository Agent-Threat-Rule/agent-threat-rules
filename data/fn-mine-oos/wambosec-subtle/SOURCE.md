# Source

Subtle injections (misdirection, output manipulation, instruction hijacking inside a plausible task).

Upstream (pinned):

- https://huggingface.co/datasets/wambosec/prompt-injections-subtle/tree/cd789a6e362aa72624d7f835c5270c8c3bdaf524 (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
