# Source

Jailbreak prompts (output-format constraints, refusal suppression, prefix forcing).

Upstream (pinned):

- https://huggingface.co/datasets/Simsonsun/JailbreakPrompts/tree/eba9f8c492e5fdad7c753766aedb60fdd4a64bc8 (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
