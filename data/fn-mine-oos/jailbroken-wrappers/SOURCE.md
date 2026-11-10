# Source

Jailbreak wrappers by name (prefix injection, refusal suppression, combinations), one row per wrapper.

Upstream (pinned):

- https://huggingface.co/datasets/sevdeawesome/jailbreak_success/tree/12bad235ee184287bc5f41ec2341489501a30049 (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
