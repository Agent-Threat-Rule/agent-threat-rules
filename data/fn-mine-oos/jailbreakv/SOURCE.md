# Source

Text jailbreak templates, persuasion and logic attacks (image-only formats excluded).

Upstream (pinned):

- https://huggingface.co/datasets/JailbreakV-28K/JailBreakV-28k/tree/f949ca582fff13d396ac8fce59596afafb2b78d3 (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
