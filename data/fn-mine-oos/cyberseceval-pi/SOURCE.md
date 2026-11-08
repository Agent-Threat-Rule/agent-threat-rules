# Source

Meta CyberSecEval 3 prompt-injection test inputs (direct and indirect variants, machine-translated set included).

Upstream (pinned):

- https://github.com/meta-llama/PurpleLlama/tree/f64eebd53003a87d9c2d2a3a712133534c214c8d (MIT)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
