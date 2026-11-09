# Source

Agentic injection techniques with labelled families, and hard negatives (questions about attacks, legitimate role-play).

Upstream (pinned):

- https://huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-5k/tree/e658d94dcafc133e3a4483f9f9aa13507f3848c4 (cc-by-4.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
