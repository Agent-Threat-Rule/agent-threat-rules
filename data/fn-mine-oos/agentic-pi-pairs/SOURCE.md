# Source

Agentic injections (prompt extraction, role-play, tool abuse, authority claims) each paired with a benign twin on the same topic.

Upstream (pinned):

- https://huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-boundary-pairs/tree/a5682e7573e1c7bc4b12e64d49c0dcd90ca776cf (cc-by-4.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
