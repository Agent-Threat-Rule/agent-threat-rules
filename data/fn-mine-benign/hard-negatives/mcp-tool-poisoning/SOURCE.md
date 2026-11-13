# Source

Poisoned MCP tool descriptions (override, exfiltration, stealth) with the clean description of the same tool.

Upstream (pinned):

- https://huggingface.co/datasets/fevziegeyurtsevenler/mcp-tool-poisoning/tree/9b7a1088526d424c518d856ba5204f935a279727 (apache-2.0)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
