# Source

Agent-security test inputs by category (injection, jailbreak, exfiltration, tool abuse, multi-agent), with over-refusal prompts as benign.

Upstream (pinned):

- https://github.com/doronp/agentshield-benchmark/tree/235b6e3acacee6f54824c797a628e027ea5620ca (Apache-2.0)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
