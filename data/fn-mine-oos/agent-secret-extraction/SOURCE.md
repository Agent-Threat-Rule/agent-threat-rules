# Source

Prompts that try to extract an agent's system prompt and secrets (direct asking, role-play, gradual extraction, encoding).

Upstream (pinned):

- https://huggingface.co/datasets/Dhanjo/ai-agent-security-dataset/tree/a6a9111cefe7a11fd73710636986e0199be48be8 (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
