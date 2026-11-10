# Source

Guardrail evaluation inputs: persona overrides and instruction-format jailbreaks to block, ordinary requests to allow.

Upstream (pinned):

- https://huggingface.co/datasets/CaiZhiTech/Evaluation-Dataset-of-AI-Agent-Security-Guardrails/tree/41874d216e759b2a445c9453908a40a35b0f474d (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
