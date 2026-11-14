# Source

Benign only: the Jinja chat and tool-calling templates vLLM ships, as a file-read tool returns them.

Upstream (pinned):

- https://github.com/vllm-project/vllm/tree/3d091b6f05f5ab3e688ce4bbe0c453de0646a069 (Apache-2.0)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
