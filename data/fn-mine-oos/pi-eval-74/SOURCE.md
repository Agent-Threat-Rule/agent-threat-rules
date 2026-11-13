# Source

Injections by category (system impersonation, override, exfiltration) with clean factual sentences.

Upstream (pinned):

- https://huggingface.co/datasets/mukunda1729/prompt-injection-eval/tree/1b709002907d3b9a4097ff332d9d5ab4fee499cd (mit)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
