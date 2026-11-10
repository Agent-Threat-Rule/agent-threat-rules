# Source

Injections planted in real web pages a browsing agent reads (same-origin and cross-origin, inbound and outbound).

Upstream (pinned):

- https://huggingface.co/datasets/umariqbal/web-agent-attack-benchmark/tree/961bc7f170d91bd8009607a91df23a8f8d953ade (cc-by-4.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
