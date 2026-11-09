# Source

Injections that try to make a crypto-wallet agent transfer funds or reveal keys, with benign wallet requests.

Upstream (pinned):

- https://huggingface.co/datasets/aaronbassett/wallet-prompt-injection/tree/eba3c6f941d9ab11566f74314857ca20c4562189 (mit)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
