# Source

Benign only: llama.cpp documentation on function calling and the server, including chat-template formats.

Upstream (pinned):

- https://github.com/ggml-org/llama.cpp/tree/ded522f8304554317e7ff8f88698dbbbca5425aa (MIT)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
