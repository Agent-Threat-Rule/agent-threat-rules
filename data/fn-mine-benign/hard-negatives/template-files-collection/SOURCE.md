# Source

Benign only: a collection of chat templates for open models (ChatML, Llama 2 and 3, Gemma, Mistral, Phi) and its README.

Upstream (pinned):

- https://github.com/chujiezheng/chat_templates/tree/11c495621569969f264ee70b5c8bb49ba7a1a410 (MIT)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
