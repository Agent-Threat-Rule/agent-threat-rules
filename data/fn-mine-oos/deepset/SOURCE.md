# Source

deepset prompt-injections, label 1. Out-of-sample attacks: no FN-mine corpus is mined from them.

Upstream (pinned):

- https://huggingface.co/datasets/deepset/prompt-injections/tree/4f61ecb038e9c3fb77e21034b22511b523772cdd (apache-2.0)

Kept: distinct rows in content-hash order up to 1500 ; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-oos-corpora.py --write` (pyarrow needed for the Hugging Face corpora).
