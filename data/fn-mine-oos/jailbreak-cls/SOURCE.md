# Source

jackhhao jailbreak-classification, type jailbreak. Out-of-sample attacks: no FN-mine corpus is mined from them.

Upstream (pinned):

- https://huggingface.co/datasets/jackhhao/jailbreak-classification/tree/2f2ceeb39658696fd3f462403562b6eea5306287 (apache-2.0)

Kept: distinct rows in content-hash order up to 1500 ; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-oos-corpora.py --write` (pyarrow needed for the Hugging Face corpora).
