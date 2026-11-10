# Source

GenTel-Bench goal-hijacking and prompt-leaking attacks (label 1). Out-of-sample attacks: no FN-mine corpus is mined from them.

Upstream (pinned):

- https://huggingface.co/datasets/GenTelLab/gentelbench-v1/tree/bf27033065d75b7622b5a971470d8d0fbc3fa444 (apache-2.0)

Kept: distinct rows in content-hash order up to 1500 ; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-oos-corpora.py --write` (pyarrow needed for the Hugging Face corpora).
