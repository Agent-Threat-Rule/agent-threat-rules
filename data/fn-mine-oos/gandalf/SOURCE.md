# Source

Gandalf instruction-override prompts, human-written. Out-of-sample attacks: no FN-mine corpus is mined from them.

Upstream (pinned):

- https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions/tree/04737b65e90a6794ec227012e4a255a7def6344b (mit)

Kept: distinct rows in content-hash order up to 1500 ; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-oos-corpora.py --write` (pyarrow needed for the Hugging Face corpora).
