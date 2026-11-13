# Source

Mosscap game prompts that carry a forged boundary, role tag, chat-template token or override, human-written. Out-of-sample attacks: no FN-mine corpus is mined from them.

Upstream (pinned):

- https://huggingface.co/datasets/Lakera/mosscap_prompt_injection/tree/b7e495ff63373ff7f7dabc1e9390cf62b5838570 (mit)

Kept: distinct rows in content-hash order up to 1500 ; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-oos-corpora.py --write` (pyarrow needed for the Hugging Face corpora).
