# Source

Agent Security Bench observation prompt injections: its five templates around its attacker-tool instructions, appended to a tool response. Out-of-sample attacks: no FN-mine corpus is mined from them.

Upstream (pinned):

- https://github.com/agiresearch/ASB/tree/544540ff0788998072f7df463056fd17e62cc9f4 (MIT)

Kept: distinct rows in content-hash order up to 1500 ; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-oos-corpora.py --write` (pyarrow needed for the Hugging Face corpora).
