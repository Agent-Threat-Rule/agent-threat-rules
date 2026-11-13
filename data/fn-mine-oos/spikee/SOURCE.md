# Source

Spikee jailbreak templates filled with its instructions (mailbox exfiltration, cybersecurity, system-prompt extraction). Out-of-sample attacks: no FN-mine corpus is mined from them.

Upstream (pinned):

- https://github.com/WithSecureLabs/spikee/tree/73130ff2630fb4052deee5ebfbab09b7f6592327 (Apache-2.0)

Kept: distinct rows in content-hash order up to 1500 ; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-oos-corpora.py --write` (pyarrow needed for the Hugging Face corpora).
