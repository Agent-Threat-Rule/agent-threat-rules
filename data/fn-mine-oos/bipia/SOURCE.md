# Source

BIPIA text and code attack instructions, as planted in emails, tables and documents: bare requests with no wrapper. Out-of-sample attacks: no FN-mine corpus is mined from them.

Upstream (pinned):

- https://github.com/microsoft/BIPIA/tree/a004b69ec0dd446e0afd461d98cb5e96e120a5d0 (MIT)

Kept: distinct rows in content-hash order up to 1500 ; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-oos-corpora.py --write` (pyarrow needed for the Hugging Face corpora).
