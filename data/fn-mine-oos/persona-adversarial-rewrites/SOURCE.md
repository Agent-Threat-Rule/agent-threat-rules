# Source

Adversarial rewrites of a request by strategy (typos, output encoding, role-play), written in a generated persona.

Upstream (pinned):

- https://huggingface.co/datasets/antoniopelusi/redteaming/tree/75345c1693a9f1d8599fd65957671c81e64ec64c (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
