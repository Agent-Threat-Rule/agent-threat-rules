# Source

PyRIT jailbreak templates (persona, developer mode, refusal suppression), placeholder filled with a system-prompt request.

Upstream (pinned):

- https://github.com/microsoft/PyRIT/tree/c98bdd8ec657696b59a48dea8f19a5634cfa53f7 (MIT)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
