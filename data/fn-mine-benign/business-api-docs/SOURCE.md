# Source

Operation summaries and descriptions of public business APIs (education, HR, payroll, accounting, tickets and tasks, messaging, scheduling, e-signature), as a docs or API-search tool returns them: benign text that names the actions an injection asks for.

Upstream (pinned):

- https://github.com/APIs-guru/openapi-directory/tree/f04b8d0bcd39c52e1cf3ad7a5fe744709832ae49 (CC0-1.0)

Kept: distinct rows in content-hash order up to 160 per API; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-oos-corpora.py --write` (pyarrow needed for the Hugging Face corpora).
