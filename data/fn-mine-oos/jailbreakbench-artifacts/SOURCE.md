# Source

JailbreakBench submitted jailbreaks (PAIR, random search, jailbreakchat templates, GCG transfer).

Upstream (pinned):

- https://github.com/JailbreakBench/artifacts/tree/909e68c01d94222b8ad2e397a017e2e12e2adb73 (MIT)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
