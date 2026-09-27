# Wild Ecosystem Scan — Flagged Findings (2026-04)

Companion dataset: `wild-scan-findings-2026-04.csv`

## What this is
The flagged-findings export from a wild scan of public AI-agent skill / MCP
ecosystems, run with the ATR detection engine. Provided as independently
citable evidence that agentic-skill threat classes occur in production
registries — not as a synthetic test.

## Scan
- Source snapshot: `data/full-scan-v2-2026-04-14.json` (in this repo — the CSV is a
  flattened view of it; re-derivable from it)
- Items scanned: 101,280 skills / MCP definitions across 5 registries
  (OpenClaw, ClawHub, Skills.sh, Hermes, MCP Registry)
- Engine at scan time: ATR v2.0.0 (113 rules). The engine has since grown to 655
  rules; this snapshot reflects the engine as it was when the scan ran.

## Results
- Flagged files: 1,434  (1,507 rule-matches)
- Severity of matches: 1,210 critical, 282 high, 15 medium
- Concentration: 552 of the flagged files belong to 2 coordinated threat-actor
  accounts (hightower6eu 354, sakaen736jih 198). Recount from the scan data
  rather than citing this line:
  `grep -oE '(hightower6eu|sakaen736jih)' data/full-scan-v2-2026-04-14.json | sort | uniq -c`
- A separate published campaign analysis reported 751 skills as malicious
  (see docs/research/96k-scan-751-malware-article.md — the filename is
  historical; that article now carries an ERRATUM giving the 101,280 / 1,434
  figures of record). **That count is frozen and is not citable as current
  fact.** Per the same ERRATUM it is a triage floor, not a precision figure: a
  manual determination layered on the flagged set, not a measurement of this
  scan. This CSV is the raw flagged output, not the curated 751.

## CSV schema
registry, file, publisher, rule_id, category, severity, detection, threat_actor_account

`category` is resolved from current ATR rule metadata; `threat_actor_account` is
`yes` for files under the three accounts above.

## Responsible disclosure
No attack payload strings are included — only the rule id, category, and detection
title. The matched malicious content is not redistributed.

## Reproduce
Re-run the engine over a corpus to reproduce flagging; the source scan output is in
`data/full-scan-v2-2026-04-14.json`. Benchmark accuracy is measured separately via
`npm run eval` (see `data/measurements/`).

License: MIT. ATR is an independent open standard.
