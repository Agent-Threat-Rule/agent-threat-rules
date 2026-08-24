# Applying the authoring standard backward

**Date:** 2026-08-24 · **Ruleset:** 785 rules at `origin/main` 53c84daaf (v4.0.0 line) · **Lane:** `hunt`

`RULE-PRODUCTION.md` writes down what a rule has to satisfy to get merged. Every
gate in CI runs against rules arriving in a pull request, so a rule that predates
a gate has never been asked to satisfy it. This asks the whole ruleset at once.

Reproduce: `npx tsx scripts/audit-rule-provenance.ts --json out.json`
(the control asserts engine-loaded == on-disk, a known attack fires, a plain
sentence does not; it exits 1 and prints no table if any of those fail).

## Result, split by the §10 provenance classifier

| check | corpus (288) | vuln (64) | generic (433) | all (785) |
| --- | ---: | ---: | ---: | ---: |
| has `true_positives` | 287 | 64 | **390** | 741 |
| has `true_negatives` | 287 | 64 | **396** | 747 |
| matches its own TPs | 285 | 64 | **383** | 732 |
| exactly one ATLAS technique | 92 | 50 | 238 | 380 |
| declares any ATLAS technique | 288 | 64 | 433 | 785 |
| measurable (no `trace.*`/`behavioral.*` under `all`) | 288 | 64 | 433 | 785 |

**Unsourced provenance predicts failure.** On "matches its own TPs" the corpus
bucket passes 98.9% and the vuln bucket 100%, against 88.5% for the bucket whose
`author:` names no source — roughly a tenfold difference in failure rate. That is
the answer to the question the split was built to ask.

## The 53 rules that fail, separated

They are not one problem. 44 rules declare no true positives at all, and 9
declare some and do not match them. The second group is entirely `draft` (6) and
`test` (3), so none of them is live: the engine skips `draft`, and `test` never
reaches the enforce lane.

The first group is where the finding is. Of the 44, 36 are `test` and 6
`experimental` — but **two are `maturity: stable`**, which is the enforce lane,
which is auto-block:

| rule | what it claims |
| --- | --- |
| `ATR-2026-01601` | SQL injection destructive DDL — "DROP TABLE, TRUNCATE TABLE, or unbounded DELETE FROM" |
| `ATR-2026-01602` | SQL injection UNION SELECT exfiltration |

Both carry `strength: primary` compliance claims against OWASP LLM02:2025,
NIST AI RMF MS.2.7, EU AI Act Article 15, and ISO/IEC 42001 clauses 8.1 and 6.2.
So a rule with no test case asserting it detects anything is auto-blocking
traffic and is cited as primary evidence for five frameworks.

### They are not inert, and one under-delivers against its own description

Probed directly:

| input | `01601` | `01602` |
| --- | --- | --- |
| `'; DROP TABLE users; --` | fires | — |
| `1' ; TRUNCATE TABLE accounts; --` | **silent** | — |
| `' UNION SELECT username, password FROM credentials --` | — | fires |
| `SELECT name, total FROM orders WHERE region = 'APAC'` | silent | silent |
| `We should drop the legacy table after the migration completes.` | silent | silent |

`01601`'s description names TRUNCATE TABLE explicitly and does not detect it.
That is a one-line true-positive away from being caught at authoring time, which
is the whole cost of shipping without one.

## What to do with this

1. The two `stable` zero-TP rules need true positives, and `01601` needs the
   TRUNCATE and unbounded-DELETE cases its description already promises — or the
   description narrowed to what it does.
2. `has true_positives` is a cheap CI gate that nothing currently enforces
   repo-wide. 44 rules would fail it today.
3. The 405 rules declaring more than one ATLAS technique are a softer finding —
   §5's "one technique per rule" is about detection scope and multi-tagging is
   sometimes legitimate — but it is the population to look at when a rule cannot
   be demoted or retired cleanly.
