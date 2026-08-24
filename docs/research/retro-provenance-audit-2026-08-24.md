# Applying the authoring standard backward

**Date:** 2026-08-24 · **Ruleset:** 785 rules at `origin/main` 53c84daaf (v4.0.0 line) · **Lane:** `hunt`

`RULE-PRODUCTION.md` writes down what a rule has to satisfy to get merged. Every
gate in CI runs against rules arriving in a pull request, so a rule that predates
a gate has never been asked to satisfy it. This asks the whole ruleset at once.

Reproduce: `npx tsx scripts/audit-rule-provenance.ts --json out.json`
(the control asserts engine-loaded == on-disk, a known attack fires, a plain
sentence does not; it exits 1 and prints no table if any of those fail).

## The finding: a gate that had nothing to test

`check-rules-safety.ts` verifies that a new rule matches its own true positives.
`extractTruePositives` read one shape:

```ts
tps.map((t) => (typeof t === "string" ? t : (t?.input ?? "")))
```

Most rules do write `- input: "..."`. **38 rules key the case by the detection
field instead** — `tool_args`, `user_input`, `tool_description`,
`tool_response`, `tool_name`, `agent_output`, `content` — and 8 more mix the two
shapes. For those, the extractor returned an empty list, so the check iterated
nothing and passed.

That is a zero from a population that could not have produced a one, which is
exactly the failure the `corpus-visibility` gate exists to prevent on the benign
side. There was no equivalent guard on this side.

**Two of the rules the check was silent about are `maturity: stable`** — the
enforce lane, auto-block — and both carry `strength: primary` compliance claims
against OWASP LLM02:2025, NIST AI RMF MS.2.7, EU AI Act Article 15, and ISO/IEC
42001 clauses 8.1 and 6.2:

| rule | |
| --- | --- |
| `ATR-2026-01601` | SQL injection destructive DDL |
| `ATR-2026-01602` | SQL injection UNION SELECT exfiltration |

Both do in fact carry four true positives each and do match them. The defect was
never that they were untested; it was that the gate could not see the tests, so
nobody could have known either way.

Fixing the extractor makes the check real for all 46 affected rules. Three of
them fail it: `ATR-2026-00040` (5 of 10 TPs unmatched), `ATR-2026-00060` (5 of
5), `ATR-2026-00012` (2 of 10). All three are `maturity: test`, so the enforce
lane is unaffected and no currently-blocking rule changes behaviour.

## Whole-ruleset result, split by the §10 provenance classifier

| check | corpus (288) | vuln (64) | generic (433) | all (785) |
| --- | ---: | ---: | ---: | ---: |
| has `true_positives` | 288 | 64 | 426 | 778 |
| has `true_negatives` | 288 | 64 | 433 | 785 |
| matches its own TPs | 286 | 64 | 416 | 766 |
| self-TP check non-vacuous upstream (before the fix) | 287 | 64 | 397 | 748 |
| exactly one ATLAS technique | 92 | 50 | 238 | 380 |
| declares any ATLAS technique | 288 | 64 | 433 | 785 |
| measurable (no `trace.*`/`behavioral.*` under `all`) | 288 | 64 | 433 | 785 |

Unsourced provenance is a mild predictor of failure but not a dramatic one:
99.3% of the corpus bucket and 100% of the vuln bucket match their own true
positives, against 96.1% of the bucket whose `author:` names no source. The
19 failures are 7 rules with no true positives at all and 12 that declare some
and do not match them; every one of the 19 is `draft` (6), `test` (12) or
`experimental` (1). **Nothing live fails this check.**

## A coverage gap the missing check was hiding

`ATR-2026-01601`'s single-quote branch was written `';` while its double-quote
branch was written `"\s*;`. A payload with whitespace between the quote and the
statement separator — `1' ; TRUNCATE TABLE accounts; --` — matched neither
branch, so DROP, TRUNCATE and unbounded DELETE all escaped in that form, and the
description promises all three. The rule's own true positives all happened to use
the unspaced form, so even a working self-TP check would not have caught this;
what would have caught it is a test case for the case the description names.

Fixed by allowing `'\s*;`, which brings the single-quote branch in line with the
double-quote branch it was already inconsistent with, plus two true positives
covering the spaced form. Verified silent on `How do I drop a table in
PostgreSQL?`, a normal parameterised `SELECT`, `We should drop the legacy table
after the migration completes.`, and the deliberately awkward `The report's ;
delimiter needs fixing before we delete from staging.`

## What is left

1. `ATR-2026-00040`, `ATR-2026-00060`, `ATR-2026-00012` fail the now-real check.
2. The 405 rules declaring more than one ATLAS technique are a softer finding —
   §5's "one technique per rule" is about detection scope and multi-tagging is
   sometimes legitimate — but that is the population to look at when a rule
   cannot be demoted or retired cleanly.
