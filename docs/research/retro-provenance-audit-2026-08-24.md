# Applying the authoring standard backward

**Date:** 2026-08-24 · **Ruleset:** 785 rules at `origin/main` 53c84daaf (v4.0.0 line) · **Lane:** `hunt`

`RULE-PRODUCTION.md` writes down what a rule has to satisfy to get merged. Every
gate in CI runs against rules arriving in a pull request, so a rule that predates
a gate has never been asked to satisfy it. This asks the whole ruleset at once.

Reproduce: `npx tsx scripts/audit-rule-provenance.ts --json out.json`
(the control asserts engine-loaded == on-disk, a known attack fires, a plain
sentence does not; it exits 1 and prints no table if any of those fail).

## The finding: a check with nothing to check

`check-rules-safety.ts` verifies that a new rule matches its own true positives.
`extractTruePositives` read one shape:

```ts
tps.map((t) => (typeof t === "string" ? t : (t?.input ?? "")))
```

Most rules do write `- input: "..."`. **38 rules key the case by the detection
field instead** — `tool_args`, `user_input`, `tool_description`,
`tool_response`, `tool_name`, `agent_output`, `content` — and 8 more mix both
shapes. For those the extractor returned an empty list, so the check iterated
nothing and passed.

That is a zero from a population that could not have produced a one — the
failure `corpus-visibility` exists to prevent on the benign side. There was no
equivalent guard here.

Two of the rules it was silent about are `maturity: stable`, i.e. the enforce
lane, and both carry `strength: primary` compliance claims against OWASP
LLM02:2025, NIST AI RMF MS.2.7, EU AI Act Article 15, and ISO/IEC 42001 8.1 and
6.2: `ATR-2026-01601` and `ATR-2026-01602`. Both do carry true positives and do
match them. The defect was never that they were untested — it was that the gate
could not see the tests, so nobody could have known either way.

## Getting the fix right took two attempts

**Reading only `input` was too narrow**, as above.

**Reading every string was too wide.** A case often carries context alongside
the payload:

```yaml
- tool_name: execute_shell
  tool_args: "{\"command\": \"cat /etc/passwd\"}"
```

`tool_name` is a registered `UNMEASURABLE_FIELD` in `corpus-event.ts`, and the
reason given there is the right one: production `tool_name` is a short
identifier, not a document, and pouring corpus text into it would fabricate
false positives on rules that are correct in production. The harness therefore
never fills it — so treating `execute_shell` as a payload makes a correct rule
look like it misses its own test case. That produced three false failures,
`ATR-2026-00040`, `ATR-2026-00060` and `ATR-2026-00012`, none of which is a
defect.

The extractor now takes `input`, bare strings, and any key in `MEASURED_FIELDS`,
and nothing else.

## Blast radius, after both corrections

**No rule turns out to lack true positives.** Nine declare measurable ones and
fail to match them:

| rule | unmatched | maturity |
| --- | --- | --- |
| `ATR-2026-00495` | 8 of 8 | test |
| `ATR-2026-00235` | 5 of 5 | test |
| `ATR-2026-00070` | 5 of 5 | test |
| `ATR-2026-00548`–`00553` | 5 of 5 each | draft |

All nine are `draft` or `test`. They predate this change, and no rule that
blocks anything today changes behaviour.

## Eight rules the check still cannot reach

Some rules declare true positives that live *entirely* on `tool_name`:
`ATR-2026-00060` through `ATR-2026-00066` — the whole `skill-compromise` family
— plus `ATR-2026-00099`.

Their test cases are exactly right for what they detect: `filesytem_read`,
`gtihub-api`, `slakc-send` are typosquats, and the typosquat *is* the attack.
The harness cannot present them, so **this family's true positives have never
been verified here.**

That is not fixed by making `tool_name` measurable; the reason it is
unmeasurable is sound. It is fixed, if it is worth fixing, by a check that
builds the event from the field each case names — a different harness from this
one. Until then the gate prints the list rather than counting them as passes,
which is the `corpus-visibility` discipline applied to this side.

## Whole-ruleset result, split by the §10 provenance classifier

| check | corpus (288) | vuln (64) | generic (433) | all (785) |
| --- | ---: | ---: | ---: | ---: |
| has measurable `true_positives` | 288 | 64 | 425 | 777 |
| has `true_negatives` | 288 | 64 | 427 | 779 |
| matches its own TPs | 286 | 64 | 418 | 768 |
| self-TP check non-vacuous upstream (before the fix) | 287 | 64 | 398 | 749 |
| exactly one ATLAS technique | 92 | 50 | 238 | 380 |
| declares any ATLAS technique | 288 | 64 | 433 | 785 |
| measurable (no `trace.*`/`behavioral.*` under `all`) | 288 | 64 | 433 | 785 |

Unsourced provenance is a mild predictor of failure, not a dramatic one: 99.3%
of the corpus bucket and 100% of the vuln bucket match their own true positives,
against 96.5% of the bucket whose `author:` names no source.

## A coverage gap the missing check was hiding

`ATR-2026-01601`'s single-quote branch was `';` while its double-quote branch
was `"\s*;`. A payload with whitespace between the quote and the separator —
`1' ; TRUNCATE TABLE accounts; --` — matched neither, so DROP, TRUNCATE and
unbounded DELETE all escaped in that form. The description names all three.

Fixed by allowing `'\s*;`, bringing the single-quote branch in line with the
double-quote branch it was already inconsistent with, plus two true positives
for the spaced form. Verified silent on `How do I drop a table in PostgreSQL?`,
a parameterised `SELECT`, `We should drop the legacy table after the migration
completes.`, and `The report's ; delimiter needs fixing before we delete from
staging.`

Note the rule's own true positives all used the unspaced form, so even a working
self-TP check would not have caught this. What catches it is a test case for the
case the description names.

## What is left

1. The nine `draft`/`test` rules that fail the now-real check.
2. The eight rules whose true positives sit on `tool_name`, unverified.
3. The 405 rules declaring more than one ATLAS technique — a softer finding,
   since §5's "one technique per rule" is about detection scope and multi-tagging
   is sometimes legitimate, but that is the population to look at when a rule
   cannot be demoted or retired cleanly.
