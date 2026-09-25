# Red Team Probe Proposals

This directory holds **draft ATR rule proposals** created from red-team
probe submissions.

## How a file lands here

1. A red-team researcher opens an issue using the
   [Red Team Probe Submission](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=red-team-probe.yml)
   template, with ≥3 positive examples and ≥3 negative (benign) examples.
2. A maintainer reviews the issue and, if it is accepted, writes the
   proposal to `proposals/red-team-probes/<slug>.proposal.yaml` and opens a
   **draft PR**.
3. A maintainer writes the detection regex. The submitter can propose one
   in a PR comment or in a PR of their own. The
   [promotion criteria](#promotion-criteria) below list the remaining steps.

## Lifecycle of a proposal

| Stage | Where the file lives | Status |
|---|---|---|
| Submitted | `proposals/red-team-probes/<slug>.proposal.yaml` | `status: draft`, `detection.conditions: []` |
| Regex drafted | same path, same PR branch | `detection.conditions: [...]` filled in |
| FP gate passed | same path | `check-rules-safety.ts` shows 0 FP on the 432-skill benign corpus |
| Promoted | `rules/<category>/ATR-2026-NNNNN-<slug>.yaml` | `status: experimental`, real ATR id assigned |
| Stable | same `rules/` path | `status: stable` after ≥30 days production observation, 0 FP reports |

## Why proposals live in their own directory

The engine in `src/engine.ts` only loads YAML files under `rules/`.
Anything in `proposals/` is invisible to consumers — exactly what you
want for half-finished detection logic. CI runs the schema validator
against proposals too, so a malformed proposal still fails fast, but
nobody is shipping a draft rule by accident.

## Promotion criteria

A maintainer should only move a file out of `proposals/red-team-probes/`
and into `rules/<category>/` when ALL of the following hold:

- [ ] `detection.conditions` is non-empty and matches every
      `test_cases.true_positives` entry.
- [ ] `detection.conditions` rejects every `test_cases.true_negatives`
      entry.
- [ ] `npx tsx scripts/check-rules-safety.ts <proposal path>` shows
      0 false positives on `data/skill-benchmark/benign/` (432 skills).
- [ ] The rule has the next free `ATR-2026-NNNNN` id assigned.
- [ ] `metadata_provenance.discovered_by` is preserved verbatim from the
      submission. The submitter is named in the `author` field (alongside
      `ATR Community`).
- [ ] CI (`validate.yml`, `rule-quality.yml`) passes on the PR.

The proposal file is deleted at the moment of promotion — the rule file
replaces it. The originating issue is closed by the promotion commit
via `Closes #N` in the message.
