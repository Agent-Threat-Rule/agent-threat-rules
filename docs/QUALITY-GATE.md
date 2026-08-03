# ATR Quality Gate

> Every rule in `rules/` passes this gate before it can ship. Production
> consumers (Microsoft Agent Governance Toolkit, Cisco AI Defense
> skill-scanner, MISP, OWASP A-S-R-H) auto-sync from `rules/`, so a bad
> rule blast-radiuses across the whole AI-security ecosystem within
> hours. The gate is what keeps that from happening.

## The 6 pre-merge checks

`scripts/check-rules-safety.ts` runs all six on every PR that touches
`rules/`. Auto-merge requires all six green. Any failure → label
`needs-human-review` and the PR sits in the maintainer queue.

| #   | Check                  | What it catches                                                                                                                                                                                                                                                                             |
| --- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Metadata complete      | Rule has author, test_cases.true_positives ≥1, test_cases.true_negatives ≥1, valid id. Blocks `MiroFish Predicted` authorship (a deprecated draft tier).                                                                                                                                    |
| 2   | Own TPs must match     | The rule's own `detection.conditions` must actually fire on every entry in its own `test_cases.true_positives`. Catches broken regex that wouldn't detect what it claims to detect.                                                                                                         |
| 3   | Benign-skill corpus FP | Rule must produce 0 matches across `data/skill-benchmark/benign/*.md` — currently 432 known-clean SKILL.md samples. This is the original FP gate; it catches "rule that fires on legitimate skill descriptions."                                                                            |
| 4   | Research-mention FP    | Rule must produce 0 matches across `data/research-mentions/corpus.jsonl` — curated text that MENTIONS attacks but isn't an attack (academic abstracts, security blog posts, READMEs, course material, CVE descriptions). This catches "rule that fires on the paper describing the attack." |
| 5   | Cross-rule conflict    | Rule must NOT match any OTHER existing rule's `test_cases.true_negatives`. If new rule X fires on existing rule Y's known-benign set, Y just regressed in precision and a human needs to look at the overlap.                                                                               |
| 6   | Per-PR cap             | ≤ `MAX_NEW_PER_PR` rule files in one PR (default 10). Forces large batches to be split into reviewable chunks.                                                                                                                                                                              |

Implementation lives at [`scripts/check-rules-safety.ts`](../scripts/check-rules-safety.ts).
The script supports two modes:

```bash
# CI mode: scan for new rule files (git diff vs base, PLUS uncommitted files on disk)
npx tsx scripts/check-rules-safety.ts --base origin/main

# Single-file mode: validate one proposal in isolation
npx tsx scripts/check-rules-safety.ts --file proposals/red-team-probes/foo.proposal.yaml
```

New-rule discovery is **not diff-only**. `git diff base...HEAD` sees committed
files, and rules are routinely written into `rules/` and gated before any commit
(`scripts/fn-mine-llm.ts` authors straight into the tree, then calls this gate).
Those rules were invisible: the gate printed `0 new rule file(s) detected —
nothing to check, treating as safe` and exited 0 while skipping all six checks.
Discovery now unions the diff with `git ls-files --others --exclude-standard --
rules/`, so a rule on disk is measured whether or not git has heard of it.

## Counting rules honestly

Two numbers, both true, not interchangeable:

| Number      | Means                                                 |
| ----------- | ----------------------------------------------------- |
| `total`     | rule files on disk                                     |
| `effective` | rules the engine loads AND that can fire in some lane   |

`inert = total - effective` is the rules with `status: draft` / `deprecated`
(or `maturity: deprecated`). Quoting `total` as detection coverage overstates
it by exactly `inert`. Both are computed by
[`scripts/reconcile-rule-count.mjs`](../scripts/reconcile-rule-count.mjs) and
published into `stats.json` / `data/stats.json`:

```bash
npm run count:rules      # print total / effective / inert / lane ceilings
npm run reconcile-stats  # write them into both caches
```

## The status gate: a rule must be able to fire

`status: draft` means the rule does not exist. `src/engine.ts` skips draft and
deprecated rules in **both** evaluation paths, before the lane gate and before
any pattern is compiled — so a draft rule fires in no lane, ever, including
`hunt`. Nothing in validation, testing, or the six checks above says so: the
rule validates, its test_cases pass (the tooling promotes drafts in memory
before testing them), and it ships inert.

`.github/workflows/rule-status-gate.yml` closes that. It is a **ratchet**, in the
shape of the maturity-FP and RE2 gates:

- a rule carrying `status: draft` that is not in
  `data/rule-status-baseline.json` fails the build;
- the recorded backlog passes, and drains on its own schedule;
- `--write-baseline` can only **shrink** the baseline. Widening is the one edit
  that would make the gate lie, so a genuine new exception must be hand-written
  where review can see it.

It compares the whole working tree, not a PR diff, because rules also arrive via
the CVE collector and auto-crystallize, which commit straight to main.

```bash
npx tsx scripts/gate-rule-status.ts             # gate
npx tsx scripts/gate-rule-status.ts --json      # machine-readable
npx tsx scripts/gate-rule-status.ts --write-baseline   # tighten after reviving rules
```

**Express immaturity with `maturity`, never with `status`.** The maturity ladder
below is what the lane gate reads: `stable` reaches the enforce (auto-block)
lane, `test` reaches alert, everything else stays hunt-only. A new rule should be
`status: experimental` + a low maturity — alive, and confined to the advisory
lane. `RuleScaffolder` emits exactly that.

## The maturity ladder

Passing the gate gets a rule into `rules/` at `maturity: experimental`.
Three more levels follow.

| Maturity       | Time in main | FP reports | Promotion criteria                                                                                                          |
| -------------- | ------------ | ---------- | --------------------------------------------------------------------------------------------------------------------------- |
| `experimental` | 0–30 days    | n/a        | Passed the gate. Default for any rule auto-generated by CVE collector, probe pipeline, or TC crystallization.               |
| `test`         | 30+ days     | 0          | Maintainer review + 0 FP reports filed against this rule. Auto-promoted by `quality-upgrade.ts` cron.                       |
| `stable`       | 60+ days     | 0          | Two maintainer approvals + 0 FP reports + ≥1 confirmed in-the-wild match. This is the bar production consumers should sync. |
| `deprecated`   | any          | n/a        | Manually demoted when a better-coverage replacement ships. Engine still loads but emits a warning.                          |

The maturity field is the contract with downstream consumers. See
[DOWNSTREAM-SYNC-CONTRACT.md](DOWNSTREAM-SYNC-CONTRACT.md) for the
recommended filter.

## Why these particular checks

Detection rules have one failure mode that matters: **firing on text
that isn't an attack**. Five families of FP source cover ~95% of real
incidents:

1. **Legitimate skill / tool descriptions** — caught by Check 3.
   Example: a skill called `system-override-helper` that's a real
   admin utility.
2. **Research papers, blog posts, READMEs** — caught by Check 4.
   Example: the abstract of _"DAN Jailbreaks: A Systematic Survey"_
   mentions every attack pattern verbatim.
3. **One rule eating another's territory** — caught by Check 5.
   Example: a new "credential exfil" rule starts firing on the existing
   "configuration documentation" rule's TNs.
4. **Broken regex** — caught by Check 2. Example: rule claims to
   detect pattern X but the regex is malformed and never fires on X.
5. **Sloppy authorship** — caught by Check 1. Example: missing
   true_negatives → no precision signal → can't be tested at all.

Each check is cheap (sub-second per rule). The full gate runs in
<10 seconds against the current corpus.

## Adding to the research-mention corpus

The research-mention corpus is the easiest one to grow safely.

1. Find a published piece of text that DESCRIBES an attack pattern
   without BEING an attack — paper abstract, blog post paragraph,
   README defence section, course module description, CVE advisory.
2. Trim to 1–3 sentences. Longer dilutes the FP signal.
3. Append a JSONL line to `data/research-mentions/corpus.jsonl` with
   `text`, `category`, `source_type`, and `source_url` when possible.
4. Open a PR. Existing rules are automatically re-validated against
   the new sample via Check 4.

See [`data/research-mentions/README.md`](../data/research-mentions/README.md)
for the schema and current source-type distribution.

## When the gate fails

A PR that fails the gate gets the `needs-human-review` label. The
maintainer should:

1. **Read the failure reason.** The script prints exact rule ID +
   exact failing sample (truncated) for every failure.
2. **Tighten the regex** to exclude the failing sample, OR
3. **Add the failing sample to the rule's own true_negatives** so the
   precision signal is preserved in the test, OR
4. **Decide the gate is wrong for this rule** — e.g. a research-mention
   sample is too aggressive. Open a separate PR removing/editing that
   sample with justification, then re-run the gate.

The gate is meant to be tight but not infallible. Disagreements get
resolved in PR review, not silenced.

## Roadmap (Phase 2)

| Item                                                              | Status                                       |
| ----------------------------------------------------------------- | -------------------------------------------- |
| 30-day FP-probation auto-promotion (experimental → test)          | Spec only                                    |
| 60-day auto-promotion (test → stable) with ≥1 wild match required | Spec only                                    |
| Telemetry feedback loop from downstream consumers                 | Spec only — requires AGT / Cisco cooperation |
| Expanded benign corpus 432 → 5000 via arxiv + README ingest       | Sized but not built                          |
| `response.actions: shadow` default for auto-generated rules       | Spec only                                    |
| Confidence threshold per consumer (AGT > 0.8, Cisco > 0.6)        | Spec only                                    |

When any of these ship, this doc gets a `## What's new` section with
the change.
