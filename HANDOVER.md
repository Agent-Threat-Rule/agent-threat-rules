# Handover notes

Written 2026-09-22 for an incoming maintainer. This file is a snapshot of what is
broken, what is load-bearing, and what only lives in one person's head. It is not
a description of how the code works — that is [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Everything below was verified by running it on `main` on the date given. Where a
number appears, the command that produces it appears next to it. Do not trust a
number in this file that has no command beside it.

---

## 1. Verify the state yourself before trusting anything

```bash
find rules -name '*.yaml' | wc -l                     # rule files on disk
node scripts/reconcile-rule-count.mjs --report        # effective vs inert breakdown
npm view agent-threat-rules dist-tags                 # what consumers actually get
node -p "require('./package.json').version"           # what this checkout claims
```

These four disagree more often than you would expect, and every past public
misstatement traces back to quoting one without checking the others.

## 2. Known broken, with root cause

### 2.1 Nothing has auto-published since 2026-08-23, and the token is the smaller half

`main` and the git tag are at `v4.1.0`. npm `latest` is `4.0.0`. Every downstream
consumer is running a version that is behind `main`.

Two independent faults produced that, and fixing only the token will leave the
worse one in place.

**The auto-publish trigger cannot fire any more.** `publish-on-rules-merge.yml`
gates its only job on the head commit being bot-authored:

```yaml
if: github.event_name == 'workflow_dispatch' ||
    contains(github.event.head_commit.message, 'crystallized rules from Threat Cloud') ||
    github.event.head_commit.author.email == 'bot@agentthreatrule.org'
```

The comment above it says this "prevents human rule edits from triggering an
auto-publish", which was the intent. The consequence is that **a human-authored
security fix never publishes.** Check it:

```bash
gh run list --workflow publish-on-rules-merge.yml --limit 20 \
  --json createdAt,conclusion,event,displayTitle
```

Every `push` run back to at least 2026-08-15 is `skipped`, including the merge of
#531 — the commit that removed catastrophic backtracking from eight rules.

The precise reason is narrower than "the bot is gone", and worth stating exactly,
because the loose version sends you looking in the wrong place. The bot still
commits here:

```bash
git log origin/main --since=2026-09-01 --format='%ae|%s' | grep bot@agentthreatrule.org
```

Nine commits since 2026-09-01, all of them `chore(adopters)` or `chore(stats)`.
**None of them touch `rules/`**, and the trigger carries `paths: ['rules/**']`, so
the `paths` filter excludes every commit the author filter would have admitted.
Meanwhile no commit since 2026-08-01 carries the `crystallized rules from Threat
Cloud` message that the second clause looks for:

```bash
git log origin/main --since=2026-08-01 --format='%s' | grep -c 'crystallized rules from Threat Cloud'
# 0
```

So the condition is not unsatisfiable in principle — **the intersection of
`paths: rules/**` and `author == bot` is empty in practice**, and has been for at
least six weeks. Rule commits here are written by people; bot commits here never
touch rules.

That is because the side that produces crystallized rule commits runs outside
this repository, in infrastructure this repository does not control and most
contributors cannot see. Whether that arrangement should continue is a governance
question for an open standard, not a CI question, and it is not settled here.

What is settled: **`workflow_dispatch` is the first clause of that `if`**, so a
manual dispatch does publish. The lane is not sealed, it just never fires on its
own for the changes that matter most.

**The credential then failed the one manual attempt.** The 2026-09-14
`workflow_dispatch` run built and tarballed fine and failed on the final PUT:

```
npm notice version: 4.1.0 / 2.3 MB / 1194 files
npm error code E404
npm error 404 Not Found - PUT https://registry.npmjs.org/agent-threat-rules
```

npm answers authentication failures with 404 rather than 401, so this is the
`NPM_TOKEN` repository secret being expired or under-scoped, not a missing
package. The secret was last updated 2026-05-29. **Fixing this needs a human with
an npm account**; it cannot be diagnosed further from inside CI.

**Two tagged versions exist that npm never received.** As of 2026-09-23:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/agent-threat-rules/4.1.0  # 404
curl -s -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/agent-threat-rules/4.1.1  # 404
curl -s https://registry.npmjs.org/agent-threat-rules | grep -o '"modified":"[^"]*"'   # 2026-08-23
```

`v4.1.0` failed on an expired credential. `v4.1.1` failed differently and more
instructively: the run reported success, printed `+ agent-threat-rules@4.1.1`,
and signed a provenance statement into the Sigstore transparency log — and the
version is still not on the registry. npm began restricting bypass-2FA granular
tokens on 2026-07-31 and is moving publishing to a stage-then-approve flow, so a
token scoped to stage-only publishes into a staging area that a human must
release with 2FA. **A green publish job is not evidence that a version shipped.**
Verify against the registry, not against the workflow.

**What actually works.** The last successful publish, 4.0.0 on 2026-08-23, went
out through `publish.yml` on a tag push. On that event it takes the version from
the tag without bumping, runs `npm run validate` (which
`publish-current-version.yml` does not), signs with `--provenance`, and creates
the GitHub Release. That is the path to use, and `--ref` must be `main` — the
`v4.1.0` tag predates the removal of the CLI's default telemetry endpoint, so
publishing from that tag would ship a build that reports to a vendor host by
default.

**The design question this leaves.** Whatever replaces the bot-author gate has to
distinguish "a rules commit that should ship immediately" from "a rules commit
that should wait", without the answer being "only bots ship". A security fix is
the case that matters and it is the case currently excluded.

### 2.2 The evidence re-measurement gate has never once succeeded

`action-eligibility.yml`'s `reverify` job has run 45 times on schedule since
2026-08-09: 44 cancelled at the 90-minute ceiling, one still in flight, zero
successful (`gh run list --workflow action-eligibility.yml --event schedule
--limit 100`, checked 2026-09-22). It has two independent causes, and fixing only
the first will waste your time:

1. **It cannot finish.** The header comment's "~45 minutes" was estimated against
   a 5,352-sample benign corpus. `data/benign-fp-measurement.json` now carries
   13,848 samples. The work is roughly 825 rules x 13,848 samples x 5 shapes.
   Both axes only grow, so this will not recover on its own. A matrix split over
   `--ids` slices would preserve the semantics, since `gate-promotion-fp.ts`
   already accepts `--ids`.
2. **It would fail even if it finished.** The diff treats "rule is on disk but not
   yet in the evidence file" and "a number was edited by hand" as the same kind of
   drift. Disk is at 825, evidence at 793, so 32 rules land in that bucket
   automatically. Those need to be separate categories: tampering should mean
   "present in both, different `fp_count`".

Consequence: the evidence file's `generated_at` is frozen at 2026-09-02, so the
one thing this gate exists to prevent — silent number drift — has never actually
been enforced.

### 2.3 The benign gate used to read 432 of 467 samples (fixed 2026-09-22)

`loadBenignSkills()` in `scripts/check-rules-safety.ts` used a non-recursive
`readdirSync`, so the 35 files in `benign/ninja-legit/` sat in the corpus without
ever being charged against a rule. The loader now walks subdirectories and the gate
reports 467.

This is worth knowing because it moves a historical baseline: **any false-positive
measurement taken before 2026-09-22 was taken over 432 samples, not 467.** The 35
newly included samples were checked against all 825 rules at the time of the change
and produced zero matches, so no rule changed status as a result.

### 2.4 pyatr silently drops rules the TypeScript engine loads

Open as issue #331 since 2026-07-14. `pyatr` reports the same rule count as the TS
engine while discarding conditions whose regex it cannot compile, with no warning.
Measured effect: 12 conditions across 5 rules dropped, and 2 rules dead outright
in Python. Anything that quotes a Python-side detection rate is quoting a
different rule set than the TypeScript one.

### 2.5 The conformance suite could not run against its own engine

`SPEC.md` §12 makes this suite normative for ATR-Compatible claims and
`TRADEMARK.md` §5 makes it the basis for certification, but the runner invoked the
CLI with a flag the CLI does not accept and fed it a file type the CLI rejects,
so all 103 true-positive fixtures scored zero matches. The runner was repaired in
this handover pass; re-run it and read `conformance/v1.0/README.md` for the
current pass rate. Treat any historical "115/226" figure as an artifact of the
broken harness, not a measurement of the rules.

### 2.5 `npm test` rewrites a tracked data file

A test run regenerates `data/skill-benchmark/benchmark-report.json` in place, so
`git status` is dirty after every `npm test` and the file will eventually be
committed by accident. The committed copy is stale in a way that shows the
problem: it carries `rule_count: 785` and a 2026-08-23 timestamp, i.e. the v4.0.0
corpus, while disk has 825.

That matters beyond tidiness, because the file also carries `avg_latency_ms` and
`max_latency_ms`. Those are machine-dependent — the same run on a laptop and on a
CI runner differ by more than a factor of two — so whoever commits it last sets
the project's published latency figures to whatever their hardware did that day.
Either make the test write to a temp path, or regenerate the file deliberately on
CI and nowhere else.

## 3. Traps that have already cost someone a day

- **`new ATREngine(...)` does not load rules.** You must `await engine.loadRules()`.
  Forgetting it produces zero matches silently, with no error, and reads exactly
  like "the product is broken". Use `data/skill-benchmark` as a positive control
  whenever a scan returns nothing.
- **`scripts/` is outside `tsconfig.json`'s `include`.** `npm run typecheck` has
  never type-checked the gate scripts; `tsx` strips types without checking them.
- **Green CI on an old PR means nothing.** `main` moves several times a day via the
  CVE collector. Re-run checks before merging anything more than a few days old.
- **A merged downstream PR is not a live integration.** `ADOPTERS.md` is the source
  of truth and carries evidence links; operational notes elsewhere go stale.
- **Rule counts change daily.** Never paste one into anything outward-facing
  without re-running the command in §1 first.
- **Run `actionlint` before pushing a workflow change.** A gate added on
  2026-09-22 runs it on every PR. It is not a style check: the release-notes body
  is assembled inside a double-quoted shell string, so an unescaped backtick in it
  is command substitution that runs at release time. That is exactly what it
  caught during this handover pass.
- **Do not hand-edit a generated block in `data/stats.json`.** `benchmarks[]` is
  written by `sync-stats-from-measurements.ts` and `byCategory` / `categories` /
  `version` by `reconcile-rule-count.mjs`; both have a `--check` mode that CI
  runs. Adding so much as an explanatory key to a generated block makes it
  disagree with its source and fails the build. Notes belong in a block no script
  owns, such as `ecosystem`. byCategory went stale for three months because two
  scripts each assumed the other owned it, so this is the failure mode the
  repository has already paid for once.

## 4. What only a human with credentials can do

Repository secrets in use (names only — values are never printed anywhere):
`NPM_TOKEN`, `PYPI_API_TOKEN`, `ATR_REPO_TOKEN`, `ANTHROPIC_API_KEY`,
`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `HF_TOKEN`, `TC_API_KEY`,
`TC_ADMIN_API_KEY`.

Hand-off items that cannot be automated:
- Reissue `NPM_TOKEN` (see §2.1) and confirm `4.1.0` publishes.
- The disclosure address was tested on 2026-09-22 and `security@agentthreatrule.org`
  did not exist: mail to it bounced with SMTP 5.1.3, "the email account that you
  tried to reach does not exist". It had been published in SECURITY.md, README, the
  telemetry spec, the downstream sync contract and two pages of the public site, so
  anyone who tried to report a vulnerability by mail got a bounce. All of those now
  point at `adam@agentthreatrule.org`, which is confirmed to receive. If you want a
  role address instead, create the alias in Google Workspace first and send a test
  message to it before changing any published reference.
- Decide whether `mcp-registry-v2.json` (1.7 MB, crawled 2026-03-15, 4,922
  entries, referenced by nothing in this repo) should stay in version control. It
  matches a `.gitignore` rule but is tracked, so the two disagree.

## 4b. Commit identity

`git shortlog -sne origin/main --since="6 months ago"` shows twelve distinct author
identities over the last six months. Two things follow from that:

- **244 commits are authored as `Panguard AI <support@panguard.ai>`.** This project
  is meant to be vendor-neutral and independent of that company, and public git
  history is permanent. The machine's *global* git config carries that identity, so
  it authors commits silently unless a local one is set. Before your first commit,
  run `git config user.email` in your clone and set a local identity if it returns
  a vendor address. Do not set it globally.
- **The human contributor appears under at least five identities**
  (`Adam Lin <imadam4real@gmail.com>`, `Adam Lin <adam@agentthreatrule.org>`,
  `Adamthereal`, `eeee2345`, and the vendor one above), so `git log --author` and
  `git blame` queries will quietly miss commits. Do not use author counts to
  measure who wrote what here.

## 5. Bot pull requests

Scheduled workflows used to open a new branch and a new pull request on every run
against the same accumulating files, so all but the newest were mutually exclusive
by construction and none could merge. The backlog peaked at 92 open pull requests,
41 of them daily CVE-ingest drafts.

PRs #587 and #589 (2026-09-22) fixed the mechanism: the lanes now maintain a
rolling branch instead of one per run, and open their PRs with a PAT so the checks
actually execute. The backlog is 44 as of 2026-09-22 — 25 human-authored, 19 from
bots — and the CVE-ingest line is down to a single open PR.

Two things did not follow automatically:

- `demote-fp-rules` was left on the job-level `GITHUB_TOKEN` when the other lanes
  moved to the PAT, so its PRs are still authored by `app/github-actions` and their
  checks still park at `action_required`. That lane demotes enforce-lane rules that
  false positive, so of all of them it is the one that most needs to go green.
  Repaired in this pass.
- The repair only applies to newly opened PRs. The already-stuck ones need a human
  to close and reopen them — a human event is what triggers the workflows — or an
  empty commit pushed to each branch. Nothing will happen to them on its own.

PR #500 proposed the rolling-branch fix back on 2026-08-23 and is still open,
overtaken by #587. Check whether it still carries anything before closing it.

A note on the shape of this backlog rather than its size: #500's checks were green
and it was still not mergeable, because `main` advances several times a day and a
month of that drift left the branch conflicting. A green PR is a statement about
the past. Re-run checks on anything more than a few days old before merging it.

## 6. What this handover pass changed

Scope was deliberately narrow: documentation accuracy, CI plumbing, and one
security fix. **No detection rule was modified.**

- Telemetry is now opt-in. `atr scan` sent results to a remote endpoint by
  default while `CONTRIBUTING.md` promised "No telemetry"; the default is now off,
  `--report-to-cloud` turns it on, `ATR_TC_URL` overrides the endpoint, and
  README §11 documents exactly which fields are sent.
- Fixed a shell injection in `issue-to-proposal.yml`. The issue title — attacker
  controlled, since anyone can open an issue — was interpolated into a `run:`
  block in a job holding `contents:write`, `issues:write` and a PAT. It was
  dormant only because a label it depended on did not exist; creating that label
  as part of this pass would have armed it.
- Withdrawn figures removed from outward-facing copy: the two lane FP rates
  (withdrawn in #579), `99.7% precision` (withdrawn 2026-06-15), and the "shipped
  in Cisco AI Defense" claim (that was a merge into an open-source scanner
  repository, not a vendor product). Historical records keep their numbers and
  gained errata notes instead of being rewritten.
- 156 accidentally committed files (144 agent scratch dumps, Next.js and Vercel
  build state, Python egg-info and caches) removed from version control and added
  to `.gitignore`. The files remain on disk.
- Repaired the conformance runner (§2.5) and the safety gate's argument parsing,
  which silently reported "treating as safe" and exit 0 when given the exact
  command `CONTRIBUTING.md` told contributors to run.

## 7. Where the numbers are allowed to come from

`data/stats.json` is generated. `ADOPTERS.md` carries evidence links for
integrations. `README.md` §8 is the only place benchmark figures should be quoted
from, and it is deliberately explicit about what each figure does and does not
support — including that the PINT corpus is self-built and is not Lakera's
official benchmark.

Figures currently withdrawn and not citable: both lane false-positive rates
(pending re-measurement against the current benign corpus) and `99.7% precision`.
README §8 explains why for each.
