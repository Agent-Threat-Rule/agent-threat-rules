# Validation commands and results

All commands ran locally on branch `review/nist-rmf-781`, starting from reviewed PR head `8973e93c89c692806a5011e39b44aff77ce914af`, with the proposed working-tree patch. Working directory: repository root. Logs are preserved under [logs/](logs/). These validation commands did not invoke a model API, generator dry-run, or remote CI dispatch; publication of the follow-up is separate.

## Passed

| Exact command | Result | Evidence / limits |
|---|---|---|
| `npm ci --ignore-scripts --no-audit --no-fund --cache /tmp/atr-npm-cache` | exit 0; 383 packages installed | Dependency lifecycle scripts disabled; build run explicitly later. [log](logs/npm-ci-retry.log). |
| `npm run validate` | exit 0; 844 passed, 0 failed | Schema/structural validation, not mapping semantics. [log](logs/validate.log). |
| `npm run validate:compliance` | exit 0; 0 violations across 844 mapped rules, 0 unvalidated frameworks | Identifier/shape/prohibited-claim checks, not correct interpretation of Core statements. [log](logs/validate-compliance.log). |
| `npm run audit:mappings -- --require-full=references:owasp_llm,references:owasp_agentic,references:mitre_atlas,compliance:eu_ai_act,compliance:nist_ai_rmf,compliance:iso_42001` | exit 0; each required framework 844/844 | Presence/coverage only, not semantic correctness. [log](logs/audit-mappings.log). |
| `python3 scripts/generate-attack-crosswalk.py --check` | exit 0; committed document matches rule metadata | [log](logs/attack-crosswalk.log). |
| `python3 scripts/generate-ast-crosswalk.py --check` | exit 0; committed document matches rule metadata | [log](logs/ast-crosswalk.log). |
| `npm run typecheck` | exit 0 | [log](logs/typecheck.log). |
| `npm run typecheck:scripts` | exit 0 after dependencies installed | Recorded in [generator-findings.md](generator-findings.md); early pre-install attempt failed with `tsc` unavailable and was not treated as a code failure or pass. |
| `npm run build` | exit 0 | [log](logs/build.log). |
| `npx --no-install vitest run tests/nist-core-reference.test.ts` | exit 0; 7/7 | New offline semantic-definition regressions; no generator import or model call. Recorded in generator findings. |
| `npx --no-install vitest run tests/nist-core-reference.test.ts tests/action-eligibility.test.ts tests/enforcement.test.ts` | exit 0; 98/98 in 3 files | Focused validation of definition data and inspected enforcement/action assumptions. [log](logs/focused-tests.log). |
| `timeout 180s npm run gate:generalization` | exit 0 | Broken: 0 (baseline 0); self-FP: 2 (baseline 2); no new regressions. Existing two baseline self-FP cases remain. [log](logs/generalization.log). |
| `timeout --signal=TERM --kill-after=10s 600s node_modules/.bin/tsx scripts/check-rules-safety.ts --base 8973e93c89c692806a5011e39b44aff77ce914af` | exit 0; PASS | Existing CI diff mode: 0 new / 2 modified rules, full four-corpus differential FP comparison and own-TP retention. [log](logs/rule-safety-pr-base.log). Scope is this follow-up, not the original #781 stack. |
| `git diff --check` | exit 0 | Patch whitespace only. |
| `python docs/reviews/pr-781/verify-review.py --repo .` | exit 0 | Rebuilds original 530-row/511-file inventory, original sample membership/order, complete pinned YAML, separate expanded reviews, CSV/statistics, deterministic screen and permitted local metadata-only changes. Requires PyYAML and pinned Git blobs locally; network disabled for Git lazy fetch. [log](logs/review-integrity.log). This validates evidence integrity, not semantic truth. |

## Exported implementation patch

`git apply --check /workspace/atr-review-evidence/implementation.patch` passed (exit 0) in an isolated temporary Git repository containing the exact original head blobs. The patch includes the four tracked implementation files and new offline test; review documents are supplied separately in this bundle. [Log](logs/patch-apply-check.log).

## Earlier status recheck — 2026-11-05 (historical)

Checked again at 2026-11-05 04:17 UTC (12:17 Asia/Taipei); exact tool timestamp and responses are preserved in [the status snapshot](source/safety-status-recheck-2026-11-05.json).

PR #781 remains open and draft at the same head `8973e93c89c692806a5011e39b44aff77ce914af`, with the same `fix/mapping-wording` base. Its two discussion comments are unchanged. Adam's latest safety report still says the run was stopped after **2 h 55 min, unfinished**; no later completed safety result appears in the discussion.

The commit-status endpoint returned no status entries. The PR-triggered workflow endpoint returned four completed successful runs (ATR Security Scan, Maturity FP gate, no-private-leak, ReDoS Gate), but none is the Validate ATR Rules / Validate Rules & Build workflow containing `check-rules-safety`. Those green workflows do not substitute for completion of this gate. The workflow endpoint is first-page and PR-trigger-filtered; no broader CI-completeness claim is made. The unchanged validation workflow targets PRs into main, whereas this PR still targets `fix/mapping-wording`.

At that earlier status-only recheck, no new safety run was started: the head, discussion and gate configuration were unchanged, and repeating the prior bounded timeout has no new evidence to resolve. The previous local run remains **exit 124, incomplete, not passed**. An independent byte comparison and `git diff --exit-code` confirm `scripts/check-rules-safety.ts` and `.github/workflows/validate.yml` are unchanged from the frozen head; no active safety process remains. No safety gate, threshold, timeout behavior, corpus, target selection logic, or workflow requirement was changed or bypassed to obtain a green result. At that time completion remained outstanding; the subsequent follow-up-base run below resolves this for the two-rule follow-up only.

## Earlier explicit-target safety attempt (incomplete)

Exact command:

```bash
timeout 180s node_modules/.bin/tsx scripts/check-rules-safety.ts rules/data-poisoning/ATR-2026-02408-dataset-loader-code-execution.yaml rules/privilege-escalation/ATR-2026-02407-agent-workspace-boundary-escape.yaml
```

**Exit 124: timed out after 180 seconds, not a pass.** [Full log](logs/rule-safety.log). The gate selected exactly the two explicitly named existing rules; its generic explicit-target message calls them “new rule file(s)” but this patch adds no rules. It loaded 467 skill files, 13,635 extended samples, 69 code samples, and 157 research-mention samples, then reported advisory wide regex bridges before timeout. It did not complete the corpus checks or produce a final safety verdict. The full 511-rule original PR safety run was not repeated; Adam's original longer attempt is documented in the discussion.

`CONTRIBUTING.md` calls the safety gate non-negotiable for merge. This explicit-target attempt remains incomplete as historical evidence. It is not relabeled as passed. The gate's existing native PR diff mode was then run to completion for this actual follow-up base, as documented next. No gate or regex was weakened, no mapping was invented, and no failure was suppressed.

## Completed safety check for this follow-up

Tested commit: `43766a71d9e59c551ef18d96dddf072470d0b1e4`. Actual draft PR base: `8973e93c89c692806a5011e39b44aff77ce914af` (`fix/mapping-nist`).

```bash
timeout --signal=TERM --kill-after=10s 600s node_modules/.bin/tsx scripts/check-rules-safety.ts --base 8973e93c89c692806a5011e39b44aff77ce914af
```

**Exit 0, PASS, within the 600-second budget.** [Full log](logs/rule-safety-pr-base.log), [structured result](source/follow-up-safety-result.json).

The unmodified gate discovered **0 new and 2 modified rules**, loaded the complete corpus census (467 skill files, 13,635 extended samples, 69 code samples, 157 research mentions), and completed its normal modified-rule checks: compare base/head false positives over all four corpora and retain original true positives. It reported no new benign false positives and no lost own true positives.

The earlier positional invocation routes explicitly named files through the new-rule checks, including cross-rule conflicts. The completed invocation uses the script's existing `--base` mode, matching how validate.yml checks an actual PR. No target selection logic, thresholds, corpus, workflow trigger or rule behavior was edited; no empty-scope check was accepted. The base is the real parent PR head, not a convenient later revision. This is completion of the native safety check for this two-rule follow-up, not completion of Adam's original combined-stack run or an assertion of zero pre-existing false positives.

## Initial environment setup failure

The first `npm ci --ignore-scripts --no-audit --no-fund` attempt exited 254 because the inherited default cache `/home/agent/.npm/_cacache` could not be created in the sandbox. It was retried successfully with an explicit writable `/tmp/atr-npm-cache`, without changing permissions, secrets or dependencies. [Initial log](logs/npm-ci.log), [successful retry](logs/npm-ci-retry.log).

## What was not verified

- The entire Vitest suite (`npm test`) was not run; 98 focused tests and the generalization gate were run.
- No new benign-corpus false-positive rate is claimed from the incomplete safety run. Historical FP figures quoted in row findings come from the pinned rule text.
- No deployment environment, applied deactivation/quarantine workflow, organizational role record, communication line, MAP prioritization record or legal interpretation was validated. Runtime source and declared metadata are not deployment execution evidence.
- The unchanged 65 other NIST reference descriptions were not audited against full official statements. Other framework mappings and other mapping rows within inspected rules were not individually adjudicated.
- Programmatic flags are triage; unflagged rows are not cleared. The 53-row sample cannot prove all 530 mappings correct.
- No API generator was run. `expand-nist-mapping.ts` selects rules missing NIST mappings; its dry-run can still call a paid Anthropic API and is not a mapping reviewer.
