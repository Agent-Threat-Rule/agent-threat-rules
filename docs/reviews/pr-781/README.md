# PR #781: NIST AI RMF mapping review

This is an AI-assisted advisory review for CHC-YHC, not NIST certification, legal compliance advice, an expert attestation, or completion of Adam's requested independent human review. The judgments are shared as provisional supporting evidence; a human must confirm them before presenting this as the requested independent human sign-off.

## Snapshot and intended use

PR #781 was open and draft at inspection. The reviewed head is `8973e93c89c692806a5011e39b44aff77ce914af` (`fix/mapping-nist`), with base `d38e56cba35d268d4d6d19247035ba5a25740412` (`fix/mapping-wording`). Both match the supplied snapshot. The full discussion contains Adam's 53-row request and his later explanation that the full safety run was stopped after 2 h 55 min. There is no posted row-by-row response in that discussion snapshot.

The stack is #779 → #781 → #782: #779 supplies wording changes and the compliance-claim validator; #782 branches from the reviewed #781 head and changes OWASP references. #778 separately documents framework errata. These existing changes are preserved. This follow-up branch starts at #781 so its corrections can be reviewed against that parent without bundling the upstream wording changes.

There is no root or rules/scripts/data/tests `AGENTS.md` at this commit. The only tracked one is `website/AGENTS.md`, read but outside this patch. `CONTRIBUTING.md`, `CONTRIBUTION-GUIDE.md`, `docs/COMPLIANCE-COVERAGE-POLICY.md`, the PR template, validation workflow, full original diff, and complete PR discussion were inspected. The compliance policy permits genuine limited detection evidence; it does not permit compliance guarantees or mappings added merely for coverage.

## Review questions and results

- **Q1:** Does the new mapping fit the existing full rationale better than the old mapping?
- **Q2:** Are the new mapping and rationale supported by the complete rule and official Core statement as detection evidence?

A Q1 Y does not imply Q2 Y. Y means limited support within that question, not fulfillment of every NIST condition. N records a concrete definition error or evidence contradiction. ? preserves insufficient semantic or deployment evidence. Model-assessed confidence is not expert certification.

The 53 rows represent 51 rules. ATR-2026-00041 and ATR-2026-00101 each have two distinct reviewed mappings. The original row order and mapping index are preserved. **Q1: 36 Y, 1 N, 16 ?. Q2: 1 Y, 6 N, 46 ?.** All verdicts assess the original head, before local proposed edits.

The sole Q2 Y, row 44, is limited support for a documented human-led reversal response. It does not prove that deployment mechanisms are applied or responsibilities assigned. Uncertain items must not be converted into positive judgments just to complete a checklist.

| Row | Rule | Old → new | Q1 | Q2 |
|---:|---|---|:---:|:---:|
| 1 | [ATR-2026-00465](rows.md#row-1-atr-2026-00465) | MG.2.3 → MG.1.3 | Y | ? |
| 2 | [ATR-2026-00041](rows.md#row-2-atr-2026-00041) | MG.2.3 → MG.1.3 | Y | ? |
| 3 | [ATR-2026-02400](rows.md#row-3-atr-2026-02400) | MG.2.3 → MG.2.4 | Y | ? |
| 4 | [ATR-2026-00243](rows.md#row-4-atr-2026-00243) | MG.2.3 → MG.2.4 | Y | ? |
| 5 | [ATR-2026-00310](rows.md#row-5-atr-2026-00310) | MG.2.3 → MG.2.4 | ? | ? |
| 6 | [ATR-2026-00075](rows.md#row-6-atr-2026-00075) | MG.2.3 → MG.1.3 | Y | ? |
| 7 | [ATR-2026-00099](rows.md#row-7-atr-2026-00099) | MG.2.3 → MG.1.3 | Y | ? |
| 8 | [ATR-2026-00317](rows.md#row-8-atr-2026-00317) | MG.2.3 → MG.2.4 | Y | ? |
| 9 | [ATR-2026-02642](rows.md#row-9-atr-2026-02642) | MG.2.3 → MG.2.4 | ? | ? |
| 10 | [ATR-2026-00378](rows.md#row-10-atr-2026-00378) | MG.2.3 → MG.2.4 | ? | ? |
| 11 | [ATR-2026-00287](rows.md#row-11-atr-2026-00287) | MG.2.3 → MG.2.4 | ? | ? |
| 12 | [ATR-2026-01899](rows.md#row-12-atr-2026-01899) | MG.2.3 → MG.1.3 | ? | ? |
| 13 | [ATR-2026-01923](rows.md#row-13-atr-2026-01923) | MG.2.3 → MG.1.3 | Y | ? |
| 14 | [ATR-2026-02121](rows.md#row-14-atr-2026-02121) | MG.2.3 → MG.1.3 | Y | ? |
| 15 | [ATR-2026-02408](rows.md#row-15-atr-2026-02408) | MG.2.3 → MG.1.3 | N | N |
| 16 | [ATR-2026-00511](rows.md#row-16-atr-2026-00511) | MG.2.3 → MG.1.3 | Y | ? |
| 17 | [ATR-2026-01927](rows.md#row-17-atr-2026-01927) | MG.2.3 → MG.1.3 | Y | ? |
| 18 | [ATR-2026-01896](rows.md#row-18-atr-2026-01896) | MG.2.3 → MG.1.3 | ? | ? |
| 19 | [ATR-2026-02627](rows.md#row-19-atr-2026-02627) | MG.2.3 → MG.1.3 | ? | ? |
| 20 | [ATR-2026-02233](rows.md#row-20-atr-2026-02233) | MG.2.3 → MG.1.3 | Y | ? |
| 21 | [ATR-2026-00345](rows.md#row-21-atr-2026-00345) | MG.2.3 → MG.2.4 | Y | ? |
| 22 | [ATR-2026-00101](rows.md#row-22-atr-2026-00101) | MG.2.3 → MG.2.4 | Y | N |
| 23 | [ATR-2026-00313](rows.md#row-23-atr-2026-00313) | MG.2.3 → MG.2.4 | ? | ? |
| 24 | [ATR-2026-02374](rows.md#row-24-atr-2026-02374) | MG.2.3 → MG.1.3 | Y | ? |
| 25 | [ATR-2026-00322](rows.md#row-25-atr-2026-00322) | MG.2.3 → MG.2.4 | Y | ? |
| 26 | [ATR-2026-00283](rows.md#row-26-atr-2026-00283) | MG.2.3 → MG.2.4 | ? | ? |
| 27 | [ATR-2026-02669](rows.md#row-27-atr-2026-02669) | MG.2.3 → MG.1.3 | Y | ? |
| 28 | [ATR-2026-02210](rows.md#row-28-atr-2026-02210) | MG.2.3 → MG.1.3 | Y | ? |
| 29 | [ATR-2026-02530](rows.md#row-29-atr-2026-02530) | MG.2.3 → MG.1.3 | ? | ? |
| 30 | [ATR-2026-00142](rows.md#row-30-atr-2026-00142) | MG.2.3 → MG.2.4 | ? | N |
| 31 | [ATR-2026-02190](rows.md#row-31-atr-2026-02190) | MG.2.3 → MG.1.3 | Y | ? |
| 32 | [ATR-2026-02817](rows.md#row-32-atr-2026-02817) | MG.2.3 → MG.2.4 | Y | N |
| 33 | [ATR-2026-02705](rows.md#row-33-atr-2026-02705) | MG.2.3 → MG.1.3 | Y | ? |
| 34 | [ATR-2026-00083](rows.md#row-34-atr-2026-00083) | MG.2.3 → MG.2.4 | ? | ? |
| 35 | [ATR-2026-01304](rows.md#row-35-atr-2026-01304) | MG.2.3 → MG.1.3 | Y | ? |
| 36 | [ATR-2026-01865](rows.md#row-36-atr-2026-01865) | MG.2.3 → MG.1.3 | Y | ? |
| 37 | [ATR-2026-00510](rows.md#row-37-atr-2026-00510) | MG.2.3 → MG.1.3 | Y | ? |
| 38 | [ATR-2026-01920](rows.md#row-38-atr-2026-01920) | MG.2.3 → MG.1.3 | Y | ? |
| 39 | [ATR-2026-00370](rows.md#row-39-atr-2026-00370) | MG.2.3 → MG.2.4 | Y | ? |
| 40 | [ATR-2026-00485](rows.md#row-40-atr-2026-00485) | MG.2.3 → MG.1.3 | Y | ? |
| 41 | [ATR-2026-00207](rows.md#row-41-atr-2026-00207) | MG.2.3 → MG.2.4 | Y | ? |
| 42 | [ATR-2026-02620](rows.md#row-42-atr-2026-02620) | MG.2.3 → MG.1.3 | ? | ? |
| 43 | [ATR-2026-00226](rows.md#row-43-atr-2026-00226) | MG.2.3 → MG.2.4 | Y | ? |
| 44 | [ATR-2026-02401](rows.md#row-44-atr-2026-02401) | MG.2.3 → MG.2.4 | Y | Y |
| 45 | [ATR-2026-00366](rows.md#row-45-atr-2026-00366) | MG.2.3 → MG.2.4 | Y | ? |
| 46 | [ATR-2026-00481](rows.md#row-46-atr-2026-00481) | MG.2.3 → MG.1.3 | Y | ? |
| 47 | [ATR-2026-00241](rows.md#row-47-atr-2026-00241) | MG.2.3 → MG.2.4 | Y | ? |
| 48 | [ATR-2026-02250](rows.md#row-48-atr-2026-02250) | MG.2.3 → MG.1.3 | Y | ? |
| 49 | [ATR-2026-00471](rows.md#row-49-atr-2026-00471) | MG.2.3 → MG.1.3 | Y | ? |
| 50 | [ATR-2026-02231](rows.md#row-50-atr-2026-02231) | MG.2.3 → MG.1.3 | Y | ? |
| 51 | [ATR-2026-00107](rows.md#row-51-atr-2026-00107) | GV.1.2 → GV.2.1 | ? | ? |
| 52 | [ATR-2026-00101](rows.md#row-52-atr-2026-00101) | GV.1.2 → GV.2.1 | ? | N |
| 53 | [ATR-2026-00041](rows.md#row-53-atr-2026-00041) | GV.1.2 → GV.2.1 | ? | N |

## Evidence and key findings

[NIST AI RMF 1.0, NIST AI 100-1 (2023)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) and the [official AIRC Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) were both retrieved successfully. [nist-core.json](nist-core.json) contains the exact relevant statements, official URLs, printed/PDF pages, retrieval details and comparison-only candidates. AIRC notes a revision is in progress; this review uses the published 1.0 Core.

- **MG.2.2, printed page 32 / PDF page 37:** “Mechanisms are in place and applied to sustain the value of deployed AI systems.” Row 15 / ATR-2026-02408 attributes this definition to MG.1.3. Expanded review found ATR-2026-02407 attributes it to MG.2.4. Neither a new ID selected by keyword nor an automatic switch to MG.2.2 establishes rule-level support for deployed value maintenance.
- **MG.1.3, same page:** responses to MAP high-priority risks must be developed, planned and documented; options include mitigating, transferring, avoiding or accepting. A bare runtime detector does not prove MAP priority or a response plan, and NIST does not require active runtime blocking for every risk.
- **MG.2.4, same page:** mechanisms are in place and applied, responsibilities assigned and understood, and the object is an AI system with performance/outcomes inconsistent with intended use. Prompt rejection, output filtering, and alerting may support a separately documented intervention but are not interchangeable with system deactivation.
- **GV.2.1, printed page 23 / PDF page 28:** documented risk-management responsibilities and communication lines must be clear to organizational individuals and teams. Rows 52 and 53 instead redefine it as enforcement of agent instruction/authority/task boundaries. Row 51 mentions human oversight but supplies no organization-level communication evidence. Agent permission vocabulary alone is insufficient.
- **Concrete response contradictions:** row 22 / ATR-2026-00101 and row 32 / ATR-2026-02817 claim disengagement/override but declare observe-only actions. Row 30 / ATR-2026-00142 claims blocking even though its response explicitly removed `block_output` after a historical reported 426/5,352 benign false positives (7.96%). That number is quoted from the pinned rule, not remeasured by this review.
- **Inert action labels:** ATR-2026-02408 lists `quarantine_artifact` and `require_human_review`; `src/action-executor.ts` does not dispatch them and `src/quality/action-eligibility.ts` calls them inert. Blocking is off by default, response metadata is not proof of execution, and test maturity does not establish applied deactivation. Runtime behavior was inspected, not changed.

## Population, sampling and limits

The original diff changes 530 mapping rows across 511 YAML files: 263 MG.2.3 → MG.1.3; 242 MG.2.3 → MG.2.4; 25 GV.1.2 → GV.2.1. The 53 sample rows cover nine of ten rule categories. They omit the sole model-security change and all 51 retained MG.2.3 rows. The published sample identities are reproducible, but no seed, PRNG, population ordering or selection program was supplied; the claimed original random draw cannot be recreated.

All 530 changed contexts received deterministic screening. **396 rows were flagged for triage, including 352 outside the original sample; flags overlap and are not verdicts.** The 134 unflagged rows are not semantically cleared. The queues include 25 organizational-governance checks, 225 MG.1.3 contexts without planning/priority wording, 144 MG.2.4 contexts with filtering/blocking language, two short MG.2.4 labels and two value-definition mismatches.

Five additional full YAML reviews cover ATR-2026-02407 (N/N), ATR-2026-00032, -00074 and -00123 (?/N), and the previously omitted model-security rule ATR-2026-02662 (Y/?). Thus **58 changed rows were individually inspected; 472 were screened without an individual semantic verdict.** The retained 51 MG.2.3 contexts were screened only. The frozen head contains 2,323 NIST mapping rows: 530 changed, 51 retained MG.2.3 contexts screened separately, and 1,742 other NIST rows outside these semantic screens. Reading a complete YAML file does not adjudicate all its other mappings. Other frameworks were not individually reviewed. No sample-based population error rate or claim that all 530 are correct is justified.

[batch-findings.md](batch-findings.md), [batch-analysis.json](batch-analysis.json), [inventory.json](inventory.json), and [coverage.json](coverage.json) give exact populations, flags, IDs, categories and scope labels. A new probability sample should publish the population manifest, ordering, seeded selection algorithm, strata and inclusion probabilities; deliberately selected boundary cases should remain separate. No seed was invented retrospectively.

## Proposed correction

The implementation patch is deliberately narrow:

1. Preserve seven directly relevant complete official Core statements in the reference allowlist so the generator does not lose organizational, planning, novelty or responsibility qualifiers. Add seven offline regression cases against independently cited official text. Other 65 reference summaries remain outside this definition audit.
2. Remove the residual `prefer GenAI Profile angle` instruction and restrict generated QA guidance to the Core reference. The earlier PR removed only the reference-table paragraph; both actionable residues remained.
3. Correct ATR-2026-02408 and ATR-2026-02407 contexts, remove the false value-maintenance attribution and unsupported execution claims, and reduce those two mappings from primary to partial. **Their IDs remain unchanged, as conditional evidence candidates pending human decision.** This is not a conclusion that either final association is established. Maintain the choice to remove or remap them after reviewing deployment evidence.

All detector, response, fixture, maturity, rule version and non-NIST fields remain unchanged. Other N/? cases have suggested bounded language and questions in [rows.md](rows.md); no mass rewrite or automatic governance substitution was performed. Few-shot examples without verified human provenance, mandatory primary output, the other reference summaries, and the existing compliance-policy MG.2.3 floor remain documented follow-up concerns, not silently repaired.

## Files and reproducibility

- [review.csv](review.csv): 53 machine-readable rows with separate questions, full old/new mappings/rationales, exact NIST text, evidence, suggestions, confidence and questions.
- [review.json](review.json): same judgments plus complete original head/base YAML and parsed rule objects for each row.
- [rows.md](rows.md): complete human-readable per-row review.
- [expanded-review.json](expanded-review.json): five separately labeled full-rule boundary reviews, excluded from original-sample statistics.
- [verify-review.py](verify-review.py): offline source, identity, inventory, CSV and proposed-change checks. It verifies artifact integrity, not semantic truth.
- [validation.md](validation.md): exact commands, results, limitations and logs.
- [source/pr-info.json](source/pr-info.json) and [source/discussion.json](source/discussion.json): the original PR refs and complete discussion snapshot.
- [source/safety-status-recheck-2026-11-05.json](source/safety-status-recheck-2026-11-05.json): the historical status-only recheck; other green workflows do not establish completion of the safety gate.
- [source/follow-up-safety-result.json](source/follow-up-safety-result.json): the subsequent completed native safety check for this two-rule follow-up.

Run `python3 docs/reviews/pr-781/verify-review.py --repo .` from the repository with the pinned Git objects available and PyYAML installed. It makes no network or paid-model calls. Do not execute `expand-nist-mapping.ts` as a reviewer: it selects unmapped rules and its dry-run can call Anthropic. No paid API was used here.

## Draft scope and human decisions

The follow-up branch is `review/nist-rmf-781`, based on the reviewed head. Draft PR base: **`fix/mapping-nist`**. Its purpose is to feed independently inspectable evidence and bounded corrections back into #781; it does not replace #781 or complete its requested second-human sign-off. #782 is an existing downstream sibling and must be coordinated if #781 later absorbs this patch. The parent refs and effective branch rules were rechecked before submission. If the stack changes, re-evaluate the base and preserve the original source snapshots.

This follow-up is shared as a draft for maintainer discussion. It does not constitute an approval or completed independent human review. This patch implements the evidence-supported choice to retain the two IDs only as conditional partial support, with the false definitions and prevention claims removed. The supplied row findings also reject unsupported governance/enforcement claims as written and include bounded replacement wording. Unknown deployment ownership, communication records and response integrations are explicitly outside the available evidence; the report does not turn them into factual claims or ask for a new full-population audit as part of this patch. The native safety gate for this two-rule follow-up completed successfully; the earlier explicit-target timeout remains documented, and Adam's original combined-stack run is not claimed complete. No author branch, safety requirement, detector, or runtime behavior is changed by this follow-up.
