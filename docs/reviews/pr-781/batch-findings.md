# PR #781 sampling and expanded-scope review

Reviewed snapshot: `8973e93c89c692806a5011e39b44aff77ce914af` against `d38e56cba35d268d4d6d19247035ba5a25740412`. This is assisted review, not NIST certification or legal compliance advice.

## Population and published sample

PR #781 changes 530 NIST mapping rows across 511 rules: 263 MG.2.3 → MG.1.3; 242 MG.2.3 → MG.2.4; 25 GV.1.2 → GV.2.1. The published 53 rows contain 51 distinct rule IDs. ATR-2026-00041 and ATR-2026-00101 each occur twice and must remain separate rows.

The exact published row list is reproducible from the comment and pinned YAML. The random draw itself cannot be reproduced from supplied evidence: the discussion and PR diff supply no seed, PRNG, candidate-order definition or selection program. The asserted draw is stratified as 50 of 505 MG moves plus 3 of 25 GV moves. It is not a category or target-subcategory stratified assurance sample.

| Rule category | Changed rows | Sample rows |
|---|---:|---:|
| agent-manipulation | 102 | 7 |
| context-exfiltration | 66 | 6 |
| data-poisoning | 8 | 1 |
| excessive-autonomy | 16 | 3 |
| model-abuse | 13 | 1 |
| model-security | 1 | 0 |
| privilege-escalation | 53 | 9 |
| prompt-injection | 182 | 19 |
| skill-compromise | 22 | 1 |
| tool-poisoning | 67 | 6 |

Sample target counts: MG.1.3 29/263; MG.2.4 21/242; GV.2.1 3/25. The sole changed model-security row is absent. Data-poisoning, model-abuse and skill-compromise each have only one sample row. All 51 retained MG.2.3 rows are outside the changed-row sample; the original classification decision to retain those is therefore untested by the 53.

## Deterministic screening, not semantic approval

`batch_scan.py` screens all 530 changed mapping contexts with the exact regular expressions recorded in `batch-analysis.json`. The full flag manifest includes every flagged ID, mapping index, path, old/new mapping, full rationale, response actions and commit-pinned URL. These are candidate queues, not automatically rejected mappings.

| Flag | Rows |
|---|---:|
| gv21_organizational_evidence_check | 25 |
| mg13_runtime_without_plan_or_priority_language | 225 |
| mg24_filter_or_block_language | 144 |
| mg24_short_runtime_label | 2 |
| value_maintenance_definition_mismatch | 2 |

396 changed rows match at least one flag; 352 of those are outside the original 53. Flags overlap. Every changed row was scanned; the 134 without a flag are not semantically cleared.

All 25 GV.2.1 contexts require an organization-evidence check: none supplies the official statement’s full documented responsibilities-and-communication evidence. Some mention human approval, gatekeepers, or responsible parties and may support a conditional secondary association; others explicitly redefine governance as software-agent privilege or instruction hierarchy. The 25 are a review queue, not 25 identical automatic rejections.

Value-maintenance wording reveals two specific errors: sample ATR-2026-02408 maps the MG.2.2 definition to MG.1.3, and unsampled ATR-2026-02407 maps it to MG.2.4. Both exact contexts are in the manifest. The “sustained denial-of-utility” phrase in ATR-2026-00302 is not treated as the same definition pattern.

Filtering/blocking phrases appear in 144 MG.2.4 contexts. The presence of “block” is not enough to establish supersession/disengagement/deactivation of an AI system, application of that mechanism, and assigned/understood responsibilities. Conversely, the word does not prove the mapping wrong; deployment integrations may supply the missing connection.

225 MG.1.3 contexts lack explicit planning, documentation or priority language. These can be runtime evidence for a separately documented response, but the detection rule alone does not prove that MAP has deemed the risk high priority or that a response was developed/planned/documented.

## Five additional rows actually inspected

The full head YAML, description, detection, response, positive/negative and evasion fixtures were individually inspected for ATR-2026-02407, ATR-2026-00032, ATR-2026-00074 ATR-2026-00123 and ATR-2026-02662. Their separate Q1/Q2 judgments are in `expanded-review.json`, with official definitions and confidence/human questions. They are outside the 53 and must not inflate its statistics.

- ATR-2026-02407: Q1 N, Q2 N. The stated definition belongs to MG.2.2. Its response declares tool blocking, but the file comments say maturity:test keeps it outside the auto-block lane. Correcting definition text is supported; selecting the final alternative ID still needs the intended association to be explicit.
- ATR-2026-00032: Q1 ?, Q2 N. Goal-redirection regexes and declared escalation do not substantiate a claim that GV.2.1 requires runtime agent task-boundary enforcement.
- ATR-2026-00074: Q1 ?, Q2 N. Cross-agent credential forwarding/impersonation and orchestrator bypass are software trust-boundary evidence, not the documented organizational roles/communication required by GV.2.1.
- ATR-2026-00123: Q1 ?, Q2 N. Broad Bash/file permissions and autoApprove detection do not make GV.2.1 a requirement to enforce AI component permissions.
- ATR-2026-02662: Q1 Y, Q2 ?. This deliberate boundary addition covers the sole changed model-security row omitted from the original random sample. Known serialization-gadget detection is closer to planned mitigation than unknown-risk recovery, but its alert-only response and absent MAP priority/response-planning records leave the full current claim uncertain.

No bulk mapping edits were made by this analysis. These findings justify expanding review beyond the original 53; they do not justify automatically removing all governance associations or remapping by new keyword rules.

## Retained MG.2.3 context-only screen

The current corpus has 51 retained MG.2.3 rows. Three omit explicit previously-unknown-risk language: ATR-2026-00030, ATR-2026-01750 and ATR-2026-02867. 47 use a generic “respond to previously unknown identified risks ... so the risk can be treated” template; quoting the condition does not establish it in a deployment. ATR-2026-02862 says “new turn-forging spellings”; a newly encountered spelling does not automatically mean the risk was previously unknown. These 51 received context-only screening, not full YAML semantic judgments. No statement about actual incident novelty, recovery procedures or deployment timelines is inferred.

## Suggested follow-up and scope

Keep the published 53-row review intact; add a reproducible boundary-case queue with rationale and frozen commit. Prioritize the two value-definition mismatches, all unsampled GV.2.1 rows, short MG.2.4 runtime labels, filter-only MG.2.4 contexts, and retained MG.2.3 contexts. For a new random audit, publish the exact population manifest, ordering, seeded selection algorithm, target/category strata and inclusion probabilities; keep deliberate boundary additions separate from the probability sample. No seed was retroactively invented for Adam’s draw.

Across the team, 53 original rows plus these five additional rows means 58 changed rows individually examined; 472 changed rows remain without individual semantic review. All 530 were programmatically screened, and 51 unchanged MG.2.3 contexts were separately scanned. All other mappings and frameworks remain outside this semantic review. The sample cannot certify all 530, and schema/allowlist checks cannot resolve semantic mapping correctness.

Offline commands used here: `python /workspace/atr-review-evidence/batch_scan.py`; `python /workspace/atr-review-evidence/write_batch_findings.py`; read-only Git diff and `rg` searches. No generator, Anthropic or other paid API was executed.
