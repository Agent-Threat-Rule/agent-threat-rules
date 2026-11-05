# NIST mapping generator review

This is an AI-assisted source review, not an expert certification or a NIST/legal compliance determination. The source-review and validation steps below did not invoke the generator or any paid API. Publication of the follow-up draft is separate from those checks.

## Scope and revisions

- Repository: `Agent-Threat-Rule/agent-threat-rules`.
- Reviewed PR head: `8973e93c89c692806a5011e39b44aff77ce914af`.
- Reviewed PR base: `d38e56cba35d268d4d6d19247035ba5a25740412` (`fix/mapping-wording`).
- The complete `scripts/expand-nist-mapping.ts` source, its PR delta, the allowlist JSON, package scripts, relevant validation code, and CI workflow were inspected.
- No repository root `AGENTS.md` exists at the reviewed head; the sole tracked `website/AGENTS.md` does not govern these paths. `CONTRIBUTING.md` is the canonical contribution process.
- Aggregate mapping-delta verification used the root agent's immutable before/after extraction; it is a structural check, not an additional semantic review of 530 rows.

## Evidenced residual GenAI Profile guidance

The PR removes the old reference-table paragraph recommending the GenAI Profile, but leaves two active instructions:

1. `buildPrompt()` says: `If the rule is GenAI-specific (prompt injection, jailbreak), prefer GenAI Profile angle.` [Immutable source at head, line 222](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/scripts/expand-nist-mapping.ts#L222).
2. The generated `SUMMARY.md` QA workflow says: `Verify subcategory IDs match RMF 1.0 / GAI Profile`. [Immutable source at head, line 448](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/scripts/expand-nist-mapping.ts#L448).

The allowlist identifies the framework as NIST AI RMF 1.0 and contains the 72 Core subcategories, not GenAI Profile action identifiers. The two instructions therefore contradict the stated Core-only reference and the PR's claim that Profile steering was dropped.

The minimal local patch deletes the prompt preference and changes the summary QA step to `Verify subcategory IDs and meanings match the NIST AI RMF 1.0 reference list`. It does not change runtime detection, rule selection, model configuration, or output schema.

## Restore seven complete official Core definitions

Because the PR makes the identifier allowlist the generator's semantic reference, omitted qualifications now directly shape its prompts. The follow-up patch replaces exactly seven abbreviated values with the published NIST AI RMF 1.0 statements: GV.1.2, GV.2.1, MP.5.2, MG.1.3, MG.2.2, MG.2.3, and MG.2.4. The authoritative source is [NIST AI 100-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf), Tables 1, 2, and 4, printed pages 22, 23, 28, and 32 (PDF pages 27, 28, 33, and 37). The source retrieval is separately recorded in `nist-core.json`.

The update preserves the 72 identifiers, their order, all other values and all other JSON fields. In particular, it restores the organizational individuals/teams condition in GV.2.1; high-priority MAP risks and developed/planned/documented responses in MG.1.3; recovery from previously unknown risks in MG.2.3; and applied mechanisms, assigned/understood responsibilities, and inconsistency with intended use in MG.2.4. MG.2.2 explicitly concerns sustaining deployed systems' value. These are source corrections, not a determination that any particular rule establishes the corresponding process.

The focused offline regression test `tests/nist-core-reference.test.ts` independently pins these seven official statements and cites their source/pages. It reads JSON data and never imports the generator or initializes an API client.

## Other findings retained for maintainers

- `loadFewShotExamples()` takes the first mapped rules encountered in three preferred categories and never checks provenance or an explicit reviewed-example allowlist, although comments and the prompt call them manually curated or a gold standard. Existing semantic mapping errors can consequently enter the few-shot prompt. For example, candidate rules ATR-2026-00032 and ATR-2026-00074 describe AI-agent task/privilege boundaries as GV.2.1; the official definition is about documented AI risk roles, responsibilities, and communication understood by organizational individuals and teams. This minimal patch does not manufacture provenance or silently replace examples. A separate reviewed-example policy is needed.
- Before this follow-up patch, the reference JSON contained abbreviated paraphrases, not full official definitions. Seven directly relevant definitions are restored as described above; the other 65 definitions remain outside this source-correction scope. Sharing an identifier allowlist with CI prevents some identifier drift; it does not establish semantic correctness.
- The prompt requires at least one `primary` relationship for every target. This requirement cannot establish that any detected event directly evidences a governance process. Deciding whether to permit an empty mapping or only partial support is a repository policy decision, deferred here.
- The generator only selects rules without a `compliance.nist_ai_rmf` block. It is not a reviewer or remapper of existing mappings.
- The `--dry-run` branch occurs after `await generateMapping(rule, examples)`, which calls `client.messages.create`. Dry-run suppresses proposal file writes; it does not suppress paid API requests. No dry-run was performed.

## Structural PR-delta check

The extracted comparison contains 530 changed mapping rows in 511 rule files: 25 GV.1.2 -> GV.2.1, 263 MG.2.3 -> MG.1.3, and 242 MG.2.3 -> MG.2.4. After replacing both abbreviated IDs and the verbose `MANAGE 2.3` spelling with the new identifier, every mapping object equals its new counterpart. Strength values and non-ID rationale text are unchanged. This result does not validate their meaning.

## Validation performed

All commands below ran from `/workspace/atr-nist-review`.

1. `git diff --check` — passed, exit 0, after the generator and seven-definition reference patches.
2. Offline Python source assertions — passed, exit 0. The assertions check absence of `GenAI Profile`, `GAI Profile`, and `600-1`; they also confirm the existing no-mapping target filter and that `generateMapping` precedes the dry-run branch. No TypeScript was imported or executed.
3. `npm run typecheck:scripts` — initially blocked, exit 127: `tsc: not found`, while dependency installation was incomplete. A rerun after installation is recorded below.
4. `npx --no-install vitest run tests/nist-core-reference.test.ts` — passed, exit 0: 1 test file, 7 tests; duration 1.64 seconds, after dependency installation.
5. `npm run typecheck:scripts` — final rerun passed, exit 0, after dependency installation.
6. Offline JSON-delta assertions — passed, exit 0: exactly the seven authorized definition values changed; keys, order, and other JSON fields remain identical.

No test asserts just the removal of two prose instructions. Instead, the new test protects the substantive official definitions that the generator consumes. The generator was not executed or imported, because top-level code initializes the API client and invokes `main()`.
