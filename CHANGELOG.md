# Changelog

All notable changes to ATR will be documented in this file.

## [Unreleased]

## [4.2.2] - 2026-10-28

A patch release of export and converter fixes, five rule rewrites for Python
portability, and reference corrections. The rule format, identifier scheme,
engine matching and Match output are unchanged.

Default behaviour that changes:

- Nothing the engine matches. The five rewritten rules match the same samples
  as before on every test case, evasion test and text file under `data/`.
- Exports regenerated from this release differ from earlier ones: the
  converters (`atr convert`, `ruleToSPL()`, `ruleToElastic()`, Sage), the
  Cisco Skill Scanner pack, the PyRIT digest, the Pipelock bundle and the
  RAMPART evaluator now follow SPEC §6.4, so a condition without a flag group
  matches case-insensitively and a leading `(?s)` or `(?m)` has no effect.
  See the upgrade note under the converters entry below.
- `references` and `compliance` metadata changes on 139 rules (the OWASP and
  ATLAS corrections below). Tooling that reports or groups by those ids sees
  different buckets.

### Added

- **`export-cisco-pack.ts --downstream` writes the Cisco Skill Scanner's
  schema_version 2 pack.** The scanner now validates its bundled packs
  against a strict schema at startup: it rejects `signature_files` and any
  rule field outside its allowlist (`maturity`, `atr_id`, `atr_url` and
  `file` included), and every rule needs a Cisco AI taxonomy code or a
  default for its category. A pack exported as before fails to load. With
  `--downstream <vendored pack dir>` the exporter writes that schema and
  carries the scanner maintainers' choices forward: each existing rule keeps
  the scanner category and taxonomy code it has downstream, and a new rule
  takes the scanner category its ATR category already maps to and inherits
  that category's default code. It stops instead of guessing when an ATR
  category maps to more than one scanner category or a new rule's category
  has no default; `--taxonomy <ATR id>=<code>` supplies the code. The pack
  description names no benchmark figure. Without `--downstream` the output is
  unchanged. `tests/cisco-pack-downstream-v2.test.ts` covers the contract.

### Fixed

- **OWASP and MITRE ATLAS references corrected on 108 rules** (#675).
  `references.owasp_llm`, `references.owasp_agentic` and
  `references.mitre_atlas` are corrected where a rule named an identifier
  that does not describe what it detects. No detection, severity, maturity,
  status, confidence or response field changes. The two crosswalks CI checks
  against rule metadata are regenerated.

- **OWASP compliance entries aligned with the corrected references on 25
  rules** (#680). 29 `compliance.owasp_agentic` / `compliance.owasp_llm`
  entries still named an identifier #675 removed from `references`, which
  kept it in `docs/OWASP-AGENTIC-MAPPING.md`.

- **`LLM08:2025` used for Excessive Agency replaced on 30 rules** (#684). In
  the OWASP Top 10 for LLM Applications 2025, LLM08 is Vector and Embedding
  Weaknesses and Excessive Agency is LLM06. Only `references.owasp_llm` and
  `compliance.owasp_llm` change; two rules that use LLM08 for its real
  meaning keep it.

- **Five rules compile under Python `re`.** The Cisco Skill Scanner pack and
  other Python consumers compile patterns with `re`, which rejects
  variable-width look-behind and a back-reference to a group that does not
  exist; such a pattern is skipped and detects nothing there. Twelve
  conditions in five rules were affected. ATR-2026-00442 and -02100 split a
  negative look-behind over alternatives of different lengths into one
  look-behind per alternative. ATR-2026-02300 and -02304 match the
  `mcpServers` or fetch-verb prefix instead of looking behind for it, which
  changes the matched span but not whether the condition matches. The fourth
  condition of ATR-2026-00290, `(?:(?:\w+\s+){40,})\1{3,}`, is removed: its
  `\1` refers to no group, which JavaScript reads as the character U+0001, so
  it never matched anything. On every test case and evasion test of the five
  rules and the text files under `data/` (7,963 samples), the old and new
  rules match the same samples. `check-python-compat.py` now reports 0
  uncompilable patterns in the exported pack, down from 12, and
  ATR-2026-02300 and -02304 profile more than 3x cheaper than their latency
  baseline (171.6x and 9.2x).
  Compiling under Python also exposed the ReDoS gate to three of these
  conditions for the first time, and they backtracked quadratically on a long
  run of whitespace: ATR-2026-00442#1 on `\s*[:,-]?\s*` and ATR-2026-02300#1
  and #3 on `:\s*\n\s+`. Both are rewritten to accept the same strings
  without the ambiguity, `(?:\s*[:,-])?\s*` and `:[^\S\n]*\n\s+`. The
  five rules' entries in `data/benign-fp-measurement.json` are re-measured
  because their detection fingerprints changed; their false-positive counts
  are unchanged.

- **The RAMPART evaluator compiles patterns as SPEC §6.4 says.**
  `integrations/rampart/src/atr_rules_evaluator.py` compiled each rule's
  pattern as written with `re.IGNORECASE | re.MULTILINE`, so `^` and `$`
  matched at every line of a field and the letters of a leading flag group
  took effect (`(?s)` let `.` match a newline). It now removes one leading
  `(?imsx)` group and compiles the rest with `re.IGNORECASE` only, as pyATR
  does. On the rules on main this can change a result only on multi-line
  input to a rule whose first regex condition, the only one the evaluator
  reads, contains `^` or `$`; none of those rules' test samples is matched
  differently by that condition. The evaluator is one of the exports issue
  #698 lists.

- **The PyRIT digest, the Cisco Skill Scanner pack and the Pipelock bundle
  now follow SPEC §6.4.** PyRIT's `RegexScorer` and the Cisco scanner
  compile patterns with Python `re` and no flags, Pipelock with Go RE2, and
  both honour an inline flag group. The exporters passed each condition's
  leading group through, so the `(?im)`, `(?si)` and `(?is)` of
  ATR-2026-00450, -00859 and -00207 were applied. A condition written
  without `(?i)` was case-sensitive in the Cisco pack, and in the Pipelock
  bundle's injection rules, which Pipelock releases up to v3.7.0 compile as
  written; Pipelock adds `(?i)` to DLP and tool-poison rules itself, and the
  digest already added it. Each pattern is now `(?i)` followed by
  `regexConditionSpec(value).source`, the pattern the engine compiles; the
  Pipelock bundle puts one `(?i)` in front of a rule's joined alternatives.
  Output change on the rules on main: in `data/pyrit-digest.json`, four
  patterns, of which only ATR-2026-00450#2 matches differently. The digest is
  also regenerated at main for the first time since 4.0.0, in a commit of its
  own: 116 new conditions, 5 removed with the deprecated ATR-2026-00233, 121
  patterns edited in their rules and nine new `condition: all` exclusions.
  The exporter no longer emits a `case_sensitive` marker, which no rule sets
  and §6.4 gives no effect. `tests/pyrit-digest.test.ts` checks the
  transform on fixed inputs and that every committed pattern starts with
  exactly one `(?i)`; it does not compare the digest with the rules, so a
  rule edit does not require regenerating it. The Cisco pack changes 1,161
  of 3,471 patterns in 307 signatures, 1,157 of them because they gain
  `(?i)`; `--reproduce-vendored` keeps the vendored pack's verbatim
  patterns, its output is unchanged, and a new test checks that wiring. The
  Pipelock bundle changes every rule's regex: 814 conditions in 191
  injection rules become case-insensitive on Pipelock releases up to v3.7.0,
  and ATR-2026-00450 no longer matches at the start of a second line; the
  compiler version is now 1.0.1. No pattern starts or stops compiling under
  Python `re` or Go RE2. Issue #698; `tests/compile-pipelock.test.ts` is new.

- **The rule converters translate regex conditions per SPEC §6.4.**
  `atr convert generic-regex|splunk|elastic`, the package exports
  `ruleToSPL()`, `ruleToElastic()`, `convertRule()` and `convertAllRules()`,
  and the `converters/sage` and `converters/sage-reverse` subpaths each
  followed a condition's leading flag group instead of SPEC §6.4 (issue
  #698):
  - generic-regex copied the group's letters into `flags`, so a condition
    without `(?i)` exported `flags: ""` (case-sensitive) and `(?im)` or
    `(?is)` turned on multiline or dotAll in the consumer. `flags` is now
    always `i`, or `iu` when the pattern needs Unicode mode.
  - Splunk passed the group to PCRE unchanged, with the same two effects.
    Every regex now starts with a single `(?i)`.
  - Elastic put the group into a Lucene `regexp` value, where inline flags do
    not exist. The value is now the condition without its group;
    `case_insensitive: true` is unchanged.
  - Sage exported a rule as case-sensitive unless a group said `(?i)`. Every
    exported rule now sets `case_insensitive: true`; a condition that depends
    on the `u` flag, which Sage cannot set, is skipped with a warning; and the
    "mixes case-sensitive" and "unsupported inline flags" warnings are gone.
    Importing from Sage (`sage-reverse`) now always writes `(?i)` and warns
    (`case_sensitivity_lost`) when the Sage rule was case-sensitive.

  The dialect lives in the new dependency-free `src/regex-dialect.ts`
  (`regexConditionSpec()`, `needsUnicodeFlag()`, `inlineCaseInsensitive()`),
  so the published `converters/sage` subpath does not load the engine;
  `src/engine.ts` imports and re-exports it, and the rule-quality and
  rule-latency gates now also run when it changes. The generic-regex docs no
  longer show an import path the package does not export.

  Upgrade note: exports regenerated after this change differ from earlier
  ones. Conditions without a flag group now match case-insensitively, so a
  SIEM or scanner that loads them can see more matches, and conditions whose
  group had `s` or `m` no longer let `.` cross a line break or `^` and `$`
  match inside the field. Generic-regex `flags` can now be `iu`, so a consumer
  that maps the letters to another regex engine must accept `u`. The Sage
  export skips conditions that depend on `u`. `ReverseWarning['kind']` gains
  `case_sensitivity_lost`; TypeScript code that switches over it exhaustively
  must handle it.

## [4.2.1] - 2026-10-24

A patch release of rule fixes and one new rule, plus two release-tooling
fixes. The rule format, identifier scheme and Match output are unchanged.

Default behaviour that changes:

- ATR-2026-01601 (SQL injection with destructive DDL, maturity `stable`, so it
  runs in the enforce lane) now also matches when whitespace separates the
  single quote from the semicolon, as in `1' ; TRUNCATE TABLE accounts; --` and
  `7' ; DELETE FROM sessions; --`, which it missed before. An integration that
  blocks on the enforce lane blocks these too. Its benign false positives were
  re-measured: none over the 14,172 samples of the benign gate (#748, issue
  #620).

### Added

- **ATR-2026-02870: an invisible control before a directive in a tool
  description or skill file.** A zero-width, soft-hyphen or bidi control
  character at the start of a clause that tells the agent to ignore or
  override instructions, send or read secrets, conversations or credential
  files, or keep something from the user. Presence of the character alone
  does not match, so soft hyphens in German, ZWNJ in Persian, LRM/RLM in Hebrew
  and Arabic, emoji ZWJ sequences and a leading BOM stay clear. It reads
  `tool_description`, so it runs in a `tools/list` scan, on `mcp_exchange`
  events and on SKILL.md files. Maturity `test` (hunt and alert lanes). No
  benign false positives on the gate corpora or on the 710 tool definitions in
  `data/test-corpora/mcp-tools-list-benign/`, which contain no such characters,
  so that last figure is weak evidence. A control inside a word, rather than at
  the start of a clause, is ATR-2026-00276's case and not covered here (#749,
  from issue #653 by @Paraphern).

### Fixed

- **ATR-2026-00040 and -00064 matched the wrong chmod modes.** Their chmod
  condition matched the owner digit of `chmod 755 deploy.sh` or `chmod 700
  ~/.ssh` and missed `chmod -R 777 /`. They now match a world-writable mode or
  a setuid/setgid/sticky four-digit mode; with options such as `-R` before the
  mode, only when the target is the root, a system directory or the home
  directory, since `chmod -R 777` on an application subdirectory is documented
  practice in the benign corpus. Group-writable modes are not matched. Both
  rules are maturity `test` (#740, issue #735, from the probe in #658 by
  @PHM-Audit).
- **ATR-2026-00500, -00501 and -00505 are grounded in the vendor test cases
  they cite.** 00500 and 00501 matched 1 and 0 of promptfoo's SSRF and
  data-exfiltration test cases, and 00505 missed an llm-guard case with a
  typographic apostrophe. They now match all of them (3 of 3, 3 of 3, 6 of 6),
  their true positives that did not occur in any vendor repository were
  replaced by verbatim vendor cases with repository, commit, file and line,
  and -00503 and -00521 gained the vendor originals behind their shortened
  samples. On the pinned vendor suites, hunt-lane recall goes from 97 to 100 of
  126 attack cases; the ablation reference is unchanged (#709, measurement in
  #750).
- **ATR-2026-00223's samples use a documentation address** (203.0.113.30)
  instead of an address from a real dropper. Detection is unchanged (#738).
- **The release workflow commits the reconciled stats cache with the version
  bump.** The 4.2.0 bump reached `main` with `data/stats.json` still at 4.1.5,
  which failed CI on `main`; the published package was not affected (#746).
- **The Gemara catalogs' first publish reads oras's "not found" as
  unpublished.** The first publish from v4.2.0 stopped at the
  already-published check; this release tag is the first that can publish the
  bundle (#747).

## [4.2.0] - 2026-10-24

The first release since 4.1.5. For an integrator it changes three things at
runtime: the Claude Code guard reads what a tool returned instead of what it
was given, rules written for `context_window` and `skill_*` events now run on
the events their data arrives in, and a match that a model decided is
reported instead of enforced unless the integrator opts in. `atr scan` now
scans an MCP config file it used to skip, and an MCP `tools/list` document
as one event per tool, without running the rules written for a tool being
called. Many rule conditions that took polynomial time on long input were
rewritten, and three rules left the enforce
lane after matching benign samples. Like 4.1.5, the npm package carries the
rules without their test samples; the repository keeps them.

Default behaviour that changes, and how to keep the old one:

- Model-decided matches are advisory. A match from a semantic rule's judge
  that its own pattern fallback does not corroborate, from the embedding
  module or from the semantic layer is listed in `verdict.advisory` and no
  longer sets the verdict's outcome or dispatches more than observe-tier
  actions. To keep the old behaviour pass `modelDecisions: 'enforce'` to
  `ATREngine` or `computeVerdict()`, or use `--model-decisions enforce` or
  `ATR_MODEL_DECISIONS=enforce` with `atr scan` and `atr mcp`. Integrations
  that wire no model, including `atr guard` and the bundled adapters, see no
  change (#720). `verdict.highestSeverity` and `highestConfidence` now
  describe only the matches the outcome came from (read `advisorySeverity`
  for the rest), and `atr scan --json` gives every match `decided_by` and
  `enforced`.
- More of what an agent sees reaches the rules. A guard registered under
  Claude Code's PostToolUse now scans the tool's output, where it used to scan
  the tool's input; registering it under PostToolUseFailure as well also scans
  failed calls (#715, #721). Rules of type `context_window` and `skill_*` now
  run on typed runtime events (#701). The OpenShell filter
  and NemoClaw preflight adapters evaluate in the hunt lane and deny at `high`
  and above by default (`ATR_MIN_SEVERITY`), so they can now deny on
  ATR-2026-00070 and -01774 (high, `llm_input`/`llm_output`) and
  ATR-2026-00157 and -02405 (critical, `tool_call`), where 4.1.5 did not. Both raise matches in
  the hunt lane, the engine default, including on benign text (measured
  figures under Fixed below); neither moves the enforce lane. There is no
  switch back. An integration that blocks on PostToolUse should block on the
  enforce lane: `atr guard --blocking --lane enforce` (or `ATR_BLOCKING=1
  ATR_LANE=enforce`), or `lane: 'enforce'` on `ATREngine`. The guard's default
  lane is hunt, so `--blocking` alone blocks on the hunt-lane matches above.
- ATR-2026-00080, -00436 and -01606 moved from maturity `stable` to `test`
  after matching benign samples in the grown corpus (#625). They still alert;
  an integration that blocks only in the enforce lane no longer blocks on
  them.
- ATR-2026-00012 moved from maturity `test` to `experimental` (#683), so it
  runs in the hunt lane only and no longer in the alert lane. ATR-2026-00233,
  a duplicate of ATR-2026-00228, is deprecated and runs in no lane (#666).
- `atr scan` on an MCP config file scans one event per server (#581, by
  @ciceroyang), and on an MCP `tools/list` document, bare or in a JSON-RPC
  response, one event per tool (#737). 4.1.5 skipped both and reported them
  clean. Any JSON file `atr scan` reads in which no event reaches the engine
  now exits 1, in text, `--json` and `--sarif` output alike; `events_scanned`
  counts only events that did, beside a new `events_skipped`. A CI step that ran
  `atr scan` on such a file and always passed may now fail, on the exit code or
  through `--fail-on`. The GitHub Action ignores the exit code (#575) but counts
  the new findings toward `fail-on-finding`. Scanning a directory that holds
  only an MCP config is not fixed yet (#575).

Under SPEC §10 this is a minor release: the rule format, identifier scheme and
Match output are unchanged (matches gain an optional `decidedBy`, which §7
allows). SPEC.md moves to 1.0.1, a [Compatible] correction of §6.4 (#699).
SPEC §10 versions the format, not the package's defaults, and some defaults
change above. 4.0.0 went major because every `atr guard` user lost a block
they had by default. Here an integration that wires no model loses no block;
one that wired a model judge and blocked on its decisions does, and one that
blocks in the hunt lane, as `atr guard --blocking` does on PostToolUse and the
OpenShell and NemoClaw adapters do, can gain blocks. If that describes your
integration, apply the switches above or stay on 4.1.5.

### Added

- **New rules, all at maturity `test`** (hunt and alert lanes, not the
  enforce lane): ATR-2026-02815, -02817 and -02820 (#612); -02858, -02859 and
  -02860, technique rules for llm-guard samples lost to earlier FP repairs
  (#668); -02855, -02861 and -02862 from the FN-mine sweeps (#650, #671);
  -02864, -02865, -02866, -02867 and -02868 from agent-related CVEs published
  2026-09-22 to 2026-10-21 (#730, #731).

- **The category registry as Gemara catalogs, generated and published from
  here.** `spec/category-registry/gemara/` holds a vector, capability, threat
  and control catalog validated against the Gemara v1.6.0 CUE schemas. The
  vector catalog is generated from `spec/category-registry/v1.0.yaml` (ids and
  descriptions verbatim) by `scripts/generate-gemara-catalogs.ts`;
  `tests/gemara-catalogs.test.ts` fails when the committed catalogs are stale.
  `.github/workflows/publish-gemara.yml` publishes them as one keyless-signed
  OCI bundle, `ghcr.io/agent-threat-rule/agent-threat-rules/gemara:<bundle
  version>`, on release tags only, and pushes nothing when that version is
  already published with the same catalogs.

- **`atr test` reports a true positive that matches only through a copy the
  test event makes.** The test event offers a case's input under every alias a
  rule might read, whatever the event type: as `user_input` and `tool_args`, and
  its content as `agent_message`. `buildEventFromTestCase` gains a `runtime`
  field set, which holds what this repository's producers put on an event of the
  type: content, the fields the case names (taken as given), `user_input` on an
  `llm_input` event, and on a tool event the `tool_name` and `tool_args`
  `src/hook-handler.ts` fills. `caseMatchesAtRuntime` runs a case on that set
  for every event type, the engine's source filter deciding which of them the
  rule runs on, or as a skill document. `atr test` lists a passing true positive
  that matches none of them under `harnessOnly` (JSON) and "Harness-only"
  (text); it still counts as passed. No true positive on main is one.
  ATR-2026-01610's two cases declared as `user_input` match their `llm_input`
  event only through the input copied into `tool_args`; the engine also runs
  `llm_io` rules on `tool_response` events, where the hook fills `tool_args`,
  and there they match. `tests/testcase-runtime-parity-rules.test.ts` runs every
  rule's true positives the way `atr test` does, leaving out a type the engine
  withholds as `atr test` does, and fails on one.

- **Every benchmark measurement records the enforce lane beside its
  headline.** A measurement's `metrics.recall` is the `hunt` lane (the engine
  default, every maturity). Each runner the weekly measurement calls now also
  runs the same samples through its own detection loop on an engine
  constructed with `lane: 'enforce'` (only `maturity: stable` rules, the lane
  for blocking) and records the result as `breakdown.enforce_lane`. Where a
  measurement records it, README's Recall cell cites both lanes and root
  `stats.json` cites the enforce figure as `enforceLaneRecall`;
  `scripts/check-benchmark-citations.ts` fails CI when either disagrees with
  the measurement or leaves the enforce figure out. Before this, the enforce
  figures in README were one-off replays.
- **Recall figures outside README are rendered from the measurement files.**
  `scripts/render-recall-citations.ts` fills the figures between recall
  markers in `LIMITATIONS.md` and the `docs/owasp-pr/` texts, from the file each
  source's `latest.json` points at, in both lanes (every rendering is held to
  the rule README's table is checked by). `scripts/sync-citation-garak.ts`
  generates the garak sentence in `CITATION.cff` from root `stats.json`, with
  both lanes and the closed-book caveat. The weekly measurement run re-renders
  and stages both and lists what it could not render in the rolling PR's body;
  CI (`eval.yml`) fails on a stale or unrenderable figure.
- **`scripts/bench-evaluate-latency.ts` times single `ATREngine.evaluate()`
  calls** in the hunt and enforce lanes on three committed corpora of
  different input length, so the latency wording in LIMITATIONS.md and
  THREAT-MODEL.md can be checked on any hardware. The `latency_ms` blocks in
  `data/measurements/` time whole corpus samples (several event shapes, a
  skill scan and, when installed, an embedding pass) inside a full benchmark
  run, and are not comparable.
- **CI re-checks the /red-team page's links against GitHub.** The page's list
  of offensive tools and corpora moved out of the page into
  `website/data/red-team-tools.json`. `scripts/verify-red-team-links.mjs`, run
  by `verify-red-team-links.yml` when the list or the checker changes and
  weekly, fails when an in-review entry's PR or issue is no longer open, an
  in-production entry's PR is not merged, a corpus entry's link is neither a
  merged PR nor a commit on the default branch, or the `stillPresent` file an
  in-production or corpus entry must name no longer holds its text. It
  reports drift, links that are gone, and lookups GitHub could not answer
  separately, and counts none of them as a pass; a failure on main or on the schedule opens a tracking issue.
  It would have flagged NVIDIA/garak#1676 within a week of its withdrawal on
  2026-08-04, instead of the ten weeks it stayed listed before #688. It cannot
  flag an open proposal nobody answers, which is why the page calls that group
  "Open proposals". The three corpus entries linked to ATR PRs #51, #52 and
  #53, which do not contain the rules they named; they now link to the commits
  that added ATR-2026-00452..00456, 00500..00505 and 00510..00517, the second
  no longer names NeMo-Guardrails as a rule source, and every figure they and
  the page's 2026-05-12 sprint section quote now comes from a measurement file
  or a committed re-run record. HackAPrompt is quoted per lane on its pinned
  4,780-prompt subset, followed by its ablation reference (the same prompts
  without the rules whose YAML names HackAPrompt), read from
  `breakdown.in_sample_ablation` of the measurement file and called what it is,
  an approximation of out-of-sample recall rather than an out-of-sample result;
  the vendor-suite entry is followed by its own. The sprint's 28.6% to 66.2%
  becomes the re-measured 28.6% to 66.0%: 66.2% could not be reproduced at the
  sprint commits `e9efefdd` and `92c0d0fe` (66.0% at best), and the 28.6% is
  itself in-sample. The paper is described as listed under Best Paper Awards at
  EMNLP 2023, on gpt-3.5-turbo, FlanT5-XXL and text-davinci-003 (not
  GPT/Claude/PaLM). The 2026-05-12 import is described as 79 of 94 samples
  occurring verbatim in the vendor file they name. The sprint added 71 rule
  files, not 75 (the 2.2.0 entry also counted four earlier CVE rules), and the
  claims that the sprint's and the 2026-06 mega-scan's rules all passed the
  quality gate with 0 benign FP are replaced by the gate re-run on 2026-10-19
  and again on 2026-10-22 (`data/gate-reruns/2026-10-19_red-team-rule-batches.json`):
  at 92c0d0fe, 10 of the 71 failed (own true positives) and none flagged a benign
  SKILL.md file; at main b9d16840 on 2026-10-22, 33 of 71 and 4 of 29 fail, and
  26 and 3 flag at least one benign sample, none of them in the enforce lane,
  the same as at 9d74fc50 on 2026-10-19 although nine of the recorded rules
  changed in between. Each corpus entry links its
  measurement file.

### Changed

- **Three rules left the enforce lane.** ATR-2026-00080, -00436 and -01606
  each matched benign samples in the grown corpus and were demoted from
  maturity `stable` to `test` (#625). ATR-2026-00233, a duplicate of another
  rule, is deprecated (#666).
- **Six rules follow MITRE ATLAS v2026.07.** AML.T0019 and AML.T0104, retired
  into AML.T0115 as sub-techniques, are replaced by AML.T0115.000 and
  AML.T0115.002 in the rules' `references.mitre_atlas` (#543).

- **A match a model decided is reported, not enforced, unless the integrator
  opts in.** Three engine paths turn a model's output into a match: a semantic
  rule's `semanticJudge`, the `embeddingModule` similarity signal (which in the
  hunt and alert lanes could produce a critical `block_input` match), and the
  `semanticModule` layer. No evidence a response tier is earned from measures
  them: the benign-corpus evidence runs the synchronous engine, where a semantic
  rule is its pattern fallback, and neither the embedding module nor the
  semantic layer. Every match now carries `decidedBy`, and
  `computeVerdict()` keeps a model-decided one out of the outcome and dispatches
  only its observe-tier actions; it is listed in the new `verdict.advisory`
  (with `verdict.advisorySeverity`), and `highestSeverity` and
  `highestConfidence` now describe the matches the outcome came from. A
  semantic rule whose judge matches is enforced when the rule's own pattern
  fallback matches the same input (reported as the fallback's match); a judge
  match the fallback does not corroborate is advisory. Rule, invariant,
  blacklist and fingerprint matches decide as before. `modelDecisions:
  'enforce'` on the engine (or on `computeVerdict`) restores the previous
  behaviour; any other value throws. `computeVerdict` now sorts the matches it
  is given instead of trusting their order.
- **`atr scan` and the MCP server follow the same default.** `atr scan
  --semantic` lists a judge-only match but leaves it out of `--fail-on`, and
  writes it to SARIF at level `note` with `properties.enforced: false`, which the
  GitHub Action no longer counts toward `fail-on-finding`. JSON and SARIF output
  name what decided each match (`decided_by`). The MCP scan tool reports a
  judge-only match with outcome `allow`, `enforced: false` and observe-tier
  recommended actions. `--model-decisions enforce` or
  `ATR_MODEL_DECISIONS=enforce` restores counting for `atr scan` and `atr mcp`.
  `atr guard` and the bundled adapters wire no model, so nothing they do
  changes.

- **The ReDoS gate now times long inputs, every branch of an alternation
  and input tiled with a pattern's own openers, and its baseline grew from 9
  to 439 conditions because of it.** Nothing got slower; the gate started
  looking. Two integrations packaging the corpus found conditions that took
  seconds to minutes on 8,000- and 50,000-character inputs while
  `scripts/gate-redos.py` reported them clean: its inputs were 1,500 to
  3,000 characters, where a quadratic condition costs about a tenth of a
  second, and only the first branch of an alternation was ever pumped. Each
  condition is now also run on 20,000-character inputs built per quantifier
  -- the text that reaches the quantifier, through whichever branch,
  lookbehind or back-reference leads there, followed by a long run of its
  own body -- and on its openers and pumped near-match tiled to length
  (#601). Each worker calibrates per chunk and times are reported in
  reference-machine seconds, which reduces, but does not remove, the effect
  of load that changes during a run. `data/redos-baseline.json` now lists
  439 conditions in 259 rules: 350 over the budget when it was written (201
  of them did not return within the wall even timed alone) and 89 under the
  budget but over a third of it, recorded too because one condition's
  readings spread by more than 2x across runs and machines. 41 are in the
  enforce lane and 412 are high or critical.
  Each entry carries a fingerprint of its pattern, so editing a baselined
  condition makes it new again instead of inheriting the exemption; an
  unchanged baselined hang is not re-run. The gate stays a ratchet: it fails
  on a slow condition outside that file. `scripts/verify_rule_redos.py` now
  uses the gate's own inputs and timing -- it had reported PASS on
  ATR-2026-02372 with both conditions hanging -- and with `--base REF` also
  times a changed condition on the inputs derived from its previous pattern.
  Twelve conditions that Python `re` cannot compile, and that the gate
  skipped without saying so, are now listed by key. pyatr runs eleven of
  them through its `regex` fallback and the TypeScript engine compiles all
  twelve, so they run in production and are still untimed here; the twelfth,
  ATR-2026-00290#3, back-references a group that does not exist, which pyatr
  refuses and JavaScript reads as the character U+0001 (#331). The semantic
  lane's per-draft ReDoS precheck now allows 300 s instead of 120 s.

- **Every recall figure the site, LIMITATIONS.md, CITATION.cff and the docs
  above take from the measurement files now names its lane** and gives the
  enforce figure wherever the measurement records one. Figures no measurement
  file records are labelled instead: the about page's historical garak figure
  as taken with every rule loaded, the neutral-benchmarks post's runs as having
  no recorded lane. The website reads `breakdown.enforce_lane` from the measurement
  files (home, coverage, research, red-team, garak integration, ATD and
  sovereign-AI pages, the PINT blog post); it no longer reads recall
  from the old eval report files or their typed fallbacks, and no longer
  hydrates recall in the browser. The garak figures carry the closed-book
  caveat, and so now do the PINT-format and HackAPrompt figures, which have
  rules mined from them too. The SKILL.md benchmark is described as the
  internal, labelled corpus it is, with the harness's layer names. An erratum
  (`e-2026-10-16-recall-lanes`) records the change on the site.
- `sync-stats.ts` now fails when CITATION.cff has no garak sentence to
  rewrite, instead of leaving an old figure in place.
- **`scripts/check-rules-safety.ts` checks that a modified rule still matches
  its own true positives, and checks renamed rules.** A new rule's true
  positives had to match; a modified rule only had to add no benign false
  positive, and a rule that matches nothing adds none. `npm run
  gate:generalization` covers pattern rules only, so a semantic rule whose
  `fallback_method` was set to `none` passed every check. The new own-TP check
  runs each true positive on both paths `atr test` tries, replaying every case
  to the changed rule as the event the base rule would receive: a case the
  base rule matched on a path (`evaluate()`, `scanSkill()`) must still match
  there, one the change adds must match, and the changed rule must still match
  one of the cases the base rule matched. That also catches re-routing a rule
  away from its cases. A rule of a type the engine withholds from typed events
  (`WITHHELD_SOURCE_TYPES`), which `atr test` reports as unevaluable, is
  skipped while it stays that type. A renamed rule file was on neither the new
  nor the modified list and skipped both checks; it is now compared with the
  file it was at the base, and a changed file whose rule id differs is checked
  as a new rule. `npm run validate` also checks a semantic rule's
  `fallback_method` (`pattern` or `none`, compared exactly, as the engine
  does), its `threshold` (a number from 0 to 1), and that a pattern fallback
  has a condition to match.
- **`scripts/check-rules-safety.ts` runs a new rule's true positives the way
  `atr test` does (Check 2).** It read only a case's `input` and ran it as the
  text of the benign corpus shapes. On main, as if each rule past Check 1 were
  new, 250 true positives in 54 rules carry their payload elsewhere
  (`tool_response`, `tool_args`, `tool_description`, a `user_input` key, an
  object `input`, ...) and were never read; 47 of those rules had none read
  and passed with nothing run. The routing a rule declares was never
  exercised. Each case now runs as the event built from it for the rule's own
  `agent_source.type`, and through `scanSkill()`, with the code the own-TP
  check for modified rules uses (`scripts/lib/own-true-positives.ts`), and its
  text must still match on the corpus shapes, so a case that fires only
  through a tool name, which no benign sample exercises, fails. The semantic
  lane's pre-gate runs the same code. A case that cannot be run fails, and so
  does a rule of a type the engine withholds from typed events
  (`memory_access`), whose cases `atr test` reports as unevaluable. A new rule
  the benign checks cannot run at all (deprecated, or a trace, behavioral or
  signature method) is refused with the reason; Check 2 used to fail most of
  them only because it could not match their cases either, and one whose cases
  carried no `input` passed the whole gate.
- **README §8 discloses that the `garak` and `garak-full` figures are partly
  closed-book.** A replay without the rules whose own YAML shows they were
  written from the in-the-wild corpus is given in the new `[^garakcorpus]`
  footnote, and the paragraph on the two `garak` rows no longer calls them
  independent: `garak-full` contains that corpus twice.
- `data/stats.json` no longer carries the orphaned `benchmark.pintRecall`
  block, a 3.5.11 figure nothing has written since #600 and nothing reads.

### Fixed

- **`atr scan` scans an MCP config file instead of skipping it.** The file was
  parsed, wrapped as one event without `content` and skipped, while the
  summary counted it as scanned, so a config that sets `NODE_OPTIONS` to a
  `require` payload came back as no threats. Each server in the document is
  now its own event, `events_scanned` counts what reached the engine beside
  `events_skipped`, and a file with nothing scannable exits non-zero (#581,
  by @ciceroyang; issue #575, where directory scans and the Action's exit
  handling remain open).

- **Rule conditions that took polynomial time on long input were
  rewritten.** 86 conditions in 48 rules found by the extended ReDoS gate
  (#704), eight conditions quadratic in a long run of one character (#723),
  and ATR-2026-00063 and -00228 (#666). The rewrites keep the language of
  each condition, except four deliberate changes in #704:
  ATR-2026-00446 condition 0 widens, and ATR-2026-01005 condition 1 and
  ATR-2026-01307 conditions 0 and 1 narrow. ATR-2026-02261 condition 0
  narrows on purpose in #723 (its back-reference no longer ties two different
  variables), and ATR-2026-00228 condition 1 in #666 (on JSON-encoded content
  the two labels must be on one line). Conditions still over the gate's
  budget stay listed in `data/redos-baseline.json`.
- **Rule false positives.** ATR-2026-00012 matched 1,817 of 14,157 benign
  samples and now matches 150, with every match of the new version also a
  match of the old one (#683). ATR-2026-02010 no longer matches blank or
  whitespace-only input (#704). ATR-2026-00013 also flags apex
  loopback-wildcard domains (CVE-2026-55096) and its IPv6 condition matches
  IPv4-mapped obfuscation only (#732, #733).
- **`atr scan` scans an MCP `tools/list` document, one event per tool.** A file
  holding `{"tools": [...]}`, or the JSON-RPC response `{"jsonrpc": "2.0",
  "result": {"tools": [...]}}`, was wrapped as one event with no content,
  skipped, and reported as "nothing was scanned", so the usual input for a
  tool-poisoning check reached no rule. Each tool is now an `mcp_exchange`
  event (`src/cli/mcp-tools-document.ts`): the content is the tool definition as
  JSON, input schema and per-parameter descriptions included, and
  `tool_name` / `tool_description` are set from the definition. A JSON array of
  such responses is accepted too. A document that lists no tools fails with
  "nothing was scanned" rather than reporting clean. `mcpServers` documents and
  event files are read as before. Tests: `tests/cli-mcp-tools-list-scan.test.ts`.
- **A tools/list scan does not run the rules written for a tool being called.**
  A definition defines a tool and calls none, but an `mcp_exchange` event admits
  every rule, so call rules (ATR-2026-00099 and others, which read the called
  tool's name and arguments) flagged every definition named `delete_*`,
  `*_reset` or `exec*`. New engine option `toolDefinitions` (`ATREngineConfig`,
  default false), which `atr scan` sets only for a tools/list document: a rule
  with `agent_source.type: tool_call` then runs only if one of its conditions
  reads `tool_description` (the test is per rule: such a rule runs with all its
  conditions), or if its subject is the tool's identity (`TOOL_IDENTITY_RULES`
  in `src/tool-definition-scope.ts`: ATR-2026-00060, impersonation); every other
  rule runs as before. No rule file changes; hooks, adapters, config documents
  and event files are unaffected. `atr scan --json` reports
  `tool_definition_scope`, `rules_evaluated` and `rules_skipped_by_scope` (SARIF:
  run properties) and the `tool_name` of each result, so a rule that was not run
  does not read as a clean result. An event that also carries a `tools` array
  is still scanned as an event. Documented in `docs/ARCHITECTURE.md` §3.2,
  `docs/schema-spec.md` (agent_source.type) and `docs/rule-writing-guide.md`.
  On 710 benign tool definitions from 45 official and vendor MCP servers,
  flagged definitions go from 58 to 6 (hunt) and 57 to 5 (alert); enforce is 0
  before and after, which says nothing here, since none of the rules involved is
  stable. The true positives of the rules that read `tool_description` give the
  same result with and without the scope: of 41, 39 fire (35 description texts,
  and 4 ATR-2026-00441 code snippets through its content conditions) and 2 do
  not (ATR-2026-00441 tool calls given as JSON with arguments, which are not
  definitions). The 6 remaining hunt-lane false positives come from rules this
  change does not touch: ATR-2026-01987, -00225, -00217, -00161 and -00569 (over-
  broad conditions) and a form match of ATR-2026-00579 (experimental); see
  `data/measurements/mcp-tools-list-benign/README.md`. The scope also costs
  detection: a poisoned definition that only a call rule catches (for example
  ATR-2026-00114) is missed in a tools/list scan; no malicious tool-definition
  corpus measures this yet. Tests:
  `tests/tool-definition-scope.test.ts`, `tests/cli-mcp-tools-list-scan.test.ts`.

- **On Claude Code, the guard scans what a tool returned on PostToolUse.**
  Claude Code sends a tool's output at the top level of the PostToolUse hook
  input, as `tool_response` (checked against the shipped 2.1.280 binary).
  `src/hook-handler.ts` read an output only from `tool_input.output` or
  `tool_input.response`, where Claude Code never puts one, so the event's content
  was the tool's input, and a prompt injection in a command's output, a file or a
  fetched page reached no rule. The event's content and `tool_response` are now
  the text of the output: `src/hook-tool-output.ts` keeps every string in it, as
  written, and leaves out binary data, what Claude Code keeps from the model,
  and labels and strings the tool only repeats from its input. A tool that edits
  a file returns the edit it made, so its event is still built from its input.
  `tool_args` stays the JSON of the input, and `tool_input.output` and
  `.response` are still read for a host that sends the output there, now as raw
  text in content too. Measured through the hook in the default hunt lane, each
  sample as a Bash command's output: the own true positives of the 746 rules the
  engine runs on a tool response (`llm_io`, `mcp_exchange` and `context_window`)
  match 3,852 of 3,890 times (0 before, and the same as a Read or MCP output);
  289 of PINT's 451 attacks match (0 before) and none of its 399 benign samples;
  1,246 of the 14,157 benign-corpus samples match a rule (0 before), most of them
  through rules at maturity `test`. In the alert lane 1,183 match, in the enforce
  lane none. Not covered: an output whose text exceeds 100,000 characters
  taken together (`MAX_EVAL_LENGTH`); and some rules take time quadratic in a
  long run of one character. `atr init` registers the guard on
  PreToolUse only, so this reaches an installation that added it under
  PostToolUse.

- **The guard also scans a failed tool call's output (PostToolUseFailure).**
  When a tool call fails, a Bash command whose exit code Claude Code counts as
  a failure among them (most non-zero codes; `grep`'s exit 1 is not one),
  Claude Code sends `PostToolUseFailure` instead of `PostToolUse`. Its input
  carries `tool_name`, `tool_input`, `tool_use_id`, `error`, `is_interrupt`
  and `duration_ms`, and no `tool_response` (checked against the shipped
  2.1.280 binary). The guard answered it "Unknown hook type" and allowed it,
  so ending a command with `; exit 1` kept its output from every rule. It now
  builds the event from `error`, the failure as the model sees it: for a shell
  command, its stderr and stdout after Claude Code's `Exit code N` line and
  abort note, which are left out. A command that printed nothing leaves no
  text, and its event is built from the input, as an output-less PostToolUse
  is. It answers in the PostToolUse contract under the `PostToolUseFailure`
  name, which Claude Code accepts, and with blocking on its `decision:
  "block"` reaches the model as a blocking error. Measured through the hook in
  the default hunt lane, each sample as a failed Bash command's error: the own
  true positives of the 746 rules the engine runs on a tool response match
  3,852 of 3,890 times (0 before); 289 of PINT's 451 attacks match (0 before)
  and none of its 399 benign samples; 1,246 of the 14,157 benign-corpus
  samples match a rule (0 before). On every sample the verdict and the rules
  matched are those of the same text as a Bash command's output on
  PostToolUse. Claude Code cuts a failed call's error to about 10,000
  characters; 1,117 of the benign samples are longer and were sent whole. To
  use it, register the guard under `PostToolUseFailure` too.

- **Flywheel shadow rules can match.** `ShadowEvaluator` compiled each
  condition with `new RegExp(value, 'i')`. A value that starts with `(?i)` is
  a SyntaxError in JavaScript, the error was swallowed, and the condition
  never matched. `RuleScaffolder` starts every pattern it writes with `(?i)`,
  so no rule the flywheel generated could match in shadow mode or reach
  promotion. Shadow conditions now go through the engine's own
  `compileRegexCondition()` (leading flag group removed per SPEC §6.4, `u`
  when needed, ReDoS gate) and `safeRegexTest()` (the engine's input-length
  limit), and a condition whose value is not a string is skipped instead of
  throwing. Shadow evaluation still differs from `ATREngine` in field
  resolution, operators, `condition: all`, Unicode normalisation and
  `agent_source` routing; those differences are unchanged.
- **Flywheel promotion needs a reviewed true positive, and promotes a rule
  once.** `ShadowEvaluator.getPromotionCandidates()` divided confirmed false
  positives by all matches, so a rule with no recorded feedback had an FP rate
  of 0 and became a candidate after its first match. Once shadow rules could
  match (above), `FlywheelManager.promoteReady()` would have handed such rules
  to `onPromote` with status `stable`, and the same rule again on every call.
  A rule is now a candidate only after at least `minReviewedMatches` (new
  `FlywheelConfig` option, default 1) matches with recorded feedback including
  a confirmed true positive; the FP rate is computed over reviewed matches; and
  `promoteReady()` hands each rule to `onPromote` once. A promoted rule keeps
  `maturity: draft`.
- **`RuleScaffolder` no longer writes a pattern that misses its own example
  payload.** An attack indicator is chosen by a broad test and writes a
  narrower pattern: "Ignore all previous instructions", "please ignore the
  rules above" and "disregard everything you were told" all selected the
  instruction-override indicator, whose pattern did not match them. An
  indicator now counts only when its pattern matches the payload, and the
  exact payload is used if nothing else does. Keyword patterns are now tried
  only at line starts, `(?:^|[\n\r\u2028\u2029])(?=[^\n\r\u2028\u2029]*word)...`,
  and exact patterns are the escaped payload without a surrounding `.*`. Both
  match the same inputs as before, but neither is quadratic on a long
  single-line input any more (about 7-12 seconds per pattern on 100,000
  characters before, about a millisecond now). An empty or whitespace-only
  example payload, which produced a pattern that matched everything, is now
  rejected. Output of `atr scaffold` and the `atr_submit_proposal` MCP tool
  changes accordingly.

- **SPEC §6.4 corrected: SPEC.md 1.0.1 [Compatible].** A `regex` pattern
  condition matches case-insensitively whether or not it begins with `(?i)`,
  and `m`, `s` and `x` in a leading flag group have no effect. The 1.0.0 text,
  added on 2026-07-19 (#340), said an engine applies the flags named in that
  group, which made a pattern without `(?i)` case-sensitive and gave `(?s)`
  and `(?m)` their dotAll and multiline meaning. Compatible: an engine that
  passes the conformance suite needs no change, because its true-positive
  fixtures already require case-insensitive matching; an implementation built
  to the 1.0.0 wording does. 1.0.1 also admits `x` in the group, which both
  engines already removed, says when the `u` flag applies, advises against
  modifier groups such as `(?-i:...)`, and adds a revision history (Appendix
  D). Issue #698 has the evidence; erratum `e-2026-10-19-regex-dialect`
  records the error. `tests/spec-regex-dialect.test.ts` and pyATR's
  `TestRegexDialectSpec64` pin the statements. `scripts/generate-sigma.py` no
  longer copies `m` and `s` from that group into exported Sigma patterns,
  where a backend would honour them; of the three rules on main that carry
  such a group, only ATR-2026-00450's `(?im)^...` condition matched
  differently because of it. Other exports that still follow the 1.0.0
  wording are listed in #698.
- **Rules with a `context_window` or `skill_*` `agent_source.type` run on the
  events their data arrives in.** `src/engine.ts` maps an event type to one of
  five source types and skipped every rule whose type differed, so a rule of an
  extended type never ran on a typed event: on the `tool_call` and
  `tool_response` events `src/hook-handler.ts` builds, ATR-2026-00070, -00075,
  -01155, -01774, -00134, -00157 and -02405 never fired, while `atr test` mapped
  their types to a base type and passed every case. The engine now does that
  mapping itself (`RUNTIME_SOURCE_TYPE`): `context_window` runs where `llm_io`
  rules run, the `skill_*` types where `tool_call` rules run, and a rule without
  `agent_source` no longer throws a `TypeError` that aborted the whole
  evaluation of a typed event. `memory_access` is withheld
  (`WITHHELD_SOURCE_TYPES`): ATR-2026-00075 also matches standing instructions
  in an ordinary chat turn ("From now on, always answer in French."), which the
  Mastra processor and the OpenShell filter, both blocking by default, would
  refuse; -00075 and -01155 still run only on an untyped event and in a skill
  scan, and a new `memory_access` rule fails the test suite until the type is
  mapped. `atr test` no longer maps anything, so what passes there is what the
  engine runs, and it reports a withheld type's cases as unevaluable, with the
  reason. The rule-latency gate profiles the five rules instead of listing them
  as unexercised. The benign-corpus measurement does not change, because its
  untyped shape already ran these rules; what changes is that their matches now
  surface at runtime in the hunt lane, the default: ATR-2026-00070 (high)
  matches 20 of the 14,157 benign samples. On the weekly benchmark suite three
  hunt-lane recalls rise: garak 601 to 602 of 650 and garak-full 1,989 to 1,991
  of 3,475 (one prompt, which -00070 catches on the tool-response channel and
  garak-full holds twice), and atr-self-test 310 to 312 of 321 (-00070's own
  true positives). No precision or false-positive figure moves (the new matches
  fall on attack samples), and no enforce-lane figure moves (none of the five
  rules is stable).

- **A tool event built from a test case always names a tool.**
  `buildEventFromTestCase` (`src/testcase-event.ts`, behind `atr test`,
  `scripts/validate-rule-testcases.ts` and the case-sensitivity gate) gave a case
  that names no tool the `tool_name` `""`, meant to keep the case's text out of
  `tool_name`. `src/engine.ts` reads a field only when it is truthy and, on a
  `tool_call` event, then falls back to the event's content, so a `tool_name`
  condition read the payload as the tool's name and a rule keyed on the tool
  could pass its cases without naming one. A tool event now carries
  `atr-test-tool` (`UNNAMED_TOOL`) when the case names no tool, as
  `src/hook-handler.ts` fills it from the host's tool call, and the
  case-sensitivity gate leaves that name out of the text it checks a condition
  against. No rule on main relied on the old behaviour: every true positive and
  true negative of every rule tests the same.

- **A test case's own `agent_message` is no longer replaced by its content.**
  `buildEventFromTestCase` set the field from the case and then copied the
  event's content over it, so a case that names an `agent_message` beside its
  input was run on the input there. No case on main names one.

- **A `medium` confidence label no longer depends on float rounding to stay
  out of `deny`.** A pattern match scored `0.7 + 0.1 * coverage`, and a
  `high`-severity match denies at `>= 0.8`. At full coverage that sum is
  `0.7999999999999999` in IEEE doubles, so the verdict was `ask` only because
  of the rounding direction; the same quantity as an integer percentage is
  `0.8`. Label-derived confidence is now computed in one place
  (`src/rule-confidence.ts`) on a basis-point scale, and a label below the
  deny threshold is capped one basis point under it. No verdict or
  auto-response decision changes. The raw `confidence` of a `medium` match at
  full coverage is `0.7999` instead of `0.7999999999999999`, and other
  partial-coverage values lose trailing float noise (`0.9500000000000001`
  becomes `0.95`). One displayed percentage moves as a result: a
  named-condition rule labelled `medium` at 3/4 coverage shows 78% (`0.775`)
  where the noise used to show 77%. No shipped rule reaches that cell.

- **A semantic rule without a pattern fallback is no longer recorded as
  measured clean.** The benign-corpus measurement
  (`scripts/gate-promotion-fp.ts`, and `scripts/remeasure-benign-fp.ts`
  through it) drives the synchronous engine, which returns null for
  `method: semantic` unless `detection.semantic.fallback_method` is exactly
  `pattern`; the judge runs only in `evaluateAsync()`. `fieldCoverage()`
  named trace, behavioral and signature as methods it cannot run, but not
  this one, and it skipped a rule with no condition field, such as a pattern
  fallback with nothing in it. Either was written down as `fp_count: 0,
  partial_measurement: false`, which `scripts/gate-action-eligibility.ts`
  graded `terminate` at maturity `stable` and `degrade` at `test`. Both are
  now recorded partial and capped at `observe`. No rule on main is in either
  state, so the committed evidence is unchanged. The skill-path check uses
  the same predicate; it used to read `fallback_method: Pattern` as
  `pattern`, which the engine does not, and it exempted a
  `scan_target: both` rule with no conditions.
- **NIST-related statements corrected across the docs and the website.**
  Pages described a NIST CAISI dialogue and position paper that did not
  happen, an RFI response ATR never filed, an OSCAL "Path 1" acceptance,
  and a quote NIST never published; they listed NIST among adopters and
  in a trust bar, and showed "100%" or "4/4 functions" for an AI RMF
  mapping that covers a subset of subcategories. usnistgov/oscal-content#338
  is described as what it is: open, reworked against NIST's AI RMF catalog,
  awaiting NIST review. The website changelog page now shows the notes on
  historical entries, which it used to drop.
- **Integration status, provenance, evasion and latency claims corrected.**
  The red-team page listed seven proposals as under review that their ATR
  author had withdrawn unmerged (NVIDIA/garak#1676 on 2026-08-04; HarmBench,
  AgentDojo, JailbreakBench, Counterfit, PromptInject and Damn Vulnerable MCP
  Server on 2026-10-14 and 15, six of them never answered). They are removed,
  along with the lapsed "On deck" schedule, and the garak, sovereign-AI,
  responsible-use, integrate and STANDARDIZATION-STATUS surfaces no longer
  call the garak integration or any OWASP PR open. The garak page and the
  contributor docs (QUALITY-GATE.md, TSC-ONBOARDING.md, REVIEWER-GUIDE.md,
  RULE-PRODUCTION.md, the issue-to-proposal PR text) no longer describe
  auto-merge, which has been off since 2026-06-03. The red-team and governance
  pages no longer promise a `metadata_provenance.discovered_by` field no rule
  has, and the home, red-team, about and quality-standard pages no longer
  credit daily auto-crystallization for growth that came from CVE sweeps,
  benchmark-miss mining and contributors. The sovereign-AI page no longer says
  ATR detects intent and cannot be evaded; LIMITATIONS.md and the
  responsible-use, integrate and research pages no longer say every rule
  carries evasion tests or that there are 64; LIMITATIONS.md and
  THREAT-MODEL.md now agree that the optional judge and embedding modules ship
  but are off by default. "Sub-millisecond", "< 5ms", "5ms pattern match" and
  "Done in 47ms" are replaced by how evaluation cost scales; the OpenShell
  example is marked as a sketch of a proposal OpenShell closed, and its
  timeouts now exceed a one-shot cold start. CITATION.cff no longer calls the
  rules hand-authored and says what the safety gate checks for added and
  changed rules; the OWASP PR text drops its 76-rule count and notes the PR
  was withdrawn. Errata `e-2026-10-16-integration-status`,
  `e-2026-10-16-evasion`, `e-2026-10-16-latency` and `e-2026-10-16-provenance`
  record the site changes.
- **A rule the engine does not evaluate no longer gets a false-positive
  record.** `scripts/gate-promotion-fp.ts --emit-measurement` wrote
  `fp_count: 0` for draft and deprecated rules, which the engine skips, so
  nothing was counted for them. `detection_fingerprint` does not cover
  `status`, so a one-line revival handed the rule that 0, and
  `scripts/gate-action-eligibility.ts` trusted it: at maturity `test`, enough
  for `block_tool`. Seven records in `data/benign-fp-measurement.json` were of
  this kind. The measurement now asks the engine (`ATREngine.evaluates`) and
  lists such a rule, or an id two loaded files share, under NOT MEASURED
  instead. Without `--filter-mode` that fails the gate: promoting a rule the
  engine does not evaluate no longer passes as clean.
  `scripts/remeasure-benign-fp.ts` leaves the same rules out, and measures in
  full, rather than extends, a record for a rule that was inert at its base
  commit. `scripts/promote-to-stable.ts` no longer counts a draft rule at
  maturity `test` as FP-clean.
- **The action gate refuses evidence that holds a record for a rule that is
  not live** (inert, or its file gone): exit 2, as for evidence taken on
  another corpus. A record carries no status, so the gate cannot tell a count
  taken while the rule was live from a 0 nothing measured, and left in place
  either is trusted the day the rule is revived or restored. Deprecating or
  deleting a rule now means re-emitting the evidence in the same change. The
  gate also reads a status that is not a string (`status: [draft]`) as live,
  as the engine does; it used to skip such a rule while the engine ran it.
- **Two rule files with the same name are both measured.** The measurement
  copied rule files into its scratch directory by file name, so of two
  same-named files in different directories only the last was read, and the
  other was reported clean.
- **`scripts/promote-to-stable.ts` no longer promotes on a 0 it did not
  measure.** A `maturity: test` rule whose conditions the benign corpus cannot
  fully exercise (a field no sample fills, such as `tool_name`, or a method the
  synchronous engine cannot run, such as `trace`) scored 0 false positives
  without being read, and `--write` promoted it to `stable`. Such a rule is now
  reported as not promotable; one that did false-positive stays with the rules
  that have false positives. No `maturity: test` rule on main is affected today.
- **verify-adopters.yml no longer fails when other commits land on main during
  a run, and its failures get noticed.** The job commits the refreshed
  `data/adopters-verification.json` straight to main with a plain push, which
  was rejected whenever another commit landed first, failing the run with
  nothing wrong in ADOPTERS.md (2026-10-07, 2026-10-15). It now rebases its
  one-file commit onto the moved main and retries, at most three times; runs
  one verification at a time per branch; and checks out the branch tip rather
  than the triggering commit, so a run that waited behind another starts from
  the data the other pushed instead of conflicting with it (the 2026-10-07
  shape: two adopter merges, each run writing the same file). A conflict with
  a hand edit of the generated file still fails the run. Four red runs in a
  row (2026-10-12 to 10-15) went unnoticed for days; a failure on main now
  opens one tracking issue, or rewrites the open one, and the next green run
  closes it. The issue lists drift only from a verification that finished.

## [4.1.5] - 2026-10-10

4.1.4 was staged on npm and removed by publish-time scanning before it could be
approved, like 4.1.1 to 4.1.3. 4.0.0 passed that scanning. What the 4.1 line
added were rules whose test samples are complete attack snippets: a
crypto-miner command line with a mining-pool URL, PHP, JSP and ASPX webshells,
and a Node.js reverse shell. This release carries the 4.1.4 rules and engine,
packaged without those samples.

### Changed

- **The npm package ships the rules without their test samples.** The release
  workflow removes `test_cases` and `evasion_tests` from each rule just before
  staging, after the tests have run on the full rules. The engine does not read
  them, so detection is unchanged: the same rules load and the same rules fire.
  The samples stay in the repository. With the package alone, `atr test` on a
  bundled rule has no samples to run, and `atr stats` reports zero TP/TN
  counts. DISCLOSURE says so.

### Fixed

- **ATR-2026-02600 no longer names a real public IP in its test samples.** Its
  two reverse-shell samples now connect to the documentation ranges 203.0.113.14
  and 192.0.2.4. The detection is unchanged.
- **ATR-2026-02627 describes the web shells it detects instead of quoting
  them.** Its description and one false-positive note quoted a working one-line
  PHP command shell; they now say what it is. The detection is unchanged.

### Changed

- **npm releases go only through the staged path in `publish.yml`.** The
  package is dual-use, so npm's policy lets CI stage a version but not publish
  one; a maintainer promotes it with 2FA. Three workflows could still put a
  version on the registry another way and have been removed:
  `publish-current-version.yml` (direct `npm publish` through trusted
  publishing), `publish-on-rules-merge.yml` (bumped and ran `npm publish` with
  `NPM_TOKEN` on pushes to `main`) and `npm-stage.yml` (approved staged
  versions from CI with `NPM_TOKEN`, skipping the maintainer's 2FA).
  `scripts/release.sh` now stops at the tag push instead of also publishing
  locally. No workflow references `NPM_TOKEN`, and
  `tests/npm-release-path.test.ts` fails if any workflow other than
  `publish.yml` gains a publish, stage or approve step.

## [4.1.4] - 2026-10-07

> Not published to npm (see 4.1.5).

The first release since 4.0.0 meant to reach npm. 4.1.1, 4.1.2 and 4.1.3 were
each blocked by npm's publish-time malware scanning, which reads the attack
strings in rule files as malware, so `npm install agent-threat-rules` still
returns 4.0.0. This release declares the package dual-use (see Changed below)
and goes through npm's staged publishing, approved by a maintainer with 2FA. It
carries everything listed under 4.1.3, 4.1.2, 4.1.1 and 4.1.0 below.

### Added

- **Four rules.** Each one passed the repository's PR checks, and is
  experimental, maturity `test`, with alert-level response actions only:
  - ATR-2026-02846: ignore-previous-and-following instructions (PromptInject
    goal hijacking), a semantic rule with a narrow regex fallback.
  - ATR-2026-02847: email exfiltration under a policy, audit or compliance
    pretext.
  - ATR-2026-02850: data exfiltration by email under a documentation pretext,
    including French phrasings.
  - ATR-2026-02851: a fake user turn inside content that instructs the agent to
    send an email.
  ATR-2026-02847, 02850 and 02851 come from human-written attack emails
  (LLMail-Inject). They fire on none of 526 real emails or 694 benign web pages
  presented as tool output, and each catches attack emails that were held out
  while the rule was written.

### Fixed

- **pyATR falls back for regex conditions Python's `re` cannot compile** (such
  as variable-width lookbehind) instead of dropping the condition (#554, thanks
  @dc-tw).
- **The test-case validator reads every key a test case can use.** It read four
  of nine and misjudged rules whose cases use the others. Its failure count on
  the current rules drops from 40 to 11, with no new failures (#607).

### Security

- **`atr tc pull` checks the rules a Threat Cloud endpoint returns before
  writing them, and no longer goes through a shell.** The response is now
  treated as untrusted: a rule is written only if its id has the form
  `ATR-YYYY-NNNNN`, its category is one of the schema's categories and no rule
  with that id is already in the repo; anything else is rejected without
  touching the disk. The validator then runs as a separate Node.js process with
  the file path as a plain argument. Before, the id and category came from the
  response unchecked and the validator was started through a shell, so a
  compromised or impersonated endpoint could affect the operator's machine
  beyond the rules directory. The category is also read from the rule's `tags`,
  not from the first `subcategory:` line in a compliance block, and the
  validator is found next to the installed CLI rather than in the current
  directory, so valid rules are no longer filed under the wrong directory or
  rejected when the command runs outside a checkout of this repo.

### Changed

- **The package is declared dual-use under the npm Dual-Use Content Policy.**
  npm's publish-time malware scanning, introduced in July 2026, blocked 4.1.1,
  4.1.2 and 4.1.3: rule files carry attack strings by design, as detection
  patterns and test samples, and the scanner treats them like malware.
  `package.json` now carries `"contentPolicy": {"class": "dual-use"}`, and a
  plain-text `DISCLOSURE` file at the package root says what the attack content
  is for and what the package does not do. Under that policy, CI may only stage
  a release; a maintainer approves it with 2FA before it goes live, so
  `publish.yml` now stages through trusted publishing and waits for the approval
  before creating the GitHub release.

## [4.1.3] - 2026-10-06

> Not published to npm (see 4.1.4).

The first release of the 4.1 line to reach npm; 4.1.2 did not either. Its
publish on 2026-10-01 went through trusted publishing (OIDC), printed
`+ agent-threat-rules@4.1.2`, and was placed in npm's staging queue instead of
being published. It never appeared on the registry, and a re-run on 2026-10-05
was refused with E409 ("Cannot publish over previously staged version"), so the
number is skipped like 4.1.1. The trusted publisher has since been set to allow
direct publishing. Rules, engine and spec are unchanged from the `v4.1.2` tag.

### Changed

- **The release workflow fails when the version never reaches the registry.**
  It now asks npm for the exact version after publishing, waits up to ten
  minutes, and fails before the GitHub release is created. Before, the check
  read `latest`, ran after the release, and only warned, which is how both 4.1.1
  and 4.1.2 went green without being published (#633).

## [4.1.2] - 2026-10-01

> Not published to npm (see 4.1.3).

The first release of the 4.1 line to reach npm. Until this one,
`npm install agent-threat-rules` returned 4.0.0. 4.1.2 carries everything
listed under 4.1.1 and 4.1.0 below. Rules, engine and spec are unchanged from
the `v4.1.1` tag; the README rewords one row of its ETSI mapping, which had
stated a conformance requirement as a fact about the corpus.

Neither earlier 4.1 tag reached the registry:

- `4.1.0` (tagged 2026-09-14): the publish step got E404 on the registry PUT.
- `4.1.1` (tagged 2026-09-22): the tag-triggered publish failed with EOTP, npm
  asking CI for a one-time password. A manual republish later that day was
  placed in npm's staging queue instead of being published, and the retry on
  2026-09-23 was refused with E409. npm does not allow publishing over a staged
  version, so the number is skipped.

The 4.1.1 entry below opens by calling itself the first 4.1 release to reach
npm. It was not; the entry is otherwise left as written.

### Changed

- **Releases publish through npm trusted publishing (OIDC).** `publish.yml` no
  longer reads a registry token. npm mints a short-lived credential for each
  run, bound to this repository and that workflow file, and generates the
  provenance attestation itself (#606).

## [4.1.1] - 2026-09-22

> Not published to npm (see 4.1.2).

The first release of the 4.1 line to actually reach npm. `4.1.0` was tagged on
2026-09-14 and never published — the publish step failed on an expired registry
token and nobody was watching, so for 30 days `npm install agent-threat-rules`
kept returning 4.0.0 while `main` moved 38 commits ahead. **4.1.1 carries
everything listed under 4.1.0 below, plus the entries here.** The version number
skips 4.1.0 on purpose, so that what is on npm and what the git tag points at are
the same tree.

### Security

- **`ATR-2026-00220` condition 2 backtracked catastrophically**, the same defect
  as condition 0 of the same rule, which was fixed in #531 — a quantified run of
  base64 characters between two unbounded `.*` gaps, with a literal at the end.
  Only condition 0 was rewritten at the time. Measured on Node against a
  base64-dense single line with no matching tail: 0.5s at 1 KB, 3.4s at 2 KB,
  **23.4s at 4 KB**. The gaps are now bounded and the run is fixed-length;
  the same inputs measure under a millisecond at 64 KB. All five of the rule's
  true positives still fire and all five true negatives stay clean, with
  condition 2 matching exactly the cases it matched before.
  Reported as GHSA-66x9-5vw9-3wv3 against condition 0, which 4.1.0 had already
  fixed; this closes the half of the rule that report did not cover.
- **The package no longer ships a default endpoint for detection data.**
  Reporting has been opt-in since 4.1.0, but opting in without naming a
  recipient silently picked one. `--report-to-cloud` now requires `--tc-url` or
  `ATR_TC_URL` and exits with an error naming the fix if neither is set. ATR is
  an open standard, not one collector's client: an operator who turns reporting
  on decides who receives it, and there is no address in the package to forget
  to change. Detection events now also carry an `X-ATR-Client-Id` header; the
  previous vendor-named header is still sent so existing collectors keep working.

> **Nine conditions still backtrack** and are listed in
> [`data/redos-baseline.json`](data/redos-baseline.json) with measured
> times — `ATR-2026-00285#0` and `ATR-2026-00272#0` are the worst at 16s and
> 14s, and `ATR-2026-00707#0` is `maturity: stable`, which means it runs in the
> enforce lane. The ReDoS gate is a ratchet against that file: a green gate
> means nothing got worse, not that the class is closed. Do not read this
> release as "ReDoS fixed".

### Changed

- `CHANGELOG.md` is now included in the npm tarball. The `files` allowlist had
  excluded it, so a release that fixed a security defect arrived at consumers
  with nothing in the package to say so.

### Fixed — external claims that overstated what had happened

- **The npm package `description` claimed a vendor product shipped the ATR rule
  pack.** What actually happened is that rules were merged into
  `cisco-ai-defense/skill-scanner`, an open-source scanner repository — not the
  same thing as shipping inside that vendor's product. The blurb is the single
  most-copied sentence in the project, so it now says what the package is and
  makes no adoption claim at all (#580).
- **Withdrew the two per-lane false-positive rates** published alongside the
  enforce/hunt split. Three defects, any one of which is disqualifying: both
  were measured on a subsample roughly a sixth of the corpus they were credited
  to; the benign corpus contained real jailbreak samples — material the rules
  are meant to catch, sitting in the set that defines a false positive — until
  an exclusion filter landed on 2026-08-04 (#373); and the ladder that produced
  the hunt figure depended on a file no longer in the repository, so that figure
  cannot be reproduced at all. A gap is more useful to an adopter than a number
  nobody can reproduce. Re-measurement against the current benign corpus is
  pending, and neither figure should be cited by anyone until it lands (#579).
- **Corrected the fiscal sponsor's legal identity.** Nine files carried an EIN
  that corresponds to no organization, and five of them additionally described
  the sponsor as a 501(c)(3) when it is a 501(c)(6). The distinction is
  substantive rather than cosmetic: funders that restrict grants to 501(c)(3)
  recipients would have been misled (#578).

## [4.1.0] - 2026-09-14

> **Never published to npm.** The tag `v4.1.0` exists, but the publish failed on
> an expired registry token and was not retried for 30 days. This version number
> does not exist on the registry and never will; everything below shipped in
> 4.1.1 instead.

At release: 825 rule files, 818 effective.

### Added

- **A benign-twin corpus: 1,788 benign counterparts to attack payloads**, across
  17 files, counted at the `v4.1.0` tag. Built so that a rule which fires on the
  harmless sibling of the attack it targets can be caught before it ships. It
  demoted one production rule on arrival.
- **Forty rules from the full proposal re-sweep**, landed as four batches of
  ten, plus fifteen from the CVE proposal backlog (#503, #504).
- **A precompiled rule digest for consumers that cannot take an engine**
  (#510), with a Python-verified variant, and a PyRIT digest that carries
  every field and names the scope it is safe to use (#511).
- `pyatr` 0.3.0: bundle refreshed, and the behaviour that had blocked the
  refresh unpinned (#507).

### Fixed — catastrophic backtracking

- **Eight rules could be made to backtrack catastrophically**; the patterns are
  rewritten and a gate now blocks the class from returning (#531).
  `ATR-2026-02610` condition 0 was fixed separately for the same defect.
- **`ATR-2026-01005`, the many-shot rule, is now linear** without giving up RE2
  portability — the obvious fix would have traded one for the other (#546).

### Fixed

- **Ten rules from the re-sweep were withheld rather than shipped**: each fired
  on its own benign twin from the same run, so the twin corpus caught them
  before release (#565). `ATR-2026-02604` was withheld earlier for the same
  reason.
- **`\u{...}` is a JavaScript-only escape, so ten rules never compiled outside
  the TypeScript engine** — they were silently absent for every other consumer
  (#509).
- The Sigma exporter did not preserve ATR's regex case semantics (#520).
- The AVID importer stopped at the API's page limit instead of enumerating all
  reports (#534).
- The quality gate now checks peer true negatives within the same PR (#529),
  and the website shows the effective rule count rather than the raw file count.

### Removed

- The one-shot bootstrap publish workflow, once it had served its purpose
  (#541).

## [4.0.0] - 2026-08-22

> Releases 3.5.1 through 3.5.12 were automated rule-publish releases cut from
> this same stretch of history and were never given their own entries. A few
> items below — the benchmark-number corrections in particular — were first
> published in one of them rather than in 4.0.0.

### Changed — blocking is now opt-in (BREAKING for anyone relying on the old default)

- **`atr guard` no longer emits a `permissionDecision` unless blocking is
  enabled.** The Claude Code PreToolUse payload now carries the detection
  (`atr_decision`, `atr_reason`, `matched_rules`, `atr_advisory: true`) and drops
  the `hookSpecificOutput` envelope entirely, so the host applies its own
  permission flow. `toClaudeCodePostToolUse` likewise omits `decision: 'block'`
  (its envelope is kept: a permissive verdict has always emitted it with no
  decision inside).
  The whole envelope goes rather than just the decision field as a **legibility**
  choice, not a compatibility one. Both shapes are in fact accepted: the
  hook-output schema in the shipped Claude Code 2.1.76 bundle declares
  `hookSpecificOutput` optional, its PreToolUse member declares
  `permissionDecision` optional, and the object is not strict, so unknown
  top-level keys are stripped rather than rejected — which is also why
  `atr_decision` and `matched_rules` have shipped alongside it all along. A
  payload with no envelope simply cannot be misread as a decision that failed to
  serialise.

- **ATR never emits `permissionDecision: "allow"` — in either mode.** This is
  wider than the blocking switch and is the part most likely to surprise: turning
  blocking ON does **not** bring the affirmative decision back. In the PreToolUse
  contract `allow` is not neutral; it is an approval that suppresses the host's
  own permission prompt, so a hooked session would permit *more* than an unhooked
  one on every operation ATR simply had not looked for. "No rule matched" is ATR
  having nothing to say, and the way to say nothing on that channel is to omit
  the field. A decision is therefore emitted only for the two verdicts that
  **restrain** — `deny` and `ask` — and only when blocking is on. Everything else
  travels in `atr_decision` / `atr_reason` / `matched_rules`.
  Consequence for the payload shape: with blocking ON and a permissive verdict
  the `hookSpecificOutput` envelope is dropped too, exactly as in advisory mode.
  `atr_advisory: true` marks the *mode*, not the verdict, so it is the one key
  that distinguishes the two:

  ```console
  $ printf '%s\n' '{"hook":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"s1"}' \
      | npx tsx src/cli.ts guard --blocking 2>/dev/null
  {"atr_hook_event":"PreToolUse","atr_decision":"allow","atr_reason":"ALLOW: High-Risk Tool Invocation Without Human Confirmation [low/71% confidence] (1 rule matched)","matched_rules":["ATR-2026-00099"]}
  ```

  The PostToolUse contract needed no equivalent change: it has exactly one
  sentinel, `decision: 'block'`, and the absence of the key *is* the
  pass-through. There is no value that function could set to suppress a host
  behaviour.
- **BREAKING for embedders: the library no longer reads the environment at all.**
  `ATR_LANE` and `ATR_BLOCKING` are **CLI-only**. `ATREngine`, `ActionExecutor`
  and `HookHandler` take their posture from explicit config or the built-in
  default, and nothing else. If you embedded ATR and were relying on a variable
  in the ambient environment to select a lane, **that no longer works** — pass
  `new ATREngine({ lane })` instead.

  ```ts
  // With ATR_LANE=enforce ATR_BLOCKING=1 exported in the environment:
  new ATREngine({ rulesDir }).getLane()          // 'hunt'  (was: 'enforce')
  new ActionExecutor({ adapter }).isBlocking()   // false
  new HookHandler({ engine, executor }).isBlocking() // false
  ```

  Ambient configuration crosses trust boundaries invisibly. A `new ATREngine()`
  inside a VS Code extension, a Mastra pipeline, or the `/openshell-filter`,
  `/nemoclaw-preflight` and `/mcp` entry points never asked to be reconfigured by
  a shell profile — and because `enforce` is a *valid* value, the old behaviour
  produced no warning at all while narrowing those callers to `maturity: stable`
  rules only.
  The guarantee is **structural, not a convention**: `resolveLane` and
  `resolveBlocking` now require an `EnvSource` argument with no `process.env`
  default, so there is no overload that can fall through to the environment. Two
  new library-facing helpers, `laneFromConfig()` and `blockingFromConfig()`, pass
  a frozen empty environment; the new `resolveEnforcementPolicy()` is the only
  function that reads `process.env` **for these two switches**, and `src/cli.ts` is its
  only caller. `resolveLaneOrWarn`, `resolveBlockingOrWarn` and
  `resetEnforcementWarnings` are **removed**.
  One deliberate exception: `src/mcp-server.ts` reads `ATR_LANE` when the file is
  the process entry point, because that makes it a CLI rather than a library. An
  importer of the `./mcp` subpath does not reach that branch and gets its lane
  from the explicit option.
  Not the only function in the package that reads the environment: ten files
  under `src/` read it in code, and two of them — `adapters/openshell-filter.ts`
  and `adapters/nemoclaw-preflight.ts` — read `ATR_MIN_SEVERITY` and still block
  by default, as the scope limit below records. `grep -rl "process\.env" src/`
  returns eleven rather than ten: `src/index.ts` only names the variable in a
  comment. An earlier revision of this paragraph published that grep count.

- **Scope limit, stated so the headline is not read wider than it is.** This
  covers the two channels the engine itself drives: the Claude Code hook
  contract and `ActionExecutor`. It does NOT cover the framework adapters, which
  keep their own severity floor: `src/adapters/mastra.ts` defaults
  `blockSeverities` to `["critical", "high"]`, and the `openshell-filter` and
  `nemoclaw-preflight` CLI entry points default `ATR_MIN_SEVERITY` to `high`.
  (The `NemoClawPreflight` and `OpenShellFilter` classes take no default at all —
  an embedder must pass `minSeverity`. Only the CLI wrappers supply one.)

  They stay as they are, and the reason is measured rather than assumed. Driving
  each adapter through its own API, with the event shape it really constructs:

  | adapter | corpus | blocks |
  |---|---|---:|
  | `ATRProcessor` (mastra) | 432 benign skills, fed as user messages | 6 (1.4%) |
  | `NemoClawPreflight` | the same 432 as skill bundles — its actual domain | 2 (0.5%) |
  | `OpenShellFilter` | 24 everyday developer commands | 1 (4.2%) |

  Three caveats on those figures, because they are small enough to be quoted
  carelessly. Feeding skill files to a Mastra processor is out of domain — it
  sees chat messages, so 1.4% says little about real traffic. Twenty-four
  hand-written commands are not a corpus. And the benign skill set has the blind
  spots `scripts/gate-corpus-visibility.ts` exists to surface.

  The one real blemish is the command `OpenShellFilter` refused:
  `scp -i ~/.ssh/deploy.pem dist.tgz ci@build.corp:/tmp/`, an ordinary
  deployment. That is a rule being too wide, not an adapter default being wrong,
  and it is the same shape review already recorded against the scp work.

  Reproduce with `npx tsx scripts/measure/adapter-defaults-<adapter>.mts`. Each
  script aborts before printing if its control fails, so a zero there means the
  measurement did not run rather than that nothing blocked.

  Unlike the hook, these adapters are not installed by a script into a global
  config. An integrator imports one and wires it into a pipeline on purpose,
  which is what an explicit operator directive looks like. An earlier draft of
  this entry was going to bring them under the same switch on the strength of a
  19.9% figure; that number came from feeding raw content straight to
  `engine.evaluate` without the `type` each adapter sets, which bypasses the
  `agent_source` filtering and fires rules the adapters never see.

- **An unrecognised `ATR_LANE` or `ATR_BLOCKING` warns on stderr, falls back to
  the safe default, and the guard keeps running (exit 0).** `main` did not read
  either variable, so a typo was previously inert. An earlier revision of this
  branch threw from the constructor instead, which measured badly:
  `ATR_BLOCKING=enabled npx atr guard` exited 1 with an empty stdout and no guard
  running — landing hardest on the operator trying to turn enforcement ON.
  `atr init` installs `atr guard` as a PreToolUse **command hook**, and Claude
  Code 2.1.76 maps any exit status other than 0 or 2 to a non-blocking error: it
  runs the tool anyway, hands the model nothing, and renders only
  `<hookName> hook error` **without** the captured stderr. Exiting would have
  discarded every detection and still not told the operator why; status 2, the
  only loud one, blocks the tool outright, which a stray shell variable must
  never do. The warnings are printed once, at startup, by the CLI — they are not
  deduplicated per value, and the `resolveLaneOrWarn` / `resolveBlockingOrWarn` /
  `resetEnforcementWarnings` helpers that did that are gone. Verbatim, prefixed
  `[atr]` (red on a TTY):

  ```text
  [atr] Invalid ATR_LANE="enfroce". Expected one of: enforce, alert, hunt. Falling back to lane "hunt". Detection still runs; this only changes which maturities may fire.
  [atr] Invalid ATR_BLOCKING="enabled". Expected one of: 1/true/yes/on or 0/false/no/off. Falling back to blocking=false. If you meant to enable enforcement, it is NOT enabled.
  ```

  A bad **flag** still exits 1 — `atr guard --lane enfroce` and
  `atr scan --lane enfroce <target>` both print
  `Error: Invalid --lane "enfroce". Expected one of: enforce, alert, hunt.` and
  stop. A flag is typed at a prompt by someone who will see the exit code; an
  inherited variable is not. An explicit bad argument
  (`new ATREngine({ lane: 'enfroce' })`) still throws for the same reason.

- **An unreadable `ATR_LANE` forces blocking off, even against an explicit
  `--blocking`.** Falling back to `hunt` while blocking stays on is the one
  degraded posture that is *more* dangerous than the one requested: the operator
  asked to enforce on `maturity: stable` rules only and would instead enforce on
  every maturity. `--blocking` says "you may block", not "block on a lane I never
  chose". `ATR_LANE=enfroce atr guard --blocking` therefore exits 0 in advisory
  mode, having printed the lane warning above plus:

  ```text
  [atr] Blocking disabled: ATR_LANE could not be read, and blocking on the fallback lane "hunt" would enforce on more rule maturities than you asked for. Fix ATR_LANE to re-enable enforcement.
  ```

- **Both switches now trim whitespace and ignore case, identically.** They were
  asymmetric: `ATR_BLOCKING=ON` worked while `ATR_LANE=ENFORCE` did not, so the
  pair `ATR_LANE=ENFORCE ATR_BLOCKING=ON` turned blocking on **and** silently
  widened the lane to `hunt` — the operator asked for the narrowest enforcement
  posture and got the broadest one. `ATR_LANE=ENFORCE`, `ATR_LANE=" alert "` and
  `--lane Alert` are all honoured now.

- **A non-boolean explicit `blocking` throws instead of enabling blocking.**
  `new ActionExecutor({ adapter, blocking: "false" })` and
  `new HookHandler({ engine, executor, blocking: "false" })` previously turned
  blocking **on**, because every non-empty string is truthy — reading, to their
  author, as an explicit "off". Both now raise a `TypeError`, whose message in
  full is:

  ```text
  Invalid blocking value "false" (string). Expected a boolean. Note that any non-empty string, including "false", would otherwise enable blocking.
  ```

  The lane path validated its explicit value from the start; a switch that fails
  toward *more* enforcement was the wrong asymmetry to leave in place. This is
  BREAKING for any JavaScript or JSON-config caller that was passing a string.

- **`ActionExecutor` no longer dispatches response actions above the `observe`
  blast-radius tier unless blocking is enabled.** `alert` / `snapshot` /
  `shadow` / `escalate` run exactly as before; `block_input` / `block_output` /
  `block_tool` / `reduce_permissions` / `reset_context` / `quarantine_session` /
  `kill_agent` are recorded as suppressed and the adapter is never called. The
  tier ladder is read from `src/quality/action-eligibility.ts` — this change does
  not introduce a second classification of what is destructive.
  This closes the dual-channel contradiction where a benign
  `Bash{command:"ls -la"}` produced `permissionDecision: "allow"` while the
  executor really invoked `blockTool` on the adapter.
- **Both channels are governed by one switch**: the `blocking` config field on
  `ActionExecutor` and `HookHandler` for embedders, and `--blocking` /
  `--no-blocking` or `ATR_BLOCKING` on `atr guard` for the CLI. Default off. The
  environment variable reaches the CLI only — see the embedder entry above.
- **Why**: `SPEC.md` §5.5 (Response) is the engine-wide requirement, quoted
  whole because it is short enough to be: "Engines MUST NOT execute response
  actions automatically without an explicit configuration directive from the
  operator. The `response` field is a recommendation expressed by the Rule
  author, not a directive to the Engine." That directive had no implementation —
  no CLI flag, no environment variable, no documented config key by which an
  operator could express it. This change is that implementation.
  Two narrower statements point the same way. Neither is the requirement, and
  neither may be quoted as a general rule:
  - `spec/atr-method-v1.1.md` §5.6 (Provenance and Trust) sits under §5
    Signature Method and is scoped to hash matches: "Engines SHOULD NOT
    auto-block on a hash match without operator policy explicitly enabling it;
    the default response action SHOULD be `log_alert` until provenance is
    operator-trusted." An earlier revision of this entry quoted that sentence
    with "on a hash match" elided, which turned a Signature-Rule SHOULD NOT into
    an engine-wide one. It is not one. Quote it whole or cite §5.5 instead.
  - `docs/QUALITY-STANDARD.md` ("For Consumers") restricts blocking to
    `maturity: stable` with confidence ≥ 80. That is deployment guidance
    addressed to consumers, not a normative requirement on engines.
- **Turning blocking on reproduces the previous behaviour on every verdict that
  restrains — and only those.** An earlier revision of this entry claimed the
  two transcripts were "byte-identical". They are not, and the difference is the
  point of the change. Measured by replaying the 850 samples of
  `data/pint-benchmark/pint-corpus.json` as **850 hook events per hook type**
  (one JSON line in, one JSON line out) through `atr guard`'s stdio loop —
  `HookHandler` → `evaluateWithVerdict` → `ActionExecutor` — on the pre-change
  merge-base `994b01b2b` with no flags, and on `b9da8d710` with `--blocking`.
  The rule corpus is byte-for-byte identical at those two commits
  (`git diff --name-only 994b01b2b..b9da8d710 -- rules` is empty), so every
  difference below is the contract change and nothing else.

  | Hook | Events | Byte-identical output lines | Differing |
  |---|---:|---:|---:|
  | `PostToolUse` | 850 | **850** | 0 |
  | `PreToolUse` | 850 | 85 | **765** |

  `PostToolUse` is unchanged outright. On `PreToolUse` the 85 identical lines are
  exactly the events where the baseline emitted a decision that **restrains** —
  81 `deny` + 4 `ask` — and all 85 of those match byte for byte. The 765
  differing lines are every event where the baseline emitted
  `permissionDecision: "allow"`; on this branch all 765 carry no
  `hookSpecificOutput` key at all.
  Restricted to the 451 samples labelled `label: true` (the attacks), the same
  replay gives 85 identical / 366 differing — i.e. **ATR was affirmatively
  pre-approving 366 of 451 known attacks**, including under
  the `enforce` lane, where no `stable` rule matched and the whole payload was

  ```json
  {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"No rules matched."},"atr_decision":"allow"}
  ```

  captured on 994b01b2b through the TypeScript API rather than the CLI, because
  the predecessor had no `--lane` flag to set the lane with. The excerpt an
  earlier revision quoted here was the inner `hookSpecificOutput` object, not
  the payload.

- **Detection is unchanged in both modes.** Over the same 850 × 2 events,
  `matched_rules` is identical to the baseline on 850/850 for both hooks in both
  modes, and `atr_decision` equals the baseline's internal decision on 850/850.
  Blocking changes what the engine *does*, never what it *sees*.

### Added — the detection lane finally has an entrance

- `ATREngineConfig.lane` existed and worked but no shipped code path ever set it
  and no user-facing entry point could, so `hunt` was the only reachable setting.
  Added `--lane <enforce|alert|hunt>` to `atr guard` and `atr scan`, the
  `ATR_LANE` environment variable, and a `lane` input on the GitHub Action.
  `ATR_LANE` is read by the **CLI surfaces only** — `atr guard`, `atr scan`, and
  `src/mcp-server.ts` when it is the process entry point. It is *not* honoured by
  every `ATREngine`: an engine constructed by an embedder ignores it entirely.
  See the library/environment entry under "Changed" above.
- **There is no single resolution order any more, and conflating the two was the
  bug.** They are different chains on different surfaces:

  | Surface | Chain |
  |---|---|
  | Library (`ATREngine` / `ActionExecutor` / `HookHandler`) | explicit config **>** built-in default. The environment is not consulted. |
  | CLI (`atr guard`, `atr scan`) | flag **>** environment variable **>** built-in default. There is no programmatic config on this surface. |

  The old "explicit programmatic config > environment > default" described a
  chain that exists on neither surface.
  On the command line an unrecognised `--lane` value is a usage error, never a
  silent fallback: `atr guard --lane enfroce` prints
  `Error: Invalid --lane "enfroce". Expected one of: enforce, alert, hunt.` and
  exits 1, so an operator who typed it is not left believing they are enforcing.
  (`--blocking` / `--no-blocking` take no value; supplying one, as in
  `--blocking=maybe`, is not recognised as the flag and leaves the switch to the
  environment and then the default — it does not error.)
  An unrecognised value arriving from the *environment* is handled differently —
  see the `ATR_LANE` / `ATR_BLOCKING` entry under "Changed" above, which is the
  only place this file describes it.
- `atr guard` now prints its posture on stderr, preceded by
  `[atr-guard] Loaded <n> rules from <dir>`. Both modes carry a parenthetical,
  and the blocking one names the limit rather than claiming enforcement outright:

  ```text
  [atr-guard] lane=hunt blocking=off (advisory: detections are reported, nothing is blocked)
  [atr-guard] lane=hunt blocking=on (deny/ask only; never approves a tool call)
  ```

  `atr init` says in its success message that the installed hook is advisory.
  "Installed" must never read as "enforcing".

- **Provenance of the console output quoted in this entry.** Every payload,
  warning and posture line above is captured stdout/stderr from
  `fix/review-never-affirmative-allow` at `b9da8d710`, pasted unedited apart from
  stripping the ANSI colour codes on the `[atr]` warnings and rewriting the
  absolute rules path. This branch carries the documentation; `b9da8d710` carries
  the implementation. The commands reproduce these outputs once both have landed
  — not before.

### Fixed

- `src/hook-handler.ts` carried two contradictory comments about failure
  behaviour: the module header said fail-open, an inline comment in
  `startStdioLoop` said the error path "fail-closes to a deny". The header was
  right — `failOpen` defaults to `true` in both the constructor and the CLI. The
  inline comment is corrected; the behaviour is unchanged.

### Fixed — published benchmark numbers

- **Withdrew two garak figures that no measurement file backed.** From 2026-08-04
  to 2026-08-05, `README.md` and `stats.json` cited 91.5% (`garak` in-the-wild)
  and 56.9% (`garak-full`) at ATR 3.5.11. Neither run produced a file under
  `data/measurements/`; the newest files there were 95.7% at 3.5.8 and 38.3% at
  3.5.0 respectively. Re-measured on 2026-08-05 at 780 rules: **92.5%**
  (`garak`, 601/650) and **57.2%** (`garak-full`, 1989/3475), both written to
  `data/measurements/` with the commit that produced them.
- **Four eval harnesses built `type: 'llm_io'`**, which is a rule *source* and
  not an `AgentEventType`. `src/engine.ts` could not map it to a source, and its
  source-type filter is skipped when the mapping is absent — so instead of the
  narrow llm_io channel those harnesses documented, every rule of every source
  ran against the event. Affected: `eval-garak-inthewild.ts`,
  `eval-academic-raw.ts`, `eval-small-corpora.ts`, `atr_recall_analysis.ts`.
  `check-new-rules-on-benign.ts` had the same class of bug with
  `type: 'user_input'` behind an `as AgentEvent` cast. Event shapes now come
  from `scripts/lib/corpus-event.ts`.
- **`scripts/` is now typechecked** (`tsconfig.scripts.json`,
  `npm run typecheck:scripts`, wired into CI). `tsconfig.json` covered only
  `src/**`, which is why every one of the above was an unreported TS2322/TS2345.
- **`.github/workflows/rule-quality.yml`'s "Run PINT eval regression check"**
  ran `npm run eval` (the internal self-test harness, not PINT), read a
  git-committed report that step does not write, and looked up a key that does
  not exist on it — printing `PINT recall: undefined` while no downstream step
  read the result. It now runs `npm run eval:pint` and gates on recall/FP
  against the committed baseline.
- **`scripts/check-benchmark-citations.ts`** (new, runs in CI) fails the build
  when `README.md`'s benchmark table or root `stats.json` cites a number,
  ATR version, or date that `data/measurements/` does not back.

No rule content changed and no threshold was loosened in any of the above.

### Added — beyond the hook and lane work above

- **The Cisco Skill Scanner pack is now a build artifact** rather than a
  hand-assembled export (#495).
- **A rule the benign corpus cannot see has not been measured** — CI now says
  so instead of counting it clean (#460). The benign gate was also given the
  two corpora it had been missing (#468).
- `DETECTION-BOUNDARY.md` — what this layer detects and what it cannot (#461) —
  and `ENFORCEMENT-MODEL.md`, which also made three contradicted statements
  elsewhere in the docs true (#470).
- `ATR-2026-02502`: covert remote-script injection into generated artifacts
  (#462). The four tool-poisoning rules are mapped to MITRE ATLAS
  `AML.T0110.000` (#465), and the CSA MAESTRO mapping is refreshed against the
  current corpus (#464).

### Fixed — the guard was not reading real events

- **`atr guard` never read a real Claude Code event.** The shape it parsed was
  not the shape the host sends (#483). The event shape now follows
  `hook_event_name` as well as the dispatch, rather than the dispatch alone
  (#487).

### Fixed — rules that matched the wrong thing

- `ATR-2026-00086` was detecting Russian, not spoofing (#489).
- `ATR-2026-01904` read method calls as domains (#474).
- `ATR-2026-00443` read an ordinary sentence as fragment assembly (#473).
- `ATR-2026-01750` fired on descriptions of loops rather than demands for
  output (#472).
- An unquoted ATLAS `T0110.000` title broke the site build (#477).

### Measurement

- The benign false-positive evidence was re-derived at 785 rules (#497).
- ATR was measured against 36,394 published ClawHub skills across three event
  shapes (#490), and rule drift was measured against the 2026-04 wild scan
  (#491).
- The rule count in the standardization document was 357 rules out of date
  (#479), and five benchmark corpora were refreshed (#478).

## [3.5.0] - 2026-06-16

> **The two lane false-positive rates quoted in this 3.5.0 entry were withdrawn on 2026-09-19 and must not be cited.** The entry is left as published, because a changelog is a record of what was said at the time. See the withdrawal under [Unreleased] for the three defects that disqualified them; re-measurement is pending.

### Added

- **Detection lanes (`enforce` / `alert` / `hunt`).** Rules now carry a maturity-driven
  lane so consumers can trade recall for precision. On a 65K-sample benign gate: `enforce`
  (stable + confirm rules only) ~0.24% FP; `hunt` (all rules) ~9% FP. Default is `hunt`,
  opt-in and fully backward-compatible.
- **`confirm` field** — an embedding/secondary check that must pass before a match fires in
  the enforce lane. Four rules ship a `confirm: embedding` guard (ATR-2026-00001 / 00002 /
  00030 / 00442).
- **`src/quality/rule-contract.ts`** — a single shared contract (`MATURITIES`, `laneAllows`,
  `validateContract`) the engine and loader consume.

### Changed

- **652 detection rules across 10 categories.** Specification line `3.0.0-alpha.1`
  (Working Draft); this is the npm release line, tracked separately from the spec version.
- **23 rules reclassified** (maturity) to reflect measured precision and generalization.
- **ATR-2026-00495 deprecated** (garak DAN "insert prompt here" variant) — it now never fires.
  Spec-conformant; the only behavior change in this release.
- Python `pyatr` engine skips `deprecated` / `draft` rules, matching the TypeScript engine.

### Note

- Report false-positive rates lane-keyed (enforce ~0.24% / hunt ~9% on a 65K-sample benign
  gate), not as a single overall figure.

## [3.1.1] - 2026-06-05

### Fixed

- **ATR-2026-00001** (prompt-injection) false positive: the `start over/fresh/anew with a new …` task-switch branch matched benign phrasing such as "start fresh with a new outline" / "a new draft" because it lacked the task-noun constraint its sibling branches carry. Tightened to require a task-like noun (task / instruction / assignment / objective / goal / mission / prompt / persona / role / directive / job) after "new". The rule's documented true-positives are unaffected; full suite green (535 tests). Surfaced by the new semantic-validation corpus.

### Added

- **Semantic-validation harness** (`data/semantic-validation/` + `scripts/semantic-validation-score.mts`): a focused, reproducible corpus — 20 held-out paraphrased attacks targeting the two v3.1.0 semantic rules (00573 instruction-override, 00574 system-prompt extraction) plus 15 adversarial benign near-misses — and a scorer. Documents what the optional semantic stage actually adds on its two target threats, and ships the corpus so anyone can re-run it with their own judge.

### Measured

- Focused semantic validation (n=35, Claude-as-judge via worklist mode, threshold 0.7): the deterministic regex layer caught 10% of the paraphrased attacks; the optional semantic judge stage raised combined recall to 95% (19/20), with 0 judge false positives on the 15 adversarial benign near-misses (0 regex FP after the 00001 fix above). This is a small-n, authored, self-judged validation of the pipeline — NOT an independent benchmark. See `data/semantic-validation/README.md` for method and caveats.

## [3.1.0] - 2026-06-05

### Added

- **Tier-2 semantic detection (T2) — optional second-stage judge.** New two-stage scan pipeline (`scripts/scan-with-judge.mts`). Stage 1 is the existing deterministic regex engine run across the whole corpus; Stage 2 spends an LLM-as-judge only on the subset Stage 1 flags or misses (~2%), so judge cost scales with the flagged/missed set rather than the corpus. Opt-in by design: it runs only with an OpenAI-compatible backend (`ATR_SEMANTIC_API_KEY` [+ `ATR_SEMANTIC_BASE_URL` / `ATR_SEMANTIC_MODEL`]) or a no-key worklist mode (`WORKLIST_OUT`) that a separate session adjudicates and feeds back via `--verdicts`. Tunable `JUDGE_SUBSET` (missed | flagged | all) and `JUDGE_THRESHOLD`. The default `ATREngine.evaluate()` path stays 100% deterministic and the LLM judge is off by default — the two semantic rules contribute only narrow regex fallback patterns to the default path (FP-gated, with documented true-negatives); the judge stage is additive and opt-in.
- **ATR-2026-00573** (prompt-injection): semantic paraphrased instruction-override. Flags reworded injection that drops the literal trigger vocabulary (ignore / disregard / forget) that pattern rule ATR-2026-00001 keys on — the precise misses recorded in 00001's `evasion_tests`. Severity high, status experimental.
- **ATR-2026-00574** (context-exfiltration): semantic paraphrased system-prompt extraction. Flags indirect elicitation of the agent's system prompt or hidden configuration without the literal verb-first phrasing (reveal / show / print your instructions). Severity high, status experimental.
- Cisco-grade, human-reviewed exploitation rules for agent runtimes: path traversal, SQL injection, and reflected XSS (ATR-2026-00569 / 00570 / 00571), MCP command injection, and SSRF-to-cloud-metadata, plus CVE-anchored detections surfaced by the daily NVD collector.
- Daily CVE collector and ecosystem-scan automation now feed agent-package vulnerability proposals into the review queue (collection only; promotion stays behind the human safety gate).

### Changed

- Total rule count: 450 → 462.
- Two rounds of false-positive hardening on existing rules, gated by a wild-confirmed benign corpus and a dual-use security-skill bucket, so security tooling that legitimately ships attack strings no longer trips detection.
- Engine and rule format unchanged; existing ecosystem integrations (Microsoft AGT, Cisco AI Defense, MISP CIRCL, OWASP A-S-R-H, precize, Sage) work without modification.

### Deprecated

- **ATR-2026-00235** — exact duplicate of ATR-2026-00230; marked deprecated, retained for ID stability.

### Notes

- First npm release to carry the post-3.0.5 work. The Cisco-grade rules and hardening landed on `main` between 2026-05-29 and 2026-06-04 but stayed unpublished until now: the auto-publish flywheel fires only for Threat-Cloud-crystallized commits, so human-authored rule work ships on an explicit minor release like this one.
- Semantic rules are experimental and the T2 judge is opt-in; production blocking should continue to rely on the pattern rules. Benchmarks remain measured on the 3.0.0 baseline (see `stats.json`) and have not been re-run against the semantic stage.

## [2.2.2] - 2026-05-13

### Added

- **ATR-2026-00523** (skill-compromise): Claude Code Hooks SessionStart pre-trust RCE (CVE-2025-59536). Detects repo-shipped `.claude/settings.json` registering a `SessionStart` hook with the `startup` matcher; the hook command fires before the trust dialog renders. Six layered conditions: literal Hooks-schema shape anchor, shell-interpreter command resolution, pipe-to-shell / inline-exec payload shape, package-manager + credential-tool invocation, repo-path + payload co-occurrence, and pre-trust prose anchor. 7 TP / 6 TN / 3 evasion tests documented. Reported by Aviv Donenfeld and Oded Vanunu (Check Point Research); patched via GHSA-ph6w-f82w-28w6 enhanced trust-dialog warning.
- **ATR-2026-00524** (context-exfiltration): Claude Code ANTHROPIC_BASE_URL credential exfiltration (CVE-2026-21852, CVSS 5.3 Moderate). Detects repo-shipped `.claude/settings.json` or env-var configuration rebinding `ANTHROPIC_BASE_URL` to an endpoint outside the Anthropic-controlled allowlist (`api.anthropic.com`, Vertex `*.googleapis.com`, Bedrock `bedrock*.<region>.amazonaws.com`); pre-trust API request leaks the live `Authorization: Bearer` header. Seven layered conditions: JSON-form allowlist negative-lookahead, shell / dotenv / Dockerfile env-var form, bare public-IPv4 detector (excludes loopback + RFC1918), cleartext-HTTP detector against non-loopback hosts, repo-path + payload co-occurrence, pre-trust prose anchor, and CVE-identifier co-occurrence. 7 TP / 8 TN / 3 evasion tests documented. Patched in Claude Code >= 2.0.65 (GHSA-jh7p-qr78-84p7); PoC at github.com/atiilla/CVE-2026-21852-PoC.

### Changed

- Total rule count: 419 → 421.

### Anchors

- 2 Check Point Research disclosures against Claude Code: CVE-2025-59536 (Hooks SessionStart pre-trust RCE) + CVE-2026-21852 (ANTHROPIC_BASE_URL pre-trust credential exfil). Both share the same root cause class — repo-scoped `.claude/settings.json` parsed and acted on before the trust dialog gates the action — and both upstream patches narrow the trust-gate ordering. ATR rules anchor on the dangerous config shape so detection survives both pre- and post-patch deployments.

## [2.2.0] - 2026-05-12

### Added

- **75 new rules** across 5 categories (prompt-injection 57 + context-exfiltration 6 + tool-poisoning 4 + excessive-autonomy 2 + model-abuse 2). Total rule count: 344 → 419.
- 5 new rule source integrations: HackAPrompt (EMNLP 2023, 4,780 samples, ATR-2026-00452..00456), NeMo-Guardrails + llm-guard + Promptfoo vendor test suites (94 samples combined, ATR-2026-00500..00505), PromptInject (NeurIPS 2022, ATR-2026-00506..00509), OWASP LLM Top 10 + MITRE ATLAS PoCs (8 standards-aligned rules ATR-2026-00510..00517).
- 6-framework compliance metadata on all 75 new rules (OWASP / MITRE ATLAS / NIST AI RMF / EU AI Act / ISO 42001 / SAFE-MCP).
- 53 rules with regex generalized from literal corpus fingerprints to multi-layer structural patterns.
- 4 rules kept as KEPT-AS-IS corpus fingerprints (ATR-GARAK-a7fcb4e5 + 3 others): cannot generalize without unacceptable FP rate; marked experimental, not for production blocking.

### Changed

- Total rule count: 344 → 419 (357 stable + 62 experimental).
- NVIDIA garak wrapped rule count: 293 → 419.

### Metrics

- HackAPrompt (4,780 samples): recall 28.6% → 66.2% (+37.6pp), 100% precision maintained.
  - Erratum (2026-10-19): re-run on the same 4,780 samples at the sprint commits,
    recall was 28.6% (1,368, at `3a6145b7`) → 65.0% (3,108, at `e9efefdd`) and
    66.0% (3,154, at `92c0d0fe`); 66.2% could not be reproduced at either. The
    28.6% starting point was itself in-sample (ATR-2026-00442..00447 were mined
    from this subset). "100% precision" was not a measurement: the corpus has
    no benign samples, so precision is undefined on it. Procedure and figures:
    `data/hackaprompt/METHOD.md`; current measurement, with the ablation
    reference: `data/measurements/hackaprompt/`.
- garak (3,475 prompts): ATR-core families ~80%+; per-family breakdown: latentinjection 34.4%, sysprompt_extraction 67.9%, dan 90.2%.
- PINT (850 samples): 0.25% FP maintained, 0 FP regression.
- SKILL.md (341 samples): 100% precision, 0% FP, 0 FP regression.
- 0 FP regression on benign corpus (432 real-world benign skills).

### Scope

- PyRIT Pliny L1B3RT4S: refused — Anthropic usage policy prevented subagent import.
- AdvBench, HarmBench, JailbreakBench: reclassified to data/test-corpora/; describe target behaviors, not attack payloads.

## [2.1.4] - 2026-05-12

### Added

- **ATR-2026-00448** (tool-poisoning): Spring AI MilvusVectorStore filter-expression injection (CVE-2026-41705). Tautology-based deletion-broadening, paren-breakout, in-clause chaining, terminator-DROP, like-ESCAPE bypass primitive. 8 TP / 6 TN / 0 FP on 431-sample benign corpus.
- **ATR-2026-00449** (context-exfiltration): Spring AI PromptChatMemoryAdvisor cross-user memory leakage (CVE-2026-41712). Shared / singleton ChatMemory wiring, placeholder conversation_id, mismatched user-tag windows, wildcard-tenant scope. 8 TP / 6 TN / 0 FP.
- **ATR-2026-00450** (data-poisoning): Spring AI PromptChatMemoryAdvisor memory poisoning (CVE-2026-41713). Persistence-aware ignore-previous, bracketed `[SYSTEM-MEMORY-PERSIST]` canaries, smuggled role-tag prefixes, REMEMBER:-shaped persona override, ChatMemory.add(SystemMessage) sink-level concat. 8 TP / 6 TN / 0 FP.
- **ATR-2026-00451** (privilege-escalation): LiteLLM proxy admin endpoint SQL injection (CVE-2026-42208, CISA KEV 2026-05-08, CVSS 9.3, federal remediation due 2026-05-11). Tautology + comment-out, stacked DROP / TRUNCATE, UNION SELECT exfil, pg_sleep blind, Postgres metadata recon, error-based extractvalue / updatexml / load_extension. 8 TP / 6 TN / 0 FP.

### Changed

- Total rule count: 344 → 348.

### Anchors

- 3 Spring AI CVEs (CVE-2026-41705 / -41712 / -41713) disclosed 2026-05-08 in Spring Security Advisory; patches in Spring AI >= 1.0.0.
- 1 CISA Known Exploited Vulnerabilities catalog entry: CVE-2026-42208 added 2026-05-08, federal remediation due 2026-05-11, active exploitation observed against financial services and healthcare deployments; patch in LiteLLM >= 1.48.3.

## [2.1.3] - 2026-05-11

### Added

- 6 HackAPrompt-cluster rules (ATR-2026-00442..00447) + benchmark harness (PR #51). Auto-published via tc-pr-back release workflow after PR #51 merge.

### Changed

- Total rule count: 338 → 344.

## [2.1.2] - 2026-05-11

### Added

- **ATR-2026-00440** (agent-manipulation): Microsoft Semantic Kernel CVE-2026-26030 — In-Memory Vector Store lambda+eval RCE. AST-traversal-via-mro primitives, BuiltinImporter reflective access, Function-constructor variants. 8 TP / 5 TN / 0 FP on 466-sample benign corpus.
- **ATR-2026-00441** (privilege-escalation): Microsoft Semantic Kernel CVE-2026-25592 — SessionsPythonPlugin arbitrary file write to autostart paths. Windows Start Menu Startup, XDG autostart, systemd-user, cron, macOS LaunchAgents/Daemons, Windows Registry Run-key persistence. 7 TP / 5 TN / 0 FP.
- **`src/redact.ts`** new module: `redactMatchedValue()` + `redactMatchedValues()` helpers. ATR-consuming integrations can run `ATRMatch.matchedPatterns` entries through this before logging. Recognises AWS keys, GitHub tokens, Slack tokens, OpenAI/Anthropic keys, Bearer creds, JWTs, PEM keys. 13 unit tests. Additive opt-in API — no existing API changes.

### Changed

- Total rule count: 336 → 338.

### Loop closure

- Microsoft Copilot SWE Agent opened `microsoft/agent-governance-toolkit#1981` 2026-05-11 06:07 UTC with regression-test fixtures presuming ATR detection. PR #50 merged + v2.1.2 npm + GitHub release published within 2h 16m. Closing-the-loop comment mapped each fixture to ATR rule IDs.

## [2.1.1] - 2026-05-10

### Added

- 6 ATR rules covering 7 gap CVEs identified by Phase 1 audit (CVSS 9.1–10.0). PR #46 + follow-up batches.
- STIX 2.1 extension for `x-atr-rule` custom SDO (PR #49) — self-published extension definition; ATR rules can now be expressed as STIX SDOs for STIX-compliant consumers.

### Adopted (external)

- **MISP/misp-taxonomies#323** merged 2026-05-10 by adulau (MISP project lead). 10 ATR predicates + 330 rule IDs as MISP machine tags.
- **MISP/misp-galaxy#1207** merged 2026-05-10 by adulau. 336 cluster values with kill-chain, severity, CVE / OWASP LLM / MITRE ATLAS cross-refs. 10,408 lines.

## [2.1.0] - 2026-05-09

> **Historical entry — the AI RMF line below overstated coverage.**
> "100% coverage of all 4 AI RMF functions" described the community OSCAL
> catalog, which encodes all 72 AI RMF subcategories as controls. ATR's
> rules map to a subset of those subcategories. The catalog is a community
> contribution and is not endorsed by NIST. Do not quote the line as a
> coverage claim. (Note added 2026-10-16.)

### Added

- **NIST AI RMF mapping v0.2** — 100% coverage of all 4 AI RMF functions (Govern / Map / Measure / Manage), 72 controls + 31 cross-reference links + worked example profile. Schema-valid OSCAL catalog published under `Agent-Threat-Rule/ai-rmf-oscal-catalog` (PR #46).
- Dedicated `/compliance/nist-ai-rmf` page on website with 314 → 330 rule count refresh sitewide.

### Adopted (external)

- **OWASP/Agent-Security-Regression-Harness#74** merged 2026-05-11 by mertsatilmaz (OWASP Project Lead): "Welcome to the team."

## [2.0.11] - 2026-04-21

> **Historical entry — do not quote the garak or SKILL.md figures below.**
> The 97.1% in-the-wild recall was measured on a garak corpus that many of
> this release's new rules were written from, so it is not an out-of-sample
> result. The SKILL.md precision and FP figures are in-sample: the benign
> set is the one the rules were tuned against. Current figures, reported
> per lane and with their closed-book share, are in README §8 Evaluation.
> (Note added 2026-10-16.)

### Added

- **193 new rules** covering the full NVIDIA garak probe corpus (ATR-00300 ~ ATR-00414), bringing total to **311 rules**
  - **agent-manipulation**: DanInTheWild community jailbreak library batch 7-9, AntiDAN inverted persona, ChatGPT DevMode RANTI, Image-Markdown unlock, Ablation_Dan_11_0 generator-name binding, AutoDAN hierarchical suffix, Goodside ThreatJSON death coercion, Doctor XML policy puppetry
  - **prompt-injection**: latentinjection separator/keyword, leakreplay cloze MASK, glitch token repeat-back (SolidGoldMagikarp et al.), echo SQL-jinja template injection, DRA parenthesis reconstruction, phrasing past/future tense, LMRC harm category, FigStep image-list multimodal, continuation ethnic slur, backspace deletion character, LLM special-token boundary, toxic continuation prefix, snowball impossible reasoning, ecoji/base2048/variant-selector/sneaky-bits encoding injection, zalgo/braille/sata encoded attacks
  - **context-exfiltration**: markdown image URL exfil + XSS, API key generation and partial-key completion
  - **model-abuse**: malwaregen code generation (TopLevel + SubFunctions), HuggingFace unsafe model artifact load
  - **tool-poisoning**: ANSI escape elicitation request
- Word-boundary (`\b`) anchoring on grandma-roleplay rule to prevent partial-word FP (late/gran/read)
- `metadata_provenance.garak_probe` field for ATR-00267 (GCGCached), ATR-00301 (TAPCached), and all new rules
- Missing `true_negatives` added to 10 existing DAN-family rules (ATR-00352–00376) to meet ≥5 TN safety gate requirement

### Changed

- **Total rule count**: 113 → 311
- **garak in-the-wild benchmark recall**: 69.7% → **97.1%** (646/666 prompts detected against garak community jailbreak corpus)
- **SKILL.md precision/FP**: maintained 100% precision, 0% FP on 498-sample benign corpus
- FP mitigations applied to new rules (response action `[alert]` only for medium-FP-risk rules — phrasing, API key, malwaregen, SQL-jinja)

### Fixed

- ATR-00402 (grandma roleplay): added word boundaries to prevent `late`/`gran`/`read` substring FP in Firebase documentation
- ATR-00401 ([MASK]): required elicitation context to prevent NLP-documentation FP
- ATR-00403 (glitch tokens): required elicitation verb before token names (StreamerBot etc.) to prevent legitimate software reference FP
- ATR-00411 (API key gen): negative lookahead on "from your dashboard/console" to exclude documentation requests

## [2.0.10] - 2026-04-21

### Added

- garak coverage batch 10: ansiescape, badchars, realtoxicityprompts, topic, fileformats (ATR-00393~00398)

## [2.0.9] - 2026-04-20

### Added

- garak DanInTheWild coverage batch 8-9: jailbreak templates, emoji-flag, prompt-browser (ATR-00377~00392)

## [2.0.0] - 2026-04-15

> **Historical entry — do not quote these figures as current.** The scan counts,
> malware counts, benchmark rates and rule totals below are as published on
> 2026-04-15 at 113 rules. The wild-scan figures in particular are under
> reconciliation and are not a citable measurement; current corpus numbers live
> in `data/stats.json` and in README §8 Evaluation. The "Cisco AI Defense" line
> describes rules merged into the open-source `cisco-ai-defense/skill-scanner`
> repository — it is not a statement about any vendor product.

### BREAKING

- **Compound detection gate**: MCP rules now require 30%+ conditions to match in skill context. This prevents over-triggering when MCP-specific patterns appear in legitimate SKILL.md documentation.
- **Code block suppression**: Skill rules no longer suppress matches inside code blocks (they are instructions, not documentation examples).
- **All fields resolve to content in skill context**: `tool_description`, `tool_args`, `user_input` all map to the full skill content for static analysis.

### Added

- **26 new rules** (87 to 113 total, 9 categories):
  - ATR-2026-00149: Compound exfiltration (12 patterns: SSH archive, wallet, browser, DNS, IMDS)
  - ATR-2026-00158/159/160: TC-crystallized rules (first rules generated end-to-end by Threat Cloud)
  - ATR-2026-00161: Cross-tool shadowing via IMPORTANT tag (from Invariant Labs PoC)
  - ATR-2026-00162: Credential exfil combo
  - ATR-2026-00163: Hidden override instructions
  - ATR-2026-00164: Scope hijack
  - Plus 19 more across prompt-injection, tool-poisoning, and data-exfiltration categories
- **RFC-001 v1.1** (ATR Quality Standard):
  - Two-Dimensional Compliance Model (metadata presence + provenance)
  - L0-L5 Review Tier Levels (first standard to include LLM-assisted review as formal tier)
  - Community Signal Aggregation (confirmations, FP reports, evasion reports)
  - Multi-Runtime Compatibility (14 runtimes: Claude Code, Cursor, Hermes, OpenAI Assistants, Google A2A, etc.)
  - Relaxed experimental gate (3/3/0) for community velocity; stable tier retains full 5/5/3
  - Future Work: RFC-002 (Detection Types), RFC-003 (Collective Defense), RFC-004 (Enterprise)
- **GOVERNANCE.md v1.1**:
  - Permanent MIT license commitment (never BSL/SSPL)
  - MITRE ATLAS positioning: ATR = detection rules complement to ATLAS (like Sigma to ATT&CK)
  - ATR Numbering Authority specification
  - Technical Advisory Group roadmap
- **96,096 real-world skills scanned** (OpenClaw 56K + Skills.sh 3K + Hermes 123 + ClawHub 36K + MCP Registry 5K)
  - **751 malware skills discovered** (hightower6eu 354, sakaen736jih 212, 52yuanchangxing 137)
  - Research report: `docs/research/openclaw-malware-campaign-2026-04.md`
  - NousResearch notified (hermes-agent#9809)
- **Threat Cloud blacklist**: 554 entries uploaded from wild scan
- **4 export formats**: SARIF v2.1.0, Splunk SPL, Elasticsearch DSL, generic regex (714 portable patterns)
- **Exponential backoff for npm registry crawl** (fixes Daily Ecosystem Scan rate limiting)

### Changed

- Engine: compound gate for context-aware matching
- Confidence formula: cross-context penalty (0.7x) for rules firing outside their tested runtime
- SKILL.md denylist reduced from 22 to 10 rules (re-enabled low-FP rules for better coverage)

### Metrics

- 113 rules (7 stable, 85 experimental, 21 draft)
- 361 tests passing
- SKILL.md benchmark (498 corpus): 100% recall, 97% precision, 0.20% FP rate
- MCP benchmark (PINT 850): 62.7% recall, 99.6% precision
- Wild scan (96K): 1.35% flag rate, 751 confirmed malware
- OWASP Agentic Top 10: 10/10 coverage
- MITRE ATLAS: 100/113 rules mapped
- SAFE-MCP: technique coverage figure (withdrawn 2026-10: it was not backed by rule-level data; see docs/SAFE-MCP-MAPPING.md)
- Avg scan latency: 14ms per file

### Ecosystem

- **Cisco AI Defense**: 34 ATR rules shipped in production (PR #79 merged)
- **OWASP**: Attack examples contributed (PR #814 merged)
- **NousResearch**: Malware campaign reported (hermes-agent#9809)

## [1.0.0] - 2026-04-06

### BREAKING

- **Rule IDs**: 3-digit → 5-digit (`ATR-2026-001` → `ATR-2026-00001`). Zero-padded, detection logic unchanged.

### Added

- **ATR-SPEC-v1.md** — Formal rule format specification. Third parties can build conforming engines in any language.
- **GOVERNANCE.md** — Contribution process, quality gates, severity rubric.
- **`scan_target` metadata** — Every rule declares `mcp` or `skill`. Engines filter by scan context.
- **`rule_version` field** — All rules carry version number. Bump on detection logic changes.
- **Unified CLI** — `atr scan` auto-detects JSON (MCP) vs .md (SKILL.md).
- **`ScanResult` type** — Unified output with `scan_type`, `content_hash` (SHA-256).
- **MCP server `atr_scan_skill` tool** — 7 tools total.
- 6 new skill rules: context poisoning (00125), rug pull setup (00126), subcommand overflow (00127), HTML comment hidden payload (00128), unicode smuggling (00129), exfil URL in instructions (00135).

### Metrics

- 87 rules (75 MCP + 12 skill)
- 53,399 real-world skills scanned (skills.sh + OpenClaw)
- 670 confirmed malicious skills detected
- SKILL.md recall: 94.4%, FP rate: 0.096%
- MCP recall: 62.7% (PINT 850, unchanged)

## [0.3.0] - 2026-03-18

### Added

- Evaluation framework (`src/eval/`):
  - `npm run eval`: 341-sample corpus (321 attacks + 20 benign), 9 attack categories
  - `npm run eval:pint`: 850-sample external PINT benchmark
  - Per-rule quality metrics (TP/FP/matchCount per rule)
  - Confusion matrix, precision/recall/F1, latency percentiles
  - Regression gate (auto-fail on metric degradation)
  - JSON report output (`data/eval-report.json`)
- CI gate (`.github/workflows/eval.yml`): typecheck + test + eval + validate on PR
- 279 auto-extracted corpus samples from rule test_cases
- 8 new detection layers in ATR-2026-001:
  - forget-everything shorthand, task switching, system prompt extraction,
  - praise-then-redirect, German formal/informal, French injection patterns
- PINT benchmark integration (deepset/prompt-injections + Lakera gandalf datasets)

### Changed

- Embedding similarity threshold: 0.82 -> 0.65 (10 extra TP, 0 extra FP on PINT)
- Test count: 225 -> 246 (+21 eval framework tests)

### Fixed

- shadow-evaluator.ts type error (TS2352)
- Removed external product references from ATR-FRAMEWORK-SPEC.md
- Added temp file patterns to .gitignore

### Benchmark Results (honest numbers)

- Self-corpus (341 samples): Precision 100%, Recall 99.4%, F1 99.5%
- PINT external (850 samples): Precision 99.4%, Recall 39.9%, F1 57.0%
- Only 6/61 rules fire on external attacks
- See LIMITATIONS.md for full analysis

## [0.2.3] - 2026-03-16

### Added

- 9 new rules from Threat Cloud community promotion (ATR-2026-100~108):
  consent bypass, trust escalation, disguised analytics exfiltration,
  hidden safety bypass, persona hijacking, silent action concealment,
  schema-description contradiction, delayed execution bypass, Sybil attack
- Python engine (pyATR) v0.2.0: validate, test, stats CLI commands, 48 tests
- Splunk SPL converter (`atr convert splunk`)
- Elastic Query DSL converter (`atr convert elastic`)
- Layer 3 LLM-as-judge prompt templates (docs/layer3-prompt-templates.md)
- Automated scan pipeline (scripts/auto-scan-pipeline.sh)
- Deployment guide for external teams (docs/deployment-guide.md)
- MCP ecosystem security audit report: 1,295 packages, 14,299 tools
- npm crawler with pagination (795 → 2,769 discoverable packages)

### Fixed

- CLI test runner: handle tool_description field, fix event type mapping
- All 61 rules pass embedded test cases (556/556, 100%)
- CJK test cases moved to evasion_tests (honest: regex can't match them)
- Removed all external product references for ATR independence
- Fixed pyATR URLs pointing to wrong GitHub org

### Stats

- 61 rules (44 experimental + 17 draft)
- 556 test cases (100% pass rate)
- 164 TypeScript tests + 48 Python tests = 212 engine tests
- 12 SIEM converter tests

## [0.2.2] - 2026-03-14

### Fixed

- ReDoS vulnerability in SSRF rule (ATR-2026-013) — O(n^2) backtracking on long hostnames
- SSRF rule false positive on filesystem paths like /home/user/
- tool_args field extraction fallback for tool_call events

### Added

- True negatives for 21 rules with insufficient test coverage (7 had zero, 14 had only 1)
- Vitest coverage reporting with v8 provider (60%+ threshold on core modules)

## [0.2.1] - 2026-03-10

### Changed

- Standardized 17 predicted rule IDs (ATR-PRED → ATR-2026-080~096)
- Fixed rule validator for skill-compromise category
- Toned down coverage claims to reflect actual verification status

## [0.1.0-rc2] - 2026-03-09

### Added

- 32 initial experimental detection rules across 9 attack categories
- TypeScript reference engine with SessionTracker
- OWASP Top 10 for Agentic Applications (2026) mapping (6 covered, 2 partial, 2 gaps)
- 13 CVE reference mappings across 16 rules (pattern-based, not empirically verified)
- OWASP LLM Top 10 (2025) mapping (7 covered, 3 gaps)
- MITRE ATLAS technique references
- JSON Schema specification (spec/atr-schema.yaml)
- Built-in true positive and true negative test cases for every rule
- Attack corpus validation tests
- Coverage report (COVERAGE.md)

### Attack Categories

- Prompt Injection (5 rules)
- Tool Poisoning (4 rules)
- Context Exfiltration (3 rules)
- Agent Manipulation (3 rules)
- Privilege Escalation (2 rules)
- Excessive Autonomy (2 rules)
- Skill Compromise (7 rules)
- Data Poisoning (1 rule)
- Model Security (2 rules)
