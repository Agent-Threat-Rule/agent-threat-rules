# Changelog

All notable changes to ATR will be documented in this file.

## [Unreleased]

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

## [3.5.0] - 2026-06-16

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

### Added

- **NIST AI RMF mapping v0.2** — 100% coverage of all 4 AI RMF functions (Govern / Map / Measure / Manage), 72 controls + 31 cross-reference links + worked example profile. Schema-valid OSCAL catalog published under `Agent-Threat-Rule/ai-rmf-oscal-catalog` (PR #46).
- Dedicated `/compliance/nist-ai-rmf` page on website with 314 → 330 rule count refresh sitewide.

### Adopted (external)

- **OWASP/Agent-Security-Regression-Harness#74** merged 2026-05-11 by mertsatilmaz (OWASP Project Lead): "Welcome to the team."

## [2.0.11] - 2026-04-21

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
- SAFE-MCP: 91.8% technique coverage
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
