# Response-Action Eligibility

> A rule may not declare a response action more destructive than its measured
> false-positive evidence has earned. This document states the policy, shows the
> measurements it is built on, and names what it does not fix.

## 1. The defect

`src/action-executor.ts` filters on nothing. The words `lane` and `maturity` do
not appear in it. The lane gate in `src/engine.ts` decides whether a rule may
**fire**; after that `computeVerdict()` unions `response.actions` over every
match and the executor dispatches all of them in priority order.

So the detection lane named **alert** — documented in `ATREngineConfig` as the
"analyst/correlation lane" — executes `kill_agent` exactly as readily as the
enforce lane does.

This was reproduced, not inferred. `ATR-2026-00062` (`maturity: test`,
`severity: critical`, actions `block_tool, quarantine_session, alert, snapshot,
kill_agent`) was driven through `engine.evaluateWithVerdict()` against a real
benign corpus document — `data/skill-benchmark/benign/ninja-legit/ninja-020-computer-use.md`,
one of the 209 benign samples it false-positives on — with a recording
`PlatformAdapter`:

```
lane=enforce  fired=false outcome=allow
  ACTUALLY EXECUTED = []
lane=alert    fired=true  outcome=deny
  ACTUALLY EXECUTED = ["kill_agent","block_tool","quarantine_session",
                       "reduce_permissions","alert","escalate","snapshot"]
lane=hunt     fired=true  outcome=deny
  ACTUALLY EXECUTED = ["kill_agent","block_tool","quarantine_session",
                       "reduce_permissions","alert","escalate","snapshot"]
```

Same result through `HookHandler.handlePreToolUse` — the production path that
`atr init` wires into Claude Code:

```
[hook] lane=alert  permissionDecision=deny
  ACTUALLY EXECUTED = ["kill_agent","block_output","block_tool",
                       "quarantine_session","reduce_permissions","alert",
                       "escalate","snapshot"]
```

`kill_agent` runs **first** because `ACTION_PRIORITY` gives it 0 — the executor's
ordering encodes urgency, so the most destructive action is also the least
pre-emptable.

### 1a. What the shipped guard actually does — measured, and it is not the same claim

`atr guard` is the process `atr init` wires into the PreToolUse hook. It is the
only place in this repo that constructs an `ActionExecutor`
(`src/cli.ts` `cmdGuard`). Two things are true of it that must be said out loud:

**It runs in the `hunt` lane.** `cmdGuard` builds `new ATREngine({ rulesDir })`
with no `lane`, and `lane` defaults to `'hunt'` — every maturity fires,
experimental included. Run verbatim, one benign line on stdin:

```
$ echo '{"hook":"PreToolUse","tool_name":"Bash",
         "tool_input":{"command":"google-chrome --no-sandbox &"}}' \
  | npx tsx src/cli.ts guard
[atr-guard] Loaded 783 rules from rules/
{"type":"alert","severity":"critical","reason":"DENY: Hidden Capability in MCP Skill
  [critical/93% confidence] (3 rules matched)","matchCount":3}
{"type":"escalation",...}
{"type":"snapshot",...}
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...},
 "matched_rules":["ATR-2026-00062","ATR-2026-00040","ATR-2026-00099"]}
```

Launching headless Chrome is denied. That is a shipped, reproducible false
positive on the production path.

**But in ATR's own bundled adapters the destructive actions are inert.**
`StdioAdapter.blockTool / quarantineSession / reducePermissions / killAgent` push
an entry onto a private `responseBuffer`, and `flushResponses()` — the only
reader — is **never called anywhere in this repository**. `DefaultAdapter` is
explicitly a no-op. Only `alert`, `snapshot`, `escalate` and `shadow` produce
observable output, which is exactly what the transcript above shows.

So, precisely:

- The **executor** dispatches every declared action with no lane or maturity
  filter. That is real and was measured with a recording adapter.
- In **ATR's own adapters** the terminate-tier actions currently do nothing.
- ATR is a standard that downstream consumers implement adapters against.
  `response.actions: [kill_agent]` in a rule file is an instruction to every one
  of them. The rule file is the interface, and it is the interface that is
  currently making an unearned claim.

This policy therefore fixes the **claim in the rule file and the executor path**,
before an integrator implements a `killAgent` that kills. It does not fix the
`deny` in the transcript above — see §3.

Two secondary findings from the same run:

- `response.auto_response_threshold` is dead. `isAutoResponseEnabled()` in
  `src/verdict.ts` is exported and never called by the engine, the executor or
  the hook handler. The one field that reads like a brake on automatic response
  is not wired to anything. (`ATR-2026-00062` declares
  `auto_response_threshold: critical`, a value the function's own map does not
  even contain.)
- The executed set is the **union across every matched rule**. On that one benign
  document four rules fired; `quarantine_session` was contributed by three of
  them independently. Fixing one rule does not stop an action another co-firing
  rule still carries — which is why this has to be a fleet-wide policy and not a
  per-rule fix.

## 2. Why this line and not more regex tightening

Measured on this same rule set:

| intervention                           | FP reduction | recall cost |
| -------------------------------------- | ------------ | ----------- |
| tighten the regex                      | −64…95%      | **−64…67%** |
| remove an action the rule never earned | 0            | **0**       |

Removing `kill_agent` from a rule does not make it detect less. It fires,
matches, reports and alerts exactly as before. It simply stops destroying a
session it was never shown to be right about. It is the only intervention in this
area with no recall side.

## 3. What this policy does NOT buy

Measured, so it cannot be overclaimed. Same corpus document, same lane, one rule
patched to `actions: [alert, snapshot]`:

```
BEFORE  outcome=deny permissionDecision=deny
  EXECUTED = [kill_agent, block_tool, quarantine_session, reduce_permissions,
              alert, escalate, snapshot]
AFTER   outcome=deny permissionDecision=deny
  EXECUTED = [block_tool, quarantine_session, reduce_permissions,
              alert, escalate, snapshot]
```

Three things to read off that:

1. `kill_agent` is gone. That is the win, and it is real.
2. `quarantine_session` and `block_tool` remain, contributed by the other rules
   that fired on the same document. Fleet-wide application is the only thing that
   closes this.
3. **`permissionDecision` is unchanged.** `computeVerdict()` derives
   allow/ask/deny from `severity` and `confidence` alone; `response.actions` is
   not an input. Stripping every action off a `severity: critical` rule still
   leaves the hook returning `deny`. This policy governs **executed response
   actions**, not the hook's block decision. Anyone quoting it must say so.

## 4. The blast-radius ladder

Actions are ranked by what survives them, not by how loud they are. This is
deliberately **not** the executor's priority order.

| tier | name        | actions                                     | what survives                                                                         |
| ---- | ----------- | ------------------------------------------- | ------------------------------------------------------------------------------------- |
| 0    | `observe`   | `alert`, `snapshot`, `shadow`, `escalate`   | everything; the agent does not notice                                                 |
| 1    | `interrupt` | `block_input`, `block_output`, `block_tool` | the agent and its state; one operation is denied and can be retried                   |
| 2    | `degrade`   | `reduce_permissions`, `reset_context`       | the agent; its capabilities or working memory are altered for the rest of the session |
| 3    | `terminate` | `quarantine_session`, `kill_agent`          | nothing; in-flight work is lost and cannot be retried                                 |

Only these eleven are ranked, because only these eleven are dispatchable —
`ACTION_METHOD_MAP` in `src/action-executor.ts` has no entry for the SPEC
Appendix A names that also appear on disk (`require_human_review`,
`quarantine_artifact`, `rate_limit_source`, `log_alert`), so the executor returns
`Unknown action` and does nothing. `tests/action-eligibility.test.ts` pins the
tiered set equal to the dispatchable set, so implementing a new adapter method
fails the build until its blast radius is stated.

## 5. The policy

| measured benign FP                                                             | max tier    | why that line is there                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **no measurement**, or partial, or the detection changed since the measurement | `observe`   | absence of evidence is not evidence of precision. A gate that cannot read a measurement must refuse, not pass                                                                                                                                          |
| **> 2%**                                                                       | `observe`   | `docs/QUALITY-STANDARD.md`, STABLE demotion criteria: "Wild FP rate > 2% → Automatic demotion". A rule the standard would pull out of the production tier does not keep blocking while it sits there                                                   |
| **0.5% – 2%**                                                                  | `interrupt` | below the demotion line, above the production ceiling. A recoverable, per-operation denial is proportionate; a session-wide state change is not                                                                                                        |
| **> 0 and ≤ 0.5%**                                                             | `degrade`   | `docs/QUALITY-STANDARD.md` + RFC-001 §3: `wild_fp_rate ≤ 0.5%` is the STABLE promotion ceiling. It meets the production bar, yet is demonstrably still wrong sometimes — so a recoverable degradation is earned and an irreversible termination is not |
| **0 FP and `maturity: stable`**                                                | `terminate` | see below                                                                                                                                                                                                                                              |

**The two numbers are not new.** `0.5%` and `2%` are lifted unchanged from
`docs/QUALITY-STANDARD.md` (STABLE promotion and demotion criteria) and
`docs/proposals/001-atr-quality-standard-rfc.md` §3. This document maps the
project's own published precision lines onto blast radius; it does not invent a
threshold. On the current corpus of 5,352 benign samples they are 27 FP and
108 FP respectively.

**Why `terminate` needs more than a clean sweep.** Zero observed events in _n_
trials is not a zero rate. By the rule of three, the 95% upper bound is 3/_n_: a
clean sweep of 5,352 samples only certifies a true FP rate below roughly
**0.056%**. At agent-fleet event volume that is still a real number of destroyed
sessions. The published ladder already names the extra evidence that closes the
gap — `stable` requires `wild_samples ≥ 1000`, `wild_fp_rate ≤ 0.5%`,
`confidence ≥ 80` and two maintainer approvals — and it is the same ladder that
calls STABLE "safe for blocking actions in enterprise deployments" while
EXPERIMENTAL is "safe for evaluation and non-blocking alerting". So `terminate`
requires both a clean sweep of this corpus **and** the maturity the standard
reserves for production blocking.

That also removes a standing contradiction: a `maturity: test` rule lives in the
lane named _alert_, and a rule in the alert lane executing `kill_agent` is the
defect in §1 written into the rule file.

### 5a. What the policy actually cost, applied to the whole fleet

Measurement: 776 live rules against 5,352 benign samples (`clean = 598 ·
dirty = 178` — an independent re-run reproducing the 2026-08-06 figures exactly).
Applying the policy:

|                        |               |
| ---------------------- | ------------- |
| rules that overreached | **59** of 776 |
| ceiling = `observe`    | 25            |
| ceiling = `degrade`    | 32            |
| ceiling = `interrupt`  | 2             |

Actions removed, by name:

| action               | removed from |
| -------------------- | ------------ |
| `quarantine_session` | 34 rules     |
| `block_tool`         | 18           |
| `kill_agent`         | 12           |
| `block_output`       | 4            |
| `reduce_permissions` | 3            |
| `block_input`        | 2            |
| `reset_context`      | 1            |

The single largest group — 20 of the 34 `quarantine_session` removals — are
rules with a **clean sweep** that are `maturity: test`. They lose the terminate
tier on the maturity condition alone, not on any observed false positive. That is
the strictest edge of this policy and it is stated here rather than buried: those
rules earn the tier back by being promoted to `stable` through the existing
ladder, which is exactly what the ladder is for.

Recall impact is **zero by construction**, and it is checked rather than
asserted: the gate only accepts a measurement whose `detection_fingerprint`
matches the rule on disk, so a green gate over all 776 rules is itself proof that
no `detection` block changed. The diff confirms it independently — every changed
line is inside `response:`.

## 6. The unmeasured cell

`data/benign-fp-measurement.json` is the evidence. A rule is UNMEASURED when:

- it is absent from that file, **or**
- the harness reported conditions it could not exercise
  (`partial_measurement`) **and the run found zero false positives**, **or**
- its `detection_fingerprint` no longer matches the rule on disk.

All three cap the rule at `observe`.

The qualifier on the second is deliberate. A partial run that found **nothing**
proves nothing — the harness said out loud that it never exercised some of the
rule's conditions, so its silence is an unasked question. A partial run that
found **hits** is real evidence: the hits happened, and completing the
measurement can only push the rate up. So a partial run with hits is graded on
the rate it observed, reported as a lower bound, and can never reach `terminate`
(which requires a complete clean sweep). `ATR-2026-00012` is the worked case: its
`tool_name` condition is unmeasurable, and it still false-positived on 1,672 of
5,352 samples. Discarding that as "incomplete" would have been the polite reading
and the wrong one.

The third is the "green CI expires" rule made mechanical. A false-positive count
is a measurement **of a detection**, not of a rule id: edit the conditions and
the number on file describes a rule that no longer exists. The fingerprint covers
`detection`, `tags.scan_target` (it selects the skill compound gate) and
`agent_source.type`, with keys sorted so that YAML tidying — which changes
nothing the engine sees — does not void a measurement.

This is the same principle PR #433 applied to `wild_fp_rate`: 230 rules carried
`wild_fp_rate: 0` produced by a `?? 0` that wrote "not on the list" as "measured
clean", and one of them (`ATR-2026-00061`) was firing on 52.58% of the benign
corpus while claiming zero. Defaulting an unreadable measurement to "fine" is the
failure mode; the default here is refusal.

## 7. Honesty caveats — FP that may be measurement artefacts

These are stated separately **on purpose**. The policy must rest on real false
positives, and folding an artefact into the argument for "it does not deserve
`kill_agent`" would corrupt both.

1. **The two FPs traced to a specific character turned out to be genuine, not
   corpus contamination.** A prior note held that the residual false positives on
   these rules were security-education documents quoting attack strings verbatim
   — _caught right, corpus mislabelled_. That is a real category and it does
   exist in the corpus, but it is not what the sampled `terminate`-tier rules are
   firing on. Traced with the engine's own `matchedConditions` /
   `matchedPatterns`:

   - `ATR-2026-00062` on `data/skill-benchmark/benign/ninja-legit/ninja-020-computer-use.md`,
     condition 0, on the raw shape. The matched text is `no-sandbox`, from the
     line `google-chrome --no-sandbox &    # Chrome (recommended)`. That is the
     standard headless-Chrome flag in a legitimate computer-use skill. A rule
     carrying `kill_agent` terminates the agent for launching a browser.
   - `ATR-2026-00066` on `data/skill-benchmark/benign/real-anthropics--accessibility-review.md`,
     matching `../../` inside the markdown link `[CONNECTORS.md](../../CONNECTORS.md)`.
     A relative link is not path traversal.

   So the policy here rests on real false positives. The contamination caveat
   still applies to _other_ rules and other bands, and re-measuring against a
   corpus with pentest / security-education samples split out is the right way
   for a rule to earn its tier back — but it is not an excuse available to these.

2. **The JSON-envelope shape.** `src/hook-handler.ts` sets
   `tool_args = JSON.stringify(toolInput)`, so a newline in the payload is the
   two characters `\` `n`. Patterns written against raw text behave differently
   there. Some counted FPs are an artefact of that encoding — and the reverse
   trap is documented: "add a backslash to the character class" is not the fix
   (it took `ATR-2026-01610` from 1,160 to 260 and opened a hole a single double
   quote walks through).
3. **The skill path is unmeasured for most of the fleet.** 645 of 776 gated rules
   (102 of them in the enforce lane)
   cannot produce a match through `engine.scanSkill()` for any input:
   `scan_target: mcp` makes the skill compound gate demand ≥2 matched conditions
   while `evaluateArrayConditions` breaks on the first match under
   `condition: any`, so `matchedConditions` never exceeds 1. Their `0 FP` is
   `0 FP on the evaluate() shapes`, silent on the skill path. This policy does
   **not** gate on it, and that is a deliberate scope decision, not an oversight:
   every rule currently at `terminate` is in that set, so gating on it would zero
   the tier out on a defect that belongs to the engine, not to the rules. It is
   its own line of work.

## 8. Tooling

```bash
# produce the evidence (slow — full benign corpus × every live rule)
npx tsx scripts/gate-promotion-fp.ts --ids <live-ids.txt> --filter-mode \
    --emit-dirty /tmp/dirty.txt \
    --emit-measurement data/benign-fp-measurement.json

# check the fleet against the policy
npx tsx scripts/gate-action-eligibility.ts        # exit 1 on any overreach
npx tsx scripts/gate-action-eligibility.ts --json

# apply the downgrades
npx tsx scripts/downgrade-unearned-actions.ts            # dry run
npx tsx scripts/downgrade-unearned-actions.ts --apply
```

The ratchet is `tests/action-eligibility.test.ts` → `repository conformance`.
It reads every rule on disk and the committed measurement, and fails naming any
rule that overreaches. Adding `kill_agent` to an unmeasured rule turns it red.

`live-ids.txt` is every rule the engine can load and fire: all of `rules/**/*.yaml`
minus `status: draft` / `status: deprecated` / `maturity: deprecated`.

## 9. What is still open

- `auto_response_threshold` is dead metadata (§1). Either wire it or remove it;
  today it reads like a safety control and is not one.
- `StdioAdapter.flushResponses()` has no caller (§1a). Every block / quarantine /
  kill the guard "executes" is written into a buffer nobody drains. Either wire
  the buffer into the hook response or delete the methods' pretence — a security
  control that silently does nothing is the worst of the three states.
- ~~`atr guard` defaults to `lane: 'hunt'` (§1a), so `atr init` installs a hook in
  which every experimental rule fires.~~ **Partly addressed (Unreleased).** The
  default is still `hunt`, but it is now a choice an operator can change:
  `--lane` on `atr guard` / `atr scan`, `ATR_LANE` in the environment of those
  commands, `lane` on the GitHub Action, `lane` in `ATREngineConfig` when
  embedding. More importantly the hook that `atr init` installs no longer
  blocks at all by default — see the next item — so "every experimental rule
  fires" now means "every experimental rule is reported".
- ~~`SPEC.md` §5.5 ... Passing an `ActionExecutor` is arguably that directive~~
  **Addressed (Unreleased).** Passing an executor is no longer treated as the
  directive. `ActionExecutor` refuses to dispatch any action above the `observe`
  tier unless `blocking` is set (explicit config only; `atr guard` maps
  `--blocking` / `ATR_BLOCKING` onto it), and the hook emits no
  `permissionDecision` in that state. The directive is now a named, documented
  switch instead of an interpretation.
- ~~The hook answers `permissionDecision: "allow"` when no rule matches.~~
  **Addressed (Unreleased).** It no longer answers at all in that case. `allow`
  is affirmative approval in the Claude Code contract, so "no rule matched" was
  being reported to the host as "ATR approves this" — measured on the 451
  attacks in `data/pint-benchmark/pint-corpus.json` under `--blocking --lane
  enforce`, where only `maturity: stable` rules may fire: 451 of 451 came back
  `allow`, including an `~/.ssh/id_rsa` exfiltration to a remote host. ATR now
  emits a decision only to restrain (`deny` / `ask`); an `allow` verdict omits
  the whole `hookSpecificOutput` envelope and the host keeps its own prompt.
- The verdict path (`severity` + `confidence` → `permissionDecision`) has no
  precision input at all. That is a second, larger line: it _would_ change what
  the engine blocks, so it needs its own recall analysis and is out of scope here.
