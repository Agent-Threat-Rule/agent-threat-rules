# Enforcement Model

> ATR separates **detection** from **enforcement**. Detection always runs and is
> always reported. Enforcement — refusing an operation, altering session state,
> or killing a session — is an operator decision that ATR does not make on the
> operator's behalf. This document states what the reference engine does by
> default, which switches change that, which decision channel each consumer
> reads, and how an existing deployment migrates.

All corpus figures below were counted directly off `rules/**/*.yaml` at the
commit this document was written against; the method is in [§8](#8-how-the-numbers-here-were-counted).

## 1. What ATR does by default

With no configuration beyond a rules directory, the reference engine:

- **loads every non-retired rule** (the `hunt` lane — see [§2](#2-the-two-operator-switches));
- **emits Match output** for everything that fires, per [SPEC §7](../SPEC.md);
- **runs OBSERVE-tier response actions** — `alert`, `snapshot`, `shadow`,
  `escalate` — which record and notify but change nothing about the agent's
  execution;
- **expresses no opinion on whether the operation should proceed.** On the
  Claude Code hook contract this means the payload carries ATR's findings and
  **omits `hookSpecificOutput.permissionDecision` entirely**; the
  `PostToolUse` payload omits `decision: "block"`.

And it does **not**:

- dispatch any response action above the OBSERVE tier (`block_input`,
  `block_output`, `block_tool`, `reduce_permissions`, `reset_context`,
  `quarantine_session`, `kill_agent`);
- return `deny` or `ask` to a host;
- return `allow` either — see [§4](#4-why-advisory-mode-is-not-allow).

This is the posture the rest of the project already described. It is
[SPEC.md §5.5](../SPEC.md) — "Engines MUST NOT execute response actions
automatically without an explicit configuration directive from the operator" —
implemented rather than assumed.

## 2. The two operator switches

Enforcement is governed by two independent switches. They answer different
questions and neither implies the other.

| Switch | Question it answers | Values | Default |
|---|---|---|---|
| **lane** | Which rule maturities may fire at all? | `enforce` / `alert` / `hunt` | `hunt` |
| **blocking** | May ATR act on what fired? | on / off | **off** |

### 2.1 Lane — which rules fire

The lane gate is a pure maturity filter (`laneAllows` in
`src/quality/rule-contract.ts`). A `deprecated` maturity never fires in any
lane; `status: draft` and `status: deprecated` rules are skipped before the lane
gate is consulted at all.

| Lane | Maturities that fire | Live rules that fire | of which `critical` | of which `high` |
|---|---|---:|---:|---:|
| `enforce` | `stable` | 106 | 43 | 51 |
| `alert` | `stable` + `test` | 700 | 249 | 372 |
| `hunt` (default) | all except `deprecated` | 777 | 271 | 421 |

Rules carrying `confirm: embedding` are additionally re-checked against
attack-content similarity before they may fire in `enforce` or `alert`, and are
dropped from those lanes when no embedding module is configured. Four live rules
carry that flag; one of them is `stable`. So the `confirm` gate narrows the
`enforce` lane by at most one rule today — it is a per-rule qualifier, not a
property of the lane.

### 2.2 Blocking — whether ATR may act

`blocking` is the operator directive required by SPEC §5.5. It is off until
someone turns it on. Turning it on has exactly two effects:

1. The `ActionExecutor` will dispatch response actions above the OBSERVE tier.
   With blocking off, those actions are refused before the `PlatformAdapter` is
   touched and recorded as suppressed.
2. The hook handler will emit a real permission decision, derived — verbatim,
   unchanged — from the severity + confidence matrix in `src/verdict.ts`:
   `critical` → `deny`; `high` with confidence ≥ 0.8 → `deny`, below → `ask`;
   `medium` with confidence ≥ 0.6 → `ask`; everything else → `allow`.

Detection output — which rules matched, their severity, their category — is
identical in both modes. Blocking changes what the engine *does*, never what it
*sees*.

In advisory mode the findings still reach the host, just not as a vote. The
`PreToolUse` payload carries them under non-colliding keys:

```json
{
  "hookSpecificOutput": { "hookEventName": "PreToolUse" },
  "atr_advisory": true,
  "atr_decision": "deny",
  "atr_reason": "DENY: … [critical/93% confidence] (3 rules matched)",
  "matched_rules": ["ATR-2026-00062", "ATR-2026-00040"]
}
```

`atr_decision` is what ATR *would* have answered. Log it, alert on it, measure
it — that is the intended way to evaluate whether you want to enable blocking.
It is deliberately not on the `permissionDecision` key, so no host can act on it
by accident.

The OBSERVE / enforcement split is not redefined here. It reads the blast-radius
ladder in `src/quality/action-eligibility.ts`, which is the project's single
ranking of what an action destroys:

| Tier | Actions | Dispatched with blocking off? |
|---|---|---|
| OBSERVE | `alert`, `snapshot`, `shadow`, `escalate` | Yes |
| INTERRUPT | `block_input`, `block_output`, `block_tool` | No |
| DEGRADE | `reduce_permissions`, `reset_context` | No |
| TERMINATE | `quarantine_session`, `kill_agent` | No |

### 2.3 Where the switches are set, and which wins

Both switches resolve the same way, and the order is deliberate:

```
explicit programmatic config  >  environment variable  >  built-in default
```

| Surface | Lane | Blocking |
|---|---|---|
| TypeScript API | `new ATREngine({ lane: 'enforce' })` | `new ActionExecutor({ adapter, blocking: true })`, `new HookHandler({ …, blocking: true })` |
| Environment | `ATR_LANE=enforce` | `ATR_BLOCKING=1` |
| `atr guard` | `--lane <enforce\|alert\|hunt>` | `--blocking` / `--no-blocking` |
| `atr scan` | `--lane <enforce\|alert\|hunt>` | n/a — scanning reports, it never enforces |
| GitHub Action | `lane:` input (default `hunt`) | n/a — the action reports findings only |
| MCP server | `ATR_LANE` | n/a — its tools return matches and never block |
| Built-in default | `hunt` | off |

Only the guard has a blocking switch, because it is the only surface that can
stop anything. Scanning, CI, and the MCP tools report; there is nothing for them
to opt into.

Accepted truthy values for `ATR_BLOCKING` are `1` / `true` / `yes` / `on`;
falsy are `0` / `false` / `no` / `off`. An unrecognised value for either
variable is a construction-time error rather than a silent fallback: an operator
who typed `ATR_BLOCKING=enabled` must not be left believing enforcement is on
when it is not, and a typo in `ATR_LANE` must not silently route them into a
lane they did not choose.

An explicit programmatic value always beats the environment, so a host embedding
the engine cannot have its policy overridden by a variable it did not set. On the
CLI, `--blocking` and `--no-blocking` are mutually exclusive; omitting both
leaves the decision to `ATR_BLOCKING`, and `--no-blocking` overrides it.

`atr guard` reports the resolved policy on startup, so the posture in effect is
never inferred from configuration files:

```
[atr-guard] lane=hunt blocking=off
```

## 3. Three decision channels, and who reads which

A consumer can learn "should this be stopped?" from three different places in
ATR. They are not equivalent, they do not agree, and knowing which one you are
reading is the difference between a working integration and a silent one.

| | Channel | Carries | Computed from |
|---|---|---|---|
| **A** | `hookSpecificOutput.permissionDecision` | `deny` / `ask` / `allow` with blocking on; **absent** with blocking off | The single highest-severity match: its `severity` plus a confidence derived from the rule's `tags.confidence` |
| **B** | `response.actions` → `ActionExecutor` → `PlatformAdapter` | Method calls such as `blockTool()` | The **union** of `response.actions` across *every* match |
| **C** | `match.severity` on Match output | Nothing — the consumer decides | Whatever floor the consumer picked |

**Who actually reads each one, in this repository and in the integrations it
ships:**

- **Channel A — one consumer.** `permissionDecision` appears in
  `src/hook-handler.ts`, its contract test, and the action-eligibility gate.
  No integration under `integrations/`, `python/`, `engines/`, `examples/`, or
  `conformance/` reads it. It exists to serve the Claude Code hook contract.
- **Channel B — no external consumer.** `response.actions` is read by nothing
  outside `src/`. The two adapters ATR ships (`DefaultAdapter`,
  `StdioAdapter`) do not enforce: the former is explicitly a no-op logger, and
  the latter writes blocking actions into a buffer with no reader. A downstream
  that implements `PlatformAdapter` for real, however, gets whatever this
  channel dispatches — which is precisely why the executor now gates it.
- **Channel C — everyone else.** Every shipped integration compares
  `match.severity` against a floor it chose itself: `critical` for the LangChain
  and Pydantic AI guardrails, `critical`+`high` for the Mastra processor and the
  goose plugin, `ATR_MIN_SEVERITY` defaulting to `high` for the NemoClaw and
  OpenShell adapters, an optional `min_severity` for the rampart evaluator. The
  Python engine (pyATR) has no `actions` field on its match type at all.

Two consequences an integrator should plan around:

1. **Channels A and B were computed from different data and could disagree.**
   A carries the top match only; B unions across all matches. A rule whose
   severity is too low to produce a permission decision could still contribute a
   `block_tool` to B. With blocking off both are silent, so the divergence is
   not observable; turning blocking on makes it observable again.
2. **Channel C is the real cross-implementation interface.** It is the one every
   consumer already uses, and it is carried by the rule file's `severity` field,
   not by anything the engine computes. Changing enforcement defaults in this
   engine does not change what any Channel C consumer does.

## 4. Why advisory mode is not `allow`

In the Claude Code `PreToolUse` contract, `permissionDecision: "allow"` is **not
neutral**. It is an affirmative approval that suppresses the host's own
permission prompt. An engine that answered "I have no opinion" with `allow`
would be *weakening* the host's built-in safety on every operation it did not
recognise as malicious — a security tool that, installed, makes the system
permit more than it did before.

Advisory mode therefore **omits the field** rather than setting it. The host
applies exactly the flow it would have used with no hook installed. The
detection result is still reported; it simply is not phrased as a vote on
permission.

The same reasoning applies on the `PostToolUse` path, which omits
`decision: "block"` rather than emitting a permissive counterpart.

## 5. Turning blocking on

The two switches are independent, which makes the useful configurations easy to
name:

| Goal | Lane | Blocking | What you get |
|---|---|---|---|
| Evaluate ATR against your traffic | `hunt` | off | Maximum visibility, zero enforcement. **This is the default.** |
| Feed a SIEM / analyst queue | `alert` | off | 700 rules; false positives cost analyst time, not blocked operations |
| Block, conservatively | `enforce` | **on** | 106 `stable` rules may act |
| Block on the full corpus | `hunt` | **on** | The pre-opt-in behaviour. See the warning below. |

```bash
# Conservative enforcement: only stable rules, and they may act.
ATR_LANE=enforce ATR_BLOCKING=1 npx agent-threat-rules guard
```

```ts
import { ATREngine } from 'agent-threat-rules';

const engine = new ATREngine({ rulesDir, lane: 'enforce' });
await engine.loadRules();          // required — the constructor compiles nothing
```

> **`hunt` + blocking on is not a supported production posture.** 559 of the 657
> live rules that declare an enforcement action are not `maturity: stable`, and
> 228 of the 271 live `critical` rules — every one of which produces a `deny` —
> are not `stable` either. [QUALITY-STANDARD.md](./QUALITY-STANDARD.md) restricts
> blocking to `stable` rules for a reason. If you enable blocking, pair it with
> `ATR_LANE=enforce` unless you have measured the false-positive cost on your own
> traffic.

Enabling blocking does not create a new decision matrix. It restores the
severity + confidence matrix that `src/verdict.ts` has always implemented,
verbatim. What changed is that reaching it now requires the operator to say so.

## 6. Migrating an existing deployment

### 6.1 What changes

| If you… | Before | After |
|---|---|---|
| Run `atr guard` as a Claude Code hook with no flags | Received `deny` / `ask` / `allow`; enforcement actions dispatched to your adapter | Receive findings with no permission decision; only OBSERVE actions dispatched |
| Parse the guard's stdout for `permissionDecision` | The key was always present | The key is absent unless blocking is on. Read `atr_decision` instead — it is present in both modes, and `atr_advisory: true` marks advisory output |
| Read `match.severity` and decide yourself (every shipped integration) | — | **No change.** Channel C is untouched. |
| Use `atr scan` / the GitHub Action / SARIF output | — | **No change.** Those paths report; they never enforced. |
| Implement your own `PlatformAdapter` and act on `block_tool` | Actions arrived unconditionally, including alongside a permissive verdict | Actions above OBSERVE arrive only with blocking enabled |
| Already construct `ATREngine` with an explicit `lane` | — | **No change.** Explicit config still wins over everything. |

### 6.2 Restoring the previous behaviour

One switch, at whichever layer you configure the engine:

```bash
ATR_BLOCKING=1 npx agent-threat-rules guard      # or: atr guard --blocking
```

```ts
new HookHandler({ engine, executor, blocking: true });
new ActionExecutor({ adapter, blocking: true });
```

Leave the lane alone and this reproduces the old behaviour exactly: same rules,
same matrix, same actions.

### 6.3 When you should restore it — and when you should not

**Restore it if** you had already validated ATR's block decisions against your
own traffic and accepted the false-positive rate; if you run a lane you chose
deliberately; or if you are mid-incident and want the corpus acting immediately.

**Do not simply restore it if** you inherited the old default without measuring
it. The behaviour you would be restoring is the full `hunt` corpus with
enforcement rights. The migration is a good moment to pick a lane on purpose:
`ATR_LANE=enforce ATR_BLOCKING=1` is the posture the quality standard actually
describes, and it costs recall — 106 rules fire instead of 777. Which of those
two errors you would rather make is a deployment decision, and it is now
expressible.

**A note for anyone measuring.** The `enforce` lane loads only `stable` rules,
and `stable` coverage is very uneven across categories. Counted off the corpus:

| Category | `maturity: stable` | Live |
|---|---:|---:|
| prompt-injection | 36 | 245 |
| context-exfiltration | 31 | 125 |
| tool-poisoning | 13 | 103 |
| excessive-autonomy | 10 | 35 |
| model-abuse | 7 | 41 |
| privilege-escalation | 4 | 60 |
| agent-manipulation | 3 | 108 |
| model-security | 1 | 3 |
| skill-compromise | 1 | 48 |
| data-poisoning | 0 | 9 |

An `enforce`-lane deployment therefore has near-zero skill-compromise and
data-poisoning coverage while retaining most of its prompt-injection and
exfiltration coverage. Measure the lane you intend to run; a `hunt`-lane recall
figure does not transfer to an `enforce`-lane deployment, and it does not
degrade uniformly.

## 7. Relationship to the ATR specification

**The enforcement model described here is reference-implementation behaviour,
not part of the ATR standard.** That is a deliberate boundary, and it is worth
stating why, because the three-way `allow` / `ask` / `deny` vocabulary looks
like something a standard would define.

What the standard does define:

- [SPEC §7](../SPEC.md) fixes the Match output an engine MUST emit: `rule_id`,
  `corpus_version`, `input_identifier`, `matched_at`, `severity`, `category`,
  `matched_conditions`. There is no outcome, decision, or verdict field.
- [SPEC §11–12](../SPEC.md) grade conformance on detection only. The conformance
  suite's outcome vocabulary is `match` / `no_match` / `graceful_error`.
- [SPEC §5.5](../SPEC.md) already constrains enforcement, and does so in exactly
  the direction this model implements: response actions are a recommendation
  from the rule author, and an engine MUST NOT execute them without an operator
  directive.

So `permissionDecision` is not an under-specified part of the standard. It is a
mapping from ATR Match output onto **one host's** permission contract, and it
belongs where the mapping lives.

Three reasons to keep it there:

1. **It is host-specific.** `allow` / `ask` / `deny` are Claude Code's
   `PreToolUse` vocabulary. Writing them into a vendor-neutral rule standard
   would bind every conformant engine — including SIEM exporters and CI scanners
   that have no notion of an interactive permission prompt — to a contract only
   one host implements.
2. **It is not conformance-testable in the current model.** Conformance fixtures
   assert whether a rule matched. Asserting a verdict would require the suite to
   also fix a severity → outcome mapping, which would in turn freeze policy that
   deployments legitimately differ on.
3. **Standardising it would bless the wrong thing.** Any normative
   "`critical` → deny" would grant blocking authority to all 271 live `critical`
   rules, 228 of which are not `stable` — in direct contradiction of the
   project's own quality standard.

**Recommendation:** document the enforcement model here, and add at most a
non-normative pointer from SPEC §5.5 to this file so an implementer looking at
the MUST NOT can find a worked example of satisfying it. Do not add normative
outcome language to SPEC.

**Separately worth a maintainer decision, and out of scope here:** SPEC
Appendix A's normative action vocabulary (`block_request`, `log_alert`,
`quarantine_artifact`, `require_human_review`, `redact_match`,
`rate_limit_source`, `revoke_credential`, `notify_operator`) has an **empty
intersection** with the action set this engine can dispatch (`block_input`,
`block_output`, `block_tool`, `quarantine_session`, `reset_context`, `alert`,
`shadow`, `snapshot`, `escalate`, `reduce_permissions`, `kill_agent`). Twelve
live rules declare at least one Appendix A action, and every one of those
declarations is silently discarded at dispatch time. That is a genuine
specification-versus-implementation gap; it is not this document's to close.

## 8. How the numbers here were counted

Every corpus figure above was recounted directly from the rule files, not read
from a cached snapshot:

```bash
find rules -name "*.yaml" | wc -l                                    # 784
python3 -c "import json;print(json.load(open('data/stats.json'))['rules']['total'])"   # 784
```

Disk and `data/stats.json` agree, so there is no corpus drift to disclose;
`data/stats.json` independently reports `rules.effective: 777`.

> **`stable` means two different things in this repository.** `status: stable`
> and `maturity: stable` are separate fields with separate counts — 59 and 106
> respectively at the time of writing, and `stats.json`'s `ruleCount.stable`
> tracks the *status*. Lanes read **`maturity`**. Every count in this document
> is a maturity count.

The 777 "live" figure applies the engine's own exclusions in the engine's own order:
`status` of `draft` or `deprecated` is skipped before any lane gate; a
`maturity` of `deprecated` never fires in any lane; an unrecognised `maturity`
is normalised to `experimental` (never to `stable`), per `normalizeMaturity`.

Rule counts move daily. Re-derive rather than quoting these figures onward.

## 9. What this model does not fix

Stated plainly, because each of these is real and none is addressed by making
blocking opt-in:

- **The severity + confidence matrix itself is unchanged.** With blocking on,
  `critical` still denies unconditionally — maturity is not an input. What
  changed is who has to ask for that behaviour.
- **The `confidence` the matrix reads is not the `confidence` the quality
  standard defines.** The engine derives it from the rule's three-valued
  `tags.confidence`; QUALITY-STANDARD's 0–100 score is computed from measured
  precision and wild validation and is never read by the engine. Any policy
  phrased as "block above confidence N" does not currently mean what it appears
  to mean.
- **The quality standard's consumer ladder has no `test` level.** It defines
  DRAFT, EXPERIMENTAL, STABLE, and DEPRECATED, while the schema and the lane
  gate both recognise `test` — the maturity of 206 of the 271 live `critical`
  rules, and the level that distinguishes the `alert` lane from `enforce`.
- **Channel C consumers are unaffected.** Every shipped integration picks its
  own severity floor off Match output. Nothing in this model reaches them; a
  consistent cross-implementation enforcement posture would be a standards-level
  change, not an engine-level one.
- **Advisory mode is not a claim about detection quality.** It removes an
  unmeasured blocking default. It does not make any individual rule more precise.
