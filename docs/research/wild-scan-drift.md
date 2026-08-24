# Rule drift against the wild scan

Has the ATR rule corpus drifted away from what actually happens in the wild?

The only wild hit evidence this repository owns is
`data/full-scan-v2-2026-04-14.json`: 101,280 items scanned across five
registries on 2026-04-13, 1,434 flagged, 1,507 rule matches, engine v2.0.0 with
113 rules. It preserved paths and rule ids. It did not preserve content, so it
cannot be re-run. This document measures the drift that can be measured, states
plainly which questions the artifact cannot answer, and names what would have to
be collected to answer them.

Two commits anchor everything below:

| | commit | rules |
| --- | --- | ---: |
| engine at scan time | `c6c514f491b8e8ddc4a9cda60ffe5bc25ec42a8f` (2026-04-14 07:22 +0800) | 113 |
| engine today | `738b2b5a8b9561af94192ca57b253ec498ecbf88` (`origin/main`) | 784 |

**Every number in this document is labelled with the event shape it was measured
under.** The same corpus scored through a different shape produces different
numbers by factors, not percentages. `engine.scanSkill()` — the shape the wild
scan used — skips source-type filtering and applies a compound gate;
`evaluate({type:'tool_call'})` and `evaluate({type:'tool_response'})` are the two
shapes `atr guard` actually emits; `evaluate({type:'llm_input'})` is a shape no
hook produces. An unlabelled recall or precision figure over this corpus is not
a measurement.

---

## 1. Do the 113 rules still exist?

All 113 survive. None was deleted, none was deprecated, and the four that were
`status: draft` at scan time are still `draft`.

| transition | rules |
| --- | ---: |
| present in `origin/main` today | 113 / 113 |
| deleted | 0 |
| now `deprecated` | 0 |
| `draft` then, `draft` now | 4 |
| `draft` -> `experimental` | 17 |
| `experimental` -> `experimental` | 85 |
| `stable` -> `stable` | 7 |

Maturity moved much more than status did:

| maturity transition | rules |
| --- | ---: |
| `experimental` -> `test` | 87 |
| `test` -> `test` | 17 |
| `stable` -> `test` (demoted) | 6 |
| `stable` -> `stable` | 1 |
| `test` -> `stable` (promoted) | 1 |
| `experimental` -> `experimental` | 1 |

The six demotions are `ATR-2026-00001`, `00002`, `00003`, `00010`, `00020`,
`00021`. None of them ever fired in the wild scan, so the demotions cost no wild
coverage. The single promotion is `ATR-2026-00080` (Encoding-Based Prompt
Injection Evasion), which also never fired in the wild scan.

No rule changed `severity`, `agent_source.type`, or its `condition` combinator.

### 1.1 Narrowing

Comparing the two trees condition by condition (hash of each condition's regex
literal, not `grep`):

| | rules |
| --- | ---: |
| condition set byte-identical to 2026-04 | 67 |
| condition set changed | 46 |
| changed rules that **lost** at least one original condition | 46 |
| changed rules that only **added** conditions | 0 |

Every edit in five months was a tightening. Nothing was widened. The six
wild-firing rules among those 46 were all narrowed against a specific
false-positive shape:

- `ATR-2026-00121` — reverse-shell branch `nc -[elp]` now requires an `-e`-style
  exec flag; the password-protected-archive branch now requires an archive
  extension within 80 characters.
- `ATR-2026-00120` — the HTML-comment branch became non-greedy with `-->`
  guards, and the bare keywords gained `\b` plus hyphen lookarounds.
- `ATR-2026-00135` — added a vendor allowlist (`google.com`, `openai.com`,
  `anthropic.com`, `microsoft.com`, `azure.com`, `aws.amazon.com`,
  `cloudflare.com`, `stripe.com`, ...) and dropped the verb `test`.
- `ATR-2026-00149` — `dig`/`nslookup` must now start a command and be followed
  by something domain-shaped; base64-in-comment now excludes URLs and image
  markdown.
- `ATR-2026-00162` — the exfiltration branch now requires a specific pipe target
  rather than any `|`.
- `ATR-2026-00163` — "run in the background" alone is no longer enough; a
  concealment clause must follow within 40 characters.

### 1.2 Which rules were narrowed past their own evidence

Since the flagged content is gone, the closest available proxy is each rule's
own true-positive vectors **as they stood at the scan commit**, replayed through
today's engine. If a rule can no longer fire on the attack strings it shipped
with in April, it has been narrowed past its own documented evidence.

Measured by `scripts/research/wild-scan-drift-measure.ts` (M2), 148 historical
true-positive payloads belonging to the 24 wild-firing rules:

| shape | historical TPs still firing |
| --- | --- |
| `scanSkill()` — the shape the wild scan used | **69 / 148** |
| `evaluate({type:'tool_call'})` | 84 / 148 |
| `evaluate({type:'tool_response'})` | 125 / 148 |
| `evaluate({type:'llm_input'})` | 46 / 148 |

Under the shape that produced the wild evidence, less than half of that evidence
still reproduces. Almost none of that loss is regex narrowing. It is
reachability, and section 3 takes it apart.

Genuine narrowing accounts for two rules only: `ATR-2026-00163` lost one of
four historical vectors, and `ATR-2026-00140` lost two of five. Both rules pass
all of their *current* vectors, so the loss is a deliberate replacement of old
test cases, not a regression.

---

## 2. What actually fires in the wild

`rule_hits` is the only table in this repository that says which rules matched
real published content rather than authored test material. 24 of the 113 rules
fired; the other 89 never matched anything in 101,280 items.

| rule | wild hits | what it catches | status / maturity now | severity | scan_target | agent_source | corpus visibility | historical TPs still firing (skill / tool_call / tool_response) |
| --- | ---: | --- | --- | --- | --- | --- | --- | --- |
| `ATR-2026-00121` | 686 | Malicious Code in Skill Package | experimental / test | critical | skill | mcp_exchange | thin | 7 / 7 / 7 of 7 |
| `ATR-2026-00150` | 113 | Credential Data Leaked in Tool Response | experimental / test | critical | mcp | mcp_exchange | thin | 0 / 5 / 5 of 5 |
| `ATR-2026-00097` | 101 | CJK Prompt Injection | experimental / test | critical | mcp | llm_io | **blind** | 0 / 0 / 31 of 31 |
| `ATR-2026-00163` | 99 | Hidden Override Instructions in Skill Content | experimental / test | high | skill | mcp_exchange | measured | 3 / 3 / 3 of 4 |
| `ATR-2026-00120` | 89 | SKILL.md Prompt Injection | experimental / test | critical | skill | mcp_exchange | thin | 5 / 5 / 5 of 5 |
| `ATR-2026-00149` | 79 | Skill Data Exfiltration via Compound Patterns | experimental / test | critical | skill | mcp_exchange | thin | 9 / 9 / 9 of 9 |
| `ATR-2026-00052` | 69 | Cascading Failure Detection in Agent Pipelines | experimental / test | high | mcp | llm_io | measured | 0 / 0 / 10 of 10 |
| `ATR-2026-00162` | 64 | Credential Access with Exfiltration in Skill Instructions | experimental / test | critical | skill | mcp_exchange | measured | 3 / 3 / 3 of 3 |
| `ATR-2026-00119` | 59 | Social Engineering Attack via Agent Output | experimental / test | high | mcp | tool_call | measured | 0 / 5 / 0 of 5 |
| `ATR-2026-00135` | 57 | Data Exfiltration URL in Skill Instructions | experimental / test | critical | skill | mcp_exchange | measured | 6 / 6 / 6 of 6 |
| `ATR-2026-00122` | 27 | Weaponized Skill — Agent as Attack Tool | experimental / test | high | skill | mcp_exchange | thin | 5 / 5 / 5 of 5 |
| `ATR-2026-00126` | 12 | Skill Rug Pull Setup Pattern | experimental / test | high | skill | mcp_exchange | measured | 5 / 5 / 5 of 5 |
| `ATR-2026-00128` | 10 | Hidden Payload in HTML Comment | experimental / test | critical | skill | mcp_exchange | measured | 5 / 5 / 5 of 5 |
| `ATR-2026-00105` | 10 | Silent Action Concealment in Tool Descriptions | experimental / test | high | mcp | tool_call | measured | 0 / 0 / 0 of 5 |
| `ATR-2026-00041` | 8 | Agent Scope Creep Detection | experimental / test | medium | mcp | llm_io | measured | 0 / 0 / 5 of 5 |

The remaining nine, each with fewer than five hits: `00164` (4), `00129` (4),
`00127` (4), `00134` (3), `00136` (3), `00108` (3), `00141` (1), `00151` (1),
`00140` (1).

Three properties of this table matter more than any individual row.

**All 24 are `maturity: test`. None is in the enforce lane.** The enforce lane
admits `maturity: stable` only. There are 106 such rules on `origin/main` and
**zero of them have ever matched anything in the wild scan**. Restricted to the
SKILL.md path, the enforce lane is four rules — `ATR-2026-00440`, `00432`,
`00433`, `00436` — all four CVE-specific RCE rules, and all four marked `blind`
by `data/corpus-visibility-baseline.json`, meaning the benign corpus contains no
sample that could have produced a false positive for them. The auto-block lane
is built entirely out of rules with no wild evidence for or against.

**One wild-firing rule is `blind`.** `ATR-2026-00097` (CJK Prompt Injection)
matched 101 real published items and sits in the visibility baseline as `blind`:
the 5,352-sample benign corpus cannot produce a single candidate for it. Its
zero false positives carry zero information, while the real world handed it 101
hits nobody has adjudicated. Six more wild-firers are `thin` — including
`ATR-2026-00121`, the rule responsible for 686 of the 1,507 matches. The most
load-bearing detection in the corpus is measured against a benign corpus that
barely contains its shapes.

**`wild_fp_rate` is absent, not zero, on 14 of the 24.** `00150`, `00097`,
`00163`, `00052`, `00162`, `00119`, `00105`, `00041`, `00164`, `00127`, `00136`,
`00108`, `00141`, `00140` carry no `wild_fp_rate` field at all. That is the honest state —
absent is better than a fabricated `0` — but it means the highest-hit rules in
the corpus have no wild false-positive measurement of any kind.

---

## 3. The reachability finding

This is the largest drift, and it is not in the regexes.

### 3.1 Ten wild-firing rules can no longer fire on the shape that found them

`engine.scanSkill()` applies a compound gate: a rule whose `tags.scan_target` is
neither `skill` nor `both` must match at least two *conditions*. For a rule with
`condition: any` the engine short-circuits after the first match, so
`matchedConditions` is capped at 1 and the requirement can never be met. 780 of
784 rules declare `condition: any`. The effective policy of the SKILL.md path is
therefore "only `scan_target: skill|both` rules run" — which the engine's own
source comments state and pin with a test.

Ten of the 24 wild-firing rules now carry `tags.scan_target: mcp`. Nine of them
are `condition: any` and are consequently unreachable on the SKILL.md path; the
tenth, `ATR-2026-00140`, is one of the four `condition: all` rules in the corpus
and still fires. The M2 replay agrees with that structural prediction exactly:
all nine score 0 under `scanSkill()`. Six of the nine score non-zero under
`tool_response`; the three that do not (`00119`, `00105`, `00108`) are the
separate reachability defects in §3.2 and §3.3.

Those ten rules carry **368 of the 1,507 wild matches (24.4%)**. A quarter of the
only wild evidence ATR has was produced by rules that today cannot fire on the
kind of artifact that produced it.

Skill-active coverage did grow, just not where the evidence is:

| | 2026-04 (113 rules) | today (784 rules) |
| --- | ---: | ---: |
| rules with `scan_target: skill\|both`, status live | 91 | 129 |
| of which are from the original 113 | — | 20 |

The corpus grew 6.9x. The SKILL.md-reachable subset grew 1.4x, and only 20 of
the original 113 remain inside it.

(The scan artifact's own header claims `skill_active: 66`. That number cannot be
re-derived from the rule metadata at that commit under any filter combination
tried — `scan_target skill|both` gives 108 raw, 91 after the status filter.
Treat the header field as unsourced.)

### 3.2 `ATR-2026-00105` keys on a field no runtime event carries

`ATR-2026-00105` matched 10 wild items. Its condition reads the field
`tool_description`. `atr guard` builds every event in
`src/hook-handler.ts:hookInputToEvent()` with exactly four fields: `tool_name`,
`tool_args`, `content`, and — on PostToolUse only — `tool_response`. There is no
`tool_description`. The rule scores 0 under all four shapes in M2. It is not
broken; it is asking a question the runtime never provides an answer to.

`ATR-2026-00108` (multi-agent consensus Sybil, 3 wild hits) has the same
disease from the other direction: `agent_source.type: multi_agent_comm` is only
admitted by an event of type `multi_agent_message`, which `atr guard` never
emits. `ATR-2026-00134` (3 wild hits) declares `agent_source.type:
skill_lifecycle`, which maps to no event source type at all — it fires only in
skill scans (5/5 under `scanSkill()`, 0/5 under both runtime shapes).

### 3.3 The guard mistypes PreToolUse events under the spelling the host sends

`hookEventOf()` correctly reads `hook_event_name` — the field Claude Code
actually sends — for dispatch. `hookInputToEvent()`, which decides the *event
type*, still reads `input.hook`:

```
const isPreTool = input.hook === 'PreToolUse';
const type = isPreTool ? 'tool_call' : 'tool_response';
```

With a real Claude Code payload `input.hook` is `undefined`, so a PreToolUse
event is built as `tool_response`. Source `tool_response` maps to
`mcp_exchange`, which admits `mcp_exchange` and `llm_io` rules and excludes
`tool_call` rules entirely.

Reproduced against `origin/main` (784 rules loaded; the payload is
`ATR-2026-00119`'s own current true positive):

```
direct evaluate tool_call                          -> ATR-2026-00119
direct evaluate tool_response                      -> none
handlePreToolUse({hook: 'PreToolUse', ...})        -> ask   :: Social Engineering Attack via Agent Output
handlePreToolUse({hook_event_name: 'PreToolUse'})  -> allow :: No rules matched.
```

Every fixture in the repository uses ATR's own `hook` spelling, so the whole
suite exercises the branch the host never sends — the same failure mode
`tests/hook-event-field.test.ts` was written to close for dispatch, still open
one call deeper for event typing.

Consequence, counted against `origin/main`: of 777 live rules (excluding `draft`
and `deprecated`), 81 declare an `agent_source.type` that a `tool_response`-typed
event does not admit — 63 `tool_call`, 6 `multi_agent_comm`, 5 `agent_trace`,
3 `skill_lifecycle`, 2 `memory_access`, 2 `context_window`. Among the wild-firing
rules that is `ATR-2026-00119` (59 hits), `00105` (10), `00108` (3) and `00134`
(3): **75 of 1,507 wild matches sit on rules the deployed guard cannot reach.**

This finding is reported, not fixed — this branch is documentation only.

---

## 4. How many of the 1,434 are real?

### 4.1 What the artifact itself supports

| | count | share of 1,434 |
| --- | ---: | ---: |
| flagged files | 1,434 | 100% |
| joinable to `data/public-blacklist.json` | 1,063 | 74.1% |
| `confirmed_malware: true` in that file | 552 | 38.5% |
| published by the three named threat actors | 552 | 38.5% |

The confirmed set and the threat-actor set are the same 552 entries. The
adjudication was "this account is a known malware campaign", applied
account-wide — it is publisher attribution, not per-file analysis. Concentration
is extreme: 616 distinct OpenClaw publishers appear among the flagged files, and
two of them (`hightower6eu` 354, `sakaen736jih` 198) account for 38.5% of
everything.

The task brief cites a contemporaneous precision summary of 0.577. That figure
does not appear anywhere in `data/`, `docs/`, or any markdown file in this
repository, and I could not reconstruct it from the artifacts. It should not be
cited until its derivation is found. The number that *is* derivable is
552 / 1,434 = 38.5% confirmed, which is a floor, not a precision.

Per the standing freeze on wild-scan figures, only `101,280 scanned /
1,434 flagged / engine v2.0.0` are citable externally from this artifact.

### 4.2 A 30-file read of paths and matches

Deterministic sample: `flagged_files` sorted by `(source, file)`, indices
`i * 47` for `i = 0..29`.

| verdict | n | basis |
| --- | ---: | --- |
| almost certainly true positive | 12 | 11 under `hightower6eu` / `sakaen736jih` (`00121`), plus `zaycv/youtubewatcher` — `zaycv` is the named campaign account in `00121`'s own description |
| likely true positive, unverified | 4 | blacklisted, `00121`, unknown publisher: `cohnen/pixcli-skill`, `iterdimensionaltv1/moltuniversity`, `seedamir/amir`, `xiazai77/product-demo-video` |
| correct detection, not malware (dual-use) | 1 | `nsahal/nmap-recon` via `00122` Weaponized Skill — it is an offensive tool on purpose |
| likely false positive | 13 | see below |

The 13 likely false positives cluster into three recognisable shapes:

- **Topic, not payload.** `hichana/resolved-sh` and
  `vahagn-madatyan/incident-response-lifecycle` both hit `00052` "Cascading
  Failure Detection". They are documents *about* incident response. The rule
  matched the vocabulary of the threat rather than the threat.
- **Security tooling flagged by its own examples.** `dgriffin831/input-guard`
  hit `00120` "SKILL.md Prompt Injection" — a prompt-guard skill necessarily
  contains injection strings.
- **Legitimate credential handling.** `bobthemom987/kalshi-trader`,
  `rk905/geeksdobyte-slack-botskill` (`00150`),
  `mohit21gojz/unipile-linkedin-sdk`, `sweesama/mzu-news-briefing` (`00162`),
  `alexhegit/rocm-vllm-deployment`, `lava-chen/bili-summary` (`00135`) — SDK and
  deployment docs that mention an API key and a URL.
- **Persuasive prose read as social engineering.**
  `flynndavid/coi-insurance-compliance-tracker` and
  `jpengcheng523-netizen/jpeng-workspace-health-monitor` hit `00119` "Social
  Engineering Attack via Agent Output"; `lucasgeeksinthewood/buy-amazon` hit
  `00041` "Agent Scope Creep" for doing what a shopping skill does.
- Plus `doubao-video-analyzer` hit by `00097` CJK Prompt Injection, a
  Chinese-language skill matched by a rule keyed on Chinese instruction phrasing.

12/30 = 40% confident true positives, which agrees closely with the structural
38.5% confirmed rate. That agreement is the useful result: the flagged set is
roughly 40% real, and the rest is dominated by dual-use security content and
credential-adjacent documentation.

### 4.3 One registry can actually be re-scanned

All 52 Skills.sh files in the flagged set still exist under
`data/skills-sh/skills/`. That snapshot was collected 2026-06-29, eleven weeks
after the scan, so skill identity is certain and byte-identity is not — but this
is the only true re-scan available anywhere in the repository.

Re-scanned through `scanSkill()` on `origin/main` (M5):

| | count |
| --- | ---: |
| re-scanned | 52 / 52 |
| **now clean — would not be flagged today** | **26** |
| still flagged | 26 |
| still flagged by the *same* rule as 2026-04 | 26 |
| additionally picked up a *new* rule added since 2026-04 | 7 |

Half the April flags in this registry have been repaired away, and the repairs
landed exactly where they should have. The 26 that went clean include
`anthropics/skill-creator`, `bitwarden/detecting-secrets`, `vercel/env-vars`,
`vercel-labs/github`, `useai-pro/credential-scanner`, `useai-pro/setup-auditor`,
and eight incident-response / observability / TDD documents that `00052` used to
match. Flagging first-party Anthropic, GitHub, Bitwarden and Vercel skills was
the single most embarrassing property of the April output, and it is gone.

What remains is not malware. 21 of the 26 still-flagged files are `sickn33/*`
offensive-security skills, 14 of them matched by `00122` "Weaponized Skill"
(`metasploit-framework`, `sqlmap-database-pentesting`, `ssh-penetration-testing`,
`linux-privilege-escalation`, ...). Two more are `useai-pro/prompt-guard` and
`useai-pro/skill-auditor` — security tooling matched by its own examples. On this registry slice the corpus's true-malware
yield is approximately zero, and the residual flags are a policy question
(is a deliberately offensive skill a finding?) rather than a detection question.

Meanwhile seven of these same files picked up *additional* hits from rules
authored after the scan — `00270` on four of them, plus `00220`, `00225`,
`00395`. The new rules are re-flagging content the old rules were repaired to
stop flagging.

### 4.4 A named contradiction

`sickn33/active-directory-attacks` appears three times in this repository:

1. flagged in the wild scan by `ATR-2026-00122`;
2. ingested into `data/benign-corpus-extended/wild-fp-confirmed.jsonl` as a
   human-adjudicated **confirmed false positive**, where it is part of the 5,352
   benign samples the promotion gate scores against;
3. still matched by `ATR-2026-00122` today, in both copies, verified directly.

Across that whole 68-sample adjudicated-false-positive corpus, **40 of 68 are
still flagged** under `scanSkill()` on `origin/main`, and 18 of them by one of
the original 24 wild-firing rules. `ATR-2026-00123` alone accounts for 12.
Because `scripts/gate-promotion-fp.ts` scores through `scanSkill()`, these are
already counted as false positives by the gate — this is not a hidden blind
spot. The finding is narrower and worse: rules stay in the corpus at
`maturity: test` while firing on samples the project has already ruled benign,
and the promotion gate's job is only to stop them reaching `stable`, not to
force a repair.

---

## 5. Can the 1,434 files' content be recovered?

Assessed, not attempted. No content was fetched.

**The paths are addresses, not opaque ids.** OpenClaw entries are
`<publisher>/<skill>/SKILL.md` (1,298 of 1,376 have exactly that shape) and
`data/public-blacklist.json` records a canonical URL of the form
`https://openclaw.com/skills/<publisher>/<slug>` for 1,063 of the 1,434.

**Verification is already solved, which is the hard half.**
`data/openclaw-scan/openclaw-scan-report.json` (a separate 2026-04-05 scan of
the `openclaw/skills` monorepo, 50,284 files) stores a SHA-256 `content_hash`
and `file_size` for every file it saw. **1,304 of the 1,376 OpenClaw flagged
paths appear in that record.** Any recovered file can therefore be proven
byte-identical to its April state, or proven changed. A recovery effort would
not have to trust the source.

| route | coverage | assessment |
| --- | ---: | --- |
| `openclaw/skills` monorepo history at an April commit | up to 1,304 hash-verifiable | best route if history was retained; malicious skills are exactly the ones most likely to have been force-removed rather than reverted |
| per-skill pages via the recorded canonical URLs | 1,063 addressable | four months stale; the 552 confirmed-malware skills are the least likely to still be served, and those are the valuable ones |
| local Skills.sh snapshot | 52 / 52 | **already recovered** — used in §4.3 |
| local ClawHub registry (`data/clawhub-scan/clawhub-registry.json`, 36,394 skills) | 3 flagged | different ecosystem, negligible overlap, and it carries summaries not file bodies |
| Hermes (2), MCP Registry (1) | 3 | not worth a pipeline |

**Assessment.** Worth doing, with clear eyes about the yield. The realistic
prize is not 1,434 files; it is the fraction of the 552 confirmed-malicious ones
that survived takedown, and every one of those is a genuine attack sample with a
hash that proves what it was. The correct order is: (1) check whether
`openclaw/skills` retains April history at all — one operation, and it decides
whether the rest is worth planning; (2) if yes, extract at the April commit and
verify against the 1,304 stored hashes; (3) treat anything that fails hash
comparison as a different artifact, not as evidence. The 882 non-confirmed
flagged files are the *second* prize and arguably the more useful one — they are
the material needed to settle whether the 40% true-positive estimate in §4.2 is
right, and they are also the benign-side samples that would move
`ATR-2026-00121` off `thin` and `ATR-2026-00097` off `blind`.

Any fetch is an outbound action and is out of scope for this branch.

---

## 6. Verdict

The rule corpus has not drifted away from real-world attacks. It has drifted
away from the *evidence* of them.

- No wild-firing rule was deleted or deprecated. Detection content is intact.
- Every condition edit in five months tightened; nothing widened. The repairs
  were correct and targeted, and half the April flags in the one re-scannable
  registry are gone as a direct result.
- But the wild evidence is quarantined. All 24 wild-firing rules are
  `maturity: test`. The enforce lane is 106 `stable` rules with zero wild hits
  between them, and on the SKILL.md path it is four `blind` CVE rules.
- And the wild evidence is partly unreachable. Ten wild-firing rules carrying
  368 of 1,507 matches can no longer fire on the shape that produced them; four
  more, carrying 75 matches, cannot be reached by the deployed guard at all —
  one of them because `hookInputToEvent()` reads the wrong spelling of the hook
  event name.

Three things would close the gap, in this order:

1. **Fix `hookInputToEvent()` to read `hook_event_name`.** It is one line, and
   until it lands, 81 live rules — including a 59-hit wild-firing rule — are
   dead weight in every deployment.
2. **Decide what `scan_target: mcp` means for a rule with wild skill hits.**
   Either the ten rules in §3.1 should be `both`, or the wild hits they produced
   should be retired as evidence. Holding both positions at once is what
   produces a 69/148 replay score that looks like a regression and is not.
3. **Recover content for the confirmed-malicious subset.** Every quality
   question in this document — is `ATR-2026-00121`'s `thin` visibility real, is
   `ATR-2026-00097` blind or just unmeasured, is the flagged set 38.5% or 40% or
   60% true — is blocked on the same missing input, and there is a stored hash
   for 1,304 of those files waiting to verify it.

---

## Reproduce

```
git checkout docs/wild-scan-drift
npx tsx scripts/research/wild-scan-drift-measure.ts
```

Exits 0 after printing four control assertions (rule count loaded vs. rule files
on disk; a named rule firing on its own canonical wild payload; the same rule
staying silent on its own documented true negative; source-type filtering and
the skill compound gate each demonstrably dropping a named rule). It exits 2 and
prints no measurements if any assertion fails. Results are written to
`docs/research/wild-scan-drift-measurements.json`. Runtime is a few minutes; the
M3 pass over the 68-sample corpus dominates it.

Sources: `data/full-scan-v2-2026-04-14.json`, `data/public-blacklist.json`,
`data/openclaw-scan/openclaw-scan-report.json` (local, gitignored),
`data/corpus-visibility-baseline.json`,
`data/benign-corpus-extended/wild-fp-confirmed.jsonl`, `data/skills-sh/skills/`,
`data/skill-benchmark/malicious/`, and the rule trees at
`c6c514f491b8e8ddc4a9cda60ffe5bc25ec42a8f` and `origin/main`.
