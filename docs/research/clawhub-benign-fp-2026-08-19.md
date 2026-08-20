# What 36,394 published skills say about ATR's false positives

**Date:** 2026-08-19 · **Ruleset:** 784 rules at `origin/main` 738b2b5a8 · **Engine lane:** `hunt` (default)
**Corpus:** `data/clawhub-scan/clawhub-registry.json` — a full crawl of the ClawHub skill registry taken 2026-03-26.

---

## The one-paragraph version

Across 36,394 real published skills, ATR flags between 8 and 116 of them depending on
which event shape you present them through — 0.022% to 0.319%. That headline is close to
useless on its own, and this document exists mainly to say why. Three things dominate it.
**One rule accounts for a third of every flag, and it is detecting the Russian language,
not an attack** — skills with Cyrillic in their description are flagged at 94.87%, against
0.217% for everything else, a 437-fold difference in flag rate produced entirely by script.
**The shape that looks cleanest is the one that asks the fewest questions** — the skill-scan
path admits 132 of 777 live rules, so its 0.022% is a 0.022% over one sixth of the corpus.
And **the corpus is registry blurbs, not skill bodies**: median 159 characters, 42.9% cut off
mid-sentence by the registry's own truncation. A clean result here is a clean result on
marketplace listing text and nothing more.

---

## How to reproduce

```bash
npx tsx scripts/control-clawhub-fp.ts        # must print PROOF and pass before anything below counts
npx tsx scripts/build-clawhub-benign.ts      # registry -> data/measurements/clawhub-benign/corpus.jsonl
for i in $(seq 0 9); do
  npx tsx scripts/measure-clawhub-fp.ts --shard $i --of 10 --variant summary &
done; wait                                   # ~25 min wall clock on 10 cores
npx tsx scripts/report-clawhub-fp.ts --variant summary --of 10 --top 20
npx tsx scripts/clawhub-shape-admission.ts   # the denominators
npx tsx scripts/triage-clawhub-flagged.ts --variant summary --of 10 --top 30
```

`corpus.jsonl` is a 12MB re-serialisation of a file already in the repo and is therefore not
committed. `data/measurements/clawhub-benign/manifest.json` pins both SHA-256s so a later run
can prove it read the same bytes:

```
source_sha256 b1a26bb1e3b2182dedcf9fb0d7c892f9d0890db61f70aca4a3497c51a9d9e17b
corpus_sha256 fc609bc0d98b93cde5ca50383024e16435b5ec970426b4c097cf15aa162215c2
```

### The control, and why it prints before it judges

`scripts/control-clawhub-fp.ts` asserts eleven exact rule-id sets — never "the array is
non-empty", which a broken engine satisfies as easily as a working one. Its first line is a
proof of execution, because a previous sweep in this repo shipped a control that never ran:
a wrong relative path killed it before any assertion, and since it exits 1 on failure, the
harness note recorded `exit=1` as "the control bit, as expected".

```
PROOF rulesOnDisk=784 rulesLoaded=784 lane=hunt maliciousSampleBytes=11686 \
  maliciousSkillHits=[ATR-2026-00121|ATR-2026-00220] \
  injectionLlmInputHits=[ATR-2026-00001|ATR-2026-00505|ATR-2026-00509|ATR-2026-00514]
CONTROL PASSED: 784 rules, 3 shapes, 11 exact-set assertions.
```

It was tamper-tested twice. Switching the lane to `enforce` fails 6 assertions; removing the
`await engine.loadRules()` fails the same 6 — `new ATREngine()` compiles no patterns, so
without that await every measurement below would be a silent zero. The measurement script's
own flagging path was verified separately by running it over 12 known-malicious skill bodies
through the identical code path: `scanned=12 flaggedAny=11`.

---

## Denominators first: what each shape actually asks

| Shape | Built by | Rules admitted | Of 777 live |
|---|---|---|---|
| `skill-preflight` — `{type:'tool_call', scanContext:'skill'}` | `src/adapters/nemoclaw-preflight.ts` | **132** | 17.0% |
| `llm-input` — `{type:'llm_input', fields.user_input}` | `src/adapters/mastra.ts` | **392** | 50.5% |
| `tool-response` — `{type:'tool_response', fields.tool_response}` | `src/hook-handler.ts` indirect channel | **696** | 89.6% |

784 rules are on disk; 7 are `deprecated`/`draft` and never fire on any shape, leaving 777.
On the skill path the engine's compound gate rejects 645 of them outright — for a
`condition: any` rule that is not `scan_target: skill|both`, the gate demands at least two
matched conditions and `matchedConditions` short-circuits at one, so the threshold is an
unconditional reject (mechanism documented in `src/corpus-event.ts`).

**A 0% on `skill-preflight` is a statement about 132 rules.** Reporting it as "784 rules were
quiet" is the exact failure mode `gate-corpus-visibility.ts` was written to name.

---

## Results

Per sample, not per shape: a skill that trips a rule on three shapes is one flagged sample.

| Shape | Flagged | Rate | Distinct rules firing | Excluding the script bug (below) |
|---|---|---|---|---|
| `skill-preflight` | 8 | **0.022%** | 4 | 8 — 0.022% |
| `llm-input` | 79 | **0.217%** | 24 | 42 — 0.115% |
| `tool-response` | 116 | **0.319%** | 39 | 79 — 0.217% |
| any shape | 116 | 0.319% | 39 | 79 — 0.217% |

39 distinct rules of 777 fired at all. 113 of the 116 flagged samples were flagged by exactly
one rule.

### By download rank — the flag rate goes UP at the top

A false positive on a skill nobody installed costs nobody anything. Rates are therefore
reported by download rank, not pooled.

| Stratum | Samples | `skill-preflight` | `llm-input` | `tool-response` |
|---|---|---|---|---|
| top 100 | 100 | 0 — 0% | 0 — 0% | 0 — 0% |
| top 1,000 | 1,000 | 0 — 0% | 3 — 0.30% | 6 — **0.60%** |
| top 10,000 | 10,000 | 2 — 0.02% | 24 — 0.24% | 34 — 0.34% |
| all | 36,394 | 8 — 0.022% | 79 — 0.217% | 116 — 0.319% |

The top 100 are clean on every shape. But from rank 100 to rank 1,000 the flag rate is
**0.60% — nearly double the corpus-wide 0.319%.** The comfortable reading ("we only bother
the long tail") is not what the data says. Popular skills are longer-lived, more integrated
and more likely to touch backup, sync, config and credential vocabulary, which is precisely
what the rules that fire here key on.

---

## The finding that matters: one rule is detecting a language

`ATR-2026-00086 — Visual Spoofing via RTL Override, Punycode, and Homoglyph Injection`
produced **37 of the 116 flags (31.9%)**, on both `llm-input` and `tool-response`.

All 37 were Cyrillic-script descriptions. Not 36. All 37.

| Group | Samples | Flagged | Rate |
|---|---|---|---|
| Descriptions containing Cyrillic | 39 | **37** | **94.87%** |
| Everything else | 36,355 | 79 | 0.217% |

**437× difference, produced by script alone.** Verified directly rather than inferred — three
ordinary Russian sentences with no attack content whatsoever, and the same three sentences in
Latin script:

```
FIRES  "Управляет расписанием команды и проводит утренние бр" :: ATR-2026-00086
FIRES  "Поиск долгосрочной аренды квартир в Одессе с фильтра" :: ATR-2026-00086
FIRES  "Проверка наличия электроэнергии через сайт областных" :: ATR-2026-00086
clean  "Manages the team schedule and runs morning briefings" :: (none)
clean  "Long-term apartment rental search in Odesa with dist" :: (none)
clean  "Checks electricity availability through the regional" :: (none)
```

Two of the rule's five conditions cause it:

```yaml
- value: "[Ѐ-ӿ][a-zA-Z]|[a-zA-Z][Ѐ-ӿ]"   # any Cyrillic letter beside any Latin letter
- value: "[аеорсух]{2,}"  # two adjacent letters from а е о р с у х
```

The second matches two consecutive letters drawn from seven of the most frequent letters in
Russian. Ordinary Russian prose satisfies it within a few words. The first fires on any
bilingual sentence — `WEEEK через Public API`, which is how Russian technical writing is
normally written.

**The rule already contains the fix, applied to the wrong script.** Condition 4 was narrowed
from CJK Unified to CJK Compatibility ideographs, with this note in the file: matching the
wider range "detected the Chinese language, not a visual-spoofing attack". That is the same
defect, diagnosed and corrected for CJK, left in place for Cyrillic. The rule's own
`false_positives` list opens with "Legitimate content in Cyrillic, CJK, or RTL scripts".

This is not a tuning nit. A scanner that flags 95% of Russian-language skills and 0.2% of
English ones is unusable in any market that does not write in Latin script, and the failure
is invisible to every existing gate because the benign corpora are English.

---

## Top rules by flag count (`tool-response`, the widest shape)

| Rule | n | Severity | Maturity | Title |
|---|---|---|---|---|
| ATR-2026-00086 | 37 | high | test | Visual Spoofing via RTL/Punycode/Homoglyph |
| ATR-2026-00217 | 13 | critical | test | Credential Harvesting via Fake Backup Tool |
| ATR-2026-00148 | 5 | high | test | Multilingual Prompt Injection via Language Switch |
| ATR-2026-00200 | 5 | critical | test | Agent Memory and Configuration File Tampering |
| ATR-2026-00065 | 4 | high | test | Malicious Skill Update or Mutation |
| ATR-2026-00284 | 4 | medium | test | Glitch Token Destabilization Attack |
| ATR-2026-00510 | 4 | critical | test | Delayed Tool Invocation via Prompt Injection |
| ATR-2026-00051 | 3 | high | test | Agent Resource Exhaustion Detection |
| ATR-2026-00161 | 3 | critical | test | MCP Tool Description — IMPORTANT Tag Shadowing |
| ATR-2026-00244 | 3 | high | test | Dual-Response Persona Jailbreak |
| ATR-2026-00445 | 3 | medium | test | Translation Hijack with Side-Output Instruction |

Full table with three worked examples per rule: `data/measurements/clawhub-benign/summary/report.json`.

---

## Hand triage of the 30 highest-download flagged skills

This step is not optional and cannot be automated. The corpus is the registry in full, not a
curated benign set — the 2026-04 wild scan found confirmed droppers on this same platform.
Treating every flag as a false positive and tightening the rules would narrow detections using
true positives as the evidence.

| Verdict | n | Meaning |
|---|---|---|
| **False positive** | 20 | The rule's premise is absent from the skill. |
| **Dual-use, behaviourally on target** | 9 | The skill really does the thing the rule detects; intent is benign. |
| **True positive** | 1 | The rule found what it was written to find. |

**The true positive.** `artur-zhdan/undetectable-ai` (1,766 downloads) — *"Make AI text
undetectable… scans ChatGPT, Claude, OpenClaw output for patterns flagged by GPTZero,
Turnitin, Originality.ai, then auto-fixes them… bypass AI detection, evade checkers."*
`ATR-2026-02413 (AI Text Detection Evasion via Humanizer Services)` fired on all three
shapes. That is the rule working exactly as designed. **Had this corpus been dropped into
the benign gate unexamined, this rule would have been "fixed" until it stopped detecting the
one thing it exists to detect.**

**The dual-use nine** — behaviour matches, intent does not. Narrowing these rules to clear
them would remove real coverage:

- `thatguysizemore/agent-config` (3,258) → `ATR-2026-00200 Agent Memory and Configuration
  File Tampering`. The skill *is* "intelligently modify agent core context files (AGENTS.md,
  SOUL.md, MEMORY.md…)". Rule on target; publisher benign. There is no regex that separates
  these two.
- `lstpsche/quick-reminders` (3,491) → `ATR-2026-00204 Stealth Execution and Persistence`.
  Implemented with `nohup sleep`, which is a persistence mechanism.
- `robbyczgw-cla/personas` (6,204) → `ATR-2026-00472 DAN/Persona Jailbreak`. Twenty personas,
  switchable mid-conversation.
- `mrgoodb/migrate` (1,441), `pfrederiksen/synology-backup` (649),
  `udiedrichsen/clawdbot-sync` (2,095), `mneves75/healthkit-sync` (3,202) →
  `ATR-2026-00217 Credential Harvesting via Fake Backup Tool`. Backup and sync tools that
  really do move credentials — `migrate` says "optionally credentials" outright,
  `healthkit-sync` names Keychain storage.
- `maxfritzhand/bolta-skills-index` (617) → `ATR-2026-00504 Tool Capability Enumeration`.
  It is a capability catalogue.
- `dagmawibabi/addis-assistant-stt` (1,929) → `ATR-2026-00445 Translation Hijack`. A
  translation skill.

**Representative false positives** — the rule's premise is simply not present:

- `rsdouglas/janee` (2,384): *"Secrets management for AI agents. Never expose your API keys
  again."* → `ATR-2026-00422 Natural-Language Credential Disclosure Instruction`. A secrets
  manager flagged for mentioning secrets, at `critical`, on the skill-scan path.
- `zskyx/detect-injection` (1,913): a prompt-injection **detector** → `ATR-2026-00001`,
  `00020`, `00213`. Three rules, all matching the description of the defence.
- `mariovallereyes/luma-event-manager` (1,880): event RSVPs, no backup and no credentials
  anywhere → `ATR-2026-00217`, `critical`.
- `mrzilvis/fieldy-ai-webhook` (2,030): *"Wire a Fieldy webhook transform into Moltbot hooks."*
  → `ATR-2026-00472 DAN/Persona Jailbreak`.
- `fontstep/send-email` (5,920): a config path in `~/.openclaw/openclaw.json` →
  `ATR-2026-00161 IMPORTANT Tag Cross-Tool Shadowing`, `critical`.
- `benbjurstrom/fiscal` (626): *"Act as a personal accountant"* → `ATR-2026-00229` **and**
  `ATR-2026-00234`, which carry byte-identical titles ("Roleplay-Based Policy Bypass
  Jailbreak"). One skill, one trigger phrase, two rule ids — a duplicate pair that
  double-counts wherever it fires.

Note the severity distribution of the false positives: `ATR-2026-00217`, `00161`, `00200`,
`00422`, `00510` are all `critical`. On the `deny` side of a verdict these block installs.

---

## Can this corpus go into the benign gate?

**No — not as a fourth entry in `MEASUREMENT_CORPORA`.** Four reasons, in order of severity.

1. **It contains at least one true positive and nine dual-use hits.** A gate treats every
   sample as ground-truth benign. Adding this set instructs the promotion machinery to
   suppress `ATR-2026-02413` on the exact behaviour it was written for, and to file down
   `00200`, `00204`, `00217` and `00472` against genuine agent-memory-tampering,
   persistence, credential-handling and persona-switching vocabulary.

2. **It would swamp the gate with the shortest text in it.** `MEASUREMENT_CORPORA`
   (`data/skill-benchmark/benign`, `data/benign-corpus-extended`, `data/benign-code`) yields
   **12,060 samples**, median length 600 characters, p90 9,545. Adding 36,394 samples of
   median 159 characters makes 75% of the gate registry blurbs. Every rule keyed on bash
   blocks, file paths or tool declarations would post a large, meaningless 0 — the corpus
   simply lacks the shapes those rules need, which is exactly the "unasked question reported
   as an answer" state `gate-corpus-visibility.ts` exists to name.

3. **It re-rates all 784 rules at once.** FP measurement feeds action-eligibility. A change
   of this size to the denominator is a decision for a human, not a side effect of a research
   run. Nothing here has been added to any gate corpus; output lives in
   `data/measurements/clawhub-benign/`.

4. **It is not a benign set.** It is the whole registry, including whatever was published to
   it. Calling it benign is an assumption, not a fact, and the triage above shows the
   assumption is already false at n=30.

**What it is genuinely good for**, and should be used for:

- **A script-coverage regression.** The 39 Cyrillic samples are the highest-value 39 samples
  in this file. No existing corpus contains them, which is why a 437× script bias survived
  in a `high`-severity rule in production. Promote those 39 (plus CJK and RTL equivalents)
  into a dedicated non-Latin regression set that gates any rule touching Unicode.
- **A dual-use boundary set.** The nine dual-use skills are the honest hard cases. They
  belong in an explicitly-labelled "benign but behaviourally indistinguishable" file that
  documents what ATR cannot separate, rather than in a corpus that pretends it can.
- **A top-of-market watchlist.** The top-1,000 stratum flagging at 0.60% is the number to
  track over time. It is the rate at which ATR would interrupt installs that matter.

---

## Side findings

**The enforce lane detects almost nothing, so its clean FP is an unasked question.** The
enforce-lane flag rate on this corpus is 0.011% (4 samples, 2 rules). Measured against the
repo's own 32 malicious skill samples across the same three shapes:

| Lane | Rules | Malicious detected | Distinct rules firing |
|---|---|---|---|
| `hunt` (default) | 784 | 31/32 — 96.9% | 12 |
| `alert` | 784 | 31/32 — 96.9% | 12 |
| `enforce` | 784 | **1/32 — 3.1%** | **1** |

A 0.011% false-positive rate on a lane that catches 3.1% of known malware is not a precision
result. Any external citation of enforce-lane FP has to carry the recall number beside it.

**`SKILL_CONTEXT_DENYLIST` is dead code with a self-contradicting comment.** `src/engine.ts:69`
defines a 22-rule set documented as "excluded from skill-context scanning due to high
false-positive rate" (`ATR-2026-00111` at "70% FP"). It is referenced nowhere in `src/`,
`scripts/` or `tests/`. Its own header says the list was "reduced from 22 → 10"; it holds 22.
Eight ids appear in a trailing "REMOVED from denylist" comment while still being active
members of the set. Practical impact is small — 21 of the 22 are `scan_target: mcp` and are
already unreachable on the skill path via the compound gate — but **`ATR-2026-00123`
(`scan_target: skill`) is reachable and runs on skill scans while the code says it is
excluded.** Either wire the set up or delete it; leaving it is a false record of what the
scanner does.

**`ATR-2026-00229` and `ATR-2026-00234` are duplicates.** Byte-identical titles, both fired on
the same sample. Any per-rule FP count involving either is inflated by the pair.

---

## Limitations — read before quoting any number above

1. **This is registry description text, not SKILL.md.** The crawl stored no skill bodies.
   Median 159 characters; 13,693 of 36,394 summaries are exactly 160 characters and 15,603
   (42.9%) end in a literal `...`. Every number here is a rate on marketplace listing text.
   **"0.3% FP on 36,394 real skills" is not a supportable sentence.** The supportable sentence
   is "0.319% of 36,394 real skill *descriptions*, on the `tool-response` shape, hunt lane".

2. **The corpus is a snapshot dated 2026-03-26** measured against rules dated 2026-08-19.
   Rules written after the crawl were not exposed to the skills that motivated them.

3. **Only 39 of 777 live rules fired at all.** The other 738 are unmeasured here, not clean.
   Short prose cannot exercise a rule keyed on `tool_args` JSON or a trace DAG.

4. **Enforce-lane figures are derived offline** from the hunt-lane run by rule maturity. Four
   rules carry `confirm: embedding`, which the engine additionally drops in enforce/alert
   without an embedding module. Those four could make the true enforce-lane count lower, never
   higher.

5. **Triage covered the 30 highest-download flagged samples**, not all 116. The 86 remaining
   are lower-download and untriaged; the FP/dual-use/TP split above should not be extrapolated
   to them without doing the work.

6. **A `card` variant (`name + summary`) was built and not run.** Several rules key on skill
   names, and names are attacker-controlled. That measurement is outstanding.
