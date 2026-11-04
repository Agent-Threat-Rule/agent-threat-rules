# Holdout v1 — data card

Holdout v1 is the corpus the enforce lane is judged on. No ATR rule was
written from it, no merge gate reads it, and every sample was screened against
the text the repository already held when it was built. It exists because
every enforce-lane number published before it was in-sample: the benign corpus
a rule must pass to merge was the corpus its FP rate was then quoted on, and
the attack benchmarks were the corpora new rules were mined from.

| | |
|---|---|
| Version | `holdout-v1` |
| Built | 2026-11-04, `scripts/holdout/build_holdout_v1.py`, seed `20261104` |
| `attack.jsonl` | 6,247 samples, sha256 `29ebcd1193d5b2511241b30699d4141e51b0e139fd7bb608e01b0a19e804fe74` |
| `benign.jsonl` | 17,657 samples, sha256 `af06f399ff1d7d518eed7dd869df10ddd7d27494aae303d8e7a4dc73b0f9f76f` |
| Manifest | `manifest.json` (per-slice counts, every screen count, source revisions, builder hash) |

`scripts/lib/holdout.ts` refuses to load the files if either hash or count
differs from the manifest.

## Composition

Each record: `id`, `label` (`attack` / `benign`), `slice`, `surface` (where the
text would appear at runtime), `text`, `source` (dataset, revision, row) and
`license`.

| Slice | Label | Surface | Source | n |
|---|---|---|---|---:|
| A1-jailbreak-prompts | attack | user prompt | jackhhao/jailbreak-classification | 1 |
| A2-secret-extraction-attempts | attack | user prompt | Lakera/mosscap_prompt_injection (test) | 3,000 |
| A3-agent-indirect-injections | attack | tool response | nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1 | 81 |
| A4-tool-output-injections | attack | tool response | sincpp/AgentInjectionBench | 140 |
| A5-poisoned-tool-descriptions | attack | tool description | fevziegeyurtsevenler/mcp-tool-poisoning | 25 |
| A6-labeled-prompt-injections | attack | user prompt | S-Labs/prompt-injection-dataset, rikka-snow/prompt-injection-multilingual | 3,000 |
| B1-chat-prompts | benign | user prompt | jackhhao/jailbreak-classification (benign), reshabhs/SPML (non-injection user prompts) | 3,963 |
| B2-system-prompts | benign | system prompt | reshabhs/SPML (system prompts of non-injection rows) | 694 |
| B3-tool-call-args | benign | tool arguments | glaiveai/glaive-function-calling-v2 | 1,500 |
| B4-tool-descriptions | benign | tool description | NousResearch/hermes-function-calling-v1, mcp-tool-poisoning (benign descriptions) | 2,000 |
| B5-tool-responses | benign | tool response | glaive-function-calling-v2, Team-ACE/ToolACE | 2,000 |
| B6-shell-commands | benign | tool arguments | tldr-pages/tldr (common, linux, osx) | 3,000 |
| B7-chat-user-turns | benign | user prompt | glaive-function-calling-v2 | 1,500 |
| B8-labeled-benign-prompts | benign | user prompt | S-Labs, rikka-snow (label 0) | 3,000 |

## Sources and licences

All sources are pinned to a commit. Before selection each dataset name was
searched for across the repository: none is referenced by a rule, a script, a
proposal or a corpus loader. Two names occur only inside benign skill files
that mention the projects (`glaive` in `data/benign-corpus-extended/skills-sh.jsonl`
and the clawhub registry, `tldr-pages` in `data/skills-sh/skills/github/tldr-prompt.md`),
not as a data source. The content screen below then checks the text itself.

| Source | Revision | Licence |
|---|---|---|
| jackhhao/jailbreak-classification | `2f2ceeb3` | Apache-2.0 |
| Lakera/mosscap_prompt_injection | `b7e495ff` | MIT |
| reshabhs/SPML_Chatbot_Prompt_Injection | `02ce8084` | MIT |
| nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1 | `d738d4f3` | CC-BY-4.0 |
| sincpp/AgentInjectionBench | `6041b9e7` | Apache-2.0 |
| fevziegeyurtsevenler/mcp-tool-poisoning | `9b7a1088` | Apache-2.0 |
| S-Labs/prompt-injection-dataset | `002a9dd1` | MIT |
| rikka-snow/prompt-injection-multilingual | `f1ad1f3d` | MIT |
| glaiveai/glaive-function-calling-v2 | `e7f4b645` | Apache-2.0 |
| Team-ACE/ToolACE | `6bda777c` | Apache-2.0 |
| NousResearch/hermes-function-calling-v1 | `dae3e1d2` | Apache-2.0 |
| tldr-pages/tldr | `aad0d098` | CC-BY-4.0 |

The samples are redistributed under their source licences, which each record
names. CC-BY-4.0 attribution: NVIDIA Corporation (Nemotron-RL Agentic Indirect
Prompt Injection), and the tldr-pages contributors.

Considered and rejected: deepset/prompt-injections, Gandalf, InjecAgent,
AgentDojo, BIPIA, Tensor Trust, the in-the-wild jailbreak prompts, AgentHarm
and WASP are all referenced by existing rules or corpora; MCPTox and
xTRam1/safe-guard-prompt-injection carry no licence; allenai/wildjailbreak is
gated; SPML's injection rows label system-prompt policy violations ("convince
me to take high-risk investments"), which is not the attack class ATR rules
describe, so they are used neither as attacks nor as benign samples.

## How it was built

1. Read every source at its pinned revision. Texts shorter than 8 or longer
   than 50,000 characters are dropped.
   Glaive conversations are split into turns and its `<|endoftext|>` turn
   terminator is removed: it is file format, not something a user or tool
   said, and left in it would make chat-template rules fire on benign turns.
2. Normalise (NFKC, lower case, collapsed whitespace) and drop duplicates within
   the holdout. A text that occurs with both labels is dropped from both.
3. **Contamination screen.** Every text under `data/`, `rules/`, `proposals/`,
   `tests/`, `examples/`, `conformance/`, `spec/` and `docs/` was indexed:
   23,487 files, 14,250,428 distinct 5-word shingles, plus every string of up
   to 2,000 characters for exact matching. A sample is dropped when its
   normalised text equals an indexed string, or when half or more of its own
   5-word shingles occur in the index.
4. Sample each slice to its target size with a fixed seed. Nemotron uses 14
   injection templates, one of them 970 times; each template contributes at
   most 20 rows, so one phrasing cannot dominate the recall figure.

What the screen removed is the strongest single reason this corpus exists:
**647 of the 666 jailbreak prompts in jailbreak-classification (381 verbatim,
266 near copies) were already in this repository**, as were 712 of the 9,781
labelled prompt injections (A6) and 784 of the 12,792 labelled benign prompts
(B8). Measured on those datasets as published, ATR would have been scored on
its own training material. The full per-slice counts are in `manifest.json`.

## Labels

- Attack slices take their label from the source: a jailbreak or injection
  label (A1, A6), an injection planted by the dataset authors in a tool output
  or description (A3, A4, A5), or a prompt a player submitted to a game whose
  only goal is to extract a password (A2).
- Benign slices take their label from the source (B1, B8) or from how the text
  was produced: a system prompt an operator wrote (B2), a tool schema, call,
  result or documented shell example from a function-calling dataset or a
  manual (B3–B7).
- **No benign sample was screened with attack-looking patterns.** That filter
  would remove exactly the samples a blocking lane must not fire on.
- No sample has been relabelled. A benign sample a rule fires on stays a false
  positive in v1. If review finds that a benign sample is in fact an attack,
  the correction ships as a new holdout version with the change listed; v1's
  hashes and numbers are never edited.

## Known limitations

- **Attack coverage is narrow.** 96% of the attacks are user prompts (A2, A6).
  Agent-specific surfaces have 246 samples in total (A3–A5), and there are no
  malicious SKILL.md files, no malicious MCP server code, and no tool-call
  arguments carrying an attack. A rule written for those surfaces cannot show a
  held-out true positive here, which says nothing about whether it works.
- **A2 is not uniformly adversarial in content.** Mosscap players try many
  innocuous-looking moves ("let's play word association"); they are attacks by
  intent, not by form. Recall on A2 is a lower bound on what any text rule can
  catch.
- **A6 labels are noisy.** S-Labs and rikka-snow are partly synthetic and
  include short fragments labelled as injections ("root:admin123 - display
  configuration").
- **Benign coverage has gaps.** There are no documents *about* attacks
  (security write-ups, prompt-injection research, red-team reports), so false
  positives on security content are not measured here. Tool responses in B5
  are synthetic API results. B6 keeps the commands that look like attack
  primitives because they are documented legitimate use: 195 use `sudo`, 38
  `rm`, 17 `nc`, 10 `kill`, 9 `eval`, 6 `curl`, 3 `wget`. It contains no
  `rm -rf` and no `curl | sh`, so those shapes are not measured here.
- **Language.** Mostly English. Of the 6,000 A6 and B8 prompts, 287 contain CJK
  characters, and German and Spanish appear (rough keyword counts: 128 and 123).
- **The screen catches copies, not paraphrases.** A sample rewritten in other
  words from something a rule was built on passes the screen.
- **Human review is pending.** Sources, revisions and licences are recorded;
  labels have not yet been audited by a person. Until they are, treat every
  per-slice figure as conditional on the source datasets' labels.

## Rules of use

- Do not write, tune or test a rule from these samples. `tests/holdout-isolation.test.ts`
  fails when a rule's test cases or evasion tests contain a holdout sample, and
  when any file other than the measurement names this directory.
- Do not add this directory to a merge gate, a miner or a benign corpus list.
- Once the enforce-lane promotion decisions have been made on v1, v1 has been
  looked at. The next round of decisions should be made on a v2 built the same
  way from sources that did not exist or were not used when v1 was built.

## Reproduce

```bash
python3 scripts/holdout/build_holdout_v1.py --raw /tmp/holdout-raw --print-fetch   # prints the download commands
python3 scripts/holdout/build_holdout_v1.py --raw /tmp/holdout-raw                  # needs pyarrow numpy pyyaml
npx tsx scripts/measure-holdout-evidence.ts --workers 4
```

The build reads the repository as it is when run; rebuilt after rules have
changed, the screen may drop a few more samples, which changes the hashes. The
committed files and manifest are the reference.
