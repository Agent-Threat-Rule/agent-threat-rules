# Benign conversation corpus

## Why this exists

Roughly half the rule corpus targets conversational traffic — 394 of 784 rules
declare `agent_source.type: llm_io`, and 245 of those are still `maturity: test`.
Until now the benign corpus they were measured against contained no conversation
at all:

| file | samples | what it is |
|---|---:|---|
| `skills-sh.jsonl` | 3,042 | skill manifests |
| `arxiv.jsonl` | 1,163 | paper abstracts |
| `official-skills.jsonl` | 256 | skill manifests |
| `pypi.jsonl` / `npm.jsonl` / `agent-ops.jsonl` | 288 | package metadata, shell commands |
| `wild-fp-confirmed.jsonl` | 68 | confirmed field FPs |

A prompt-matching rule that clears a corpus of skill manifests has not been
measured against the traffic it actually inspects. That gap is the stated reason
the daily maturity-promotion schedule is paused: lane membership was a function
of elapsed time, not of measured evidence.

## Source and licence

`conversation-oasst1.jsonl` is drawn from
[OpenAssistant/oasst1](https://huggingface.co/datasets/OpenAssistant/oasst1),
released under **Apache-2.0**. Each line carries `source_dataset` and `license`
so downstream consumers can trace provenance. Apache-2.0 permits redistribution
with attribution and does not impose a share-alike obligation on this repository
or on anything that vendors it.

Datasets rejected on licence grounds rather than quality: `databricks-dolly-15k`
(CC BY-SA 3.0 — the share-alike term would propagate into an MIT repository that
ships inside third-party products), and any Alpaca-derived set (non-commercial).

## Selection discipline

The prior lesson here is expensive: a benign gate was once found to contain real
jailbreak content, which made every "0 FP" verdict measured against it worthless.
A sample is kept only if it clears **both** the dataset's own moderation signals
**and** an independent attack-marker screen.

Dataset-side, a sample is dropped when `deleted` is set, `review_result` is not
true, `synthetic` is set, the language is not English, or any `detoxify` score or
human `labels` value exceeds a conservative threshold (toxicity 0.05, threat 0.02,
sexual_explicit 0.02, hate_speech 0.05, and so on).

Independently, a sample is dropped if it contains any shape an ATR rule looks for
— instruction-override phrasing, persona-switch framing, DAN or developer-mode
references, system-prompt extraction, encoded payloads, credential paths, reverse
shells, pipe-to-shell. A benign corpus containing those is not a benign corpus; it
is an unlabelled attack corpus, and it would certify the exact rules that should
fail.

Yield from ~21,100 source rows: 6,706 kept. The independent attack screen
rejected 4 samples that had already cleared the dataset's own moderation — a small
number, and the reason the second screen exists. A benign corpus is only as good
as its worst line.

Size is deliberately subordinate to trust. Growing this file matters less than
keeping every line in it defensible.

## What it found immediately

Evaluated against `main` at the time of writing, 99 of 6,706 samples matched at
least one rule — a **1.48% false-positive rate across 30 distinct rules**.

An earlier 569-sample draft of this corpus surfaced only 10 of those 30. Twelve
times the corpus found three times the rules, which is the clearest evidence
available that the previous corpus was not merely missing conversation but was
too small to characterise what it did contain.

Of the 30 rules, 24 are `maturity: test`, 3 are `experimental` — the promotion
pool the paused schedule would have advanced. The remaining **3 are already
`maturity: stable`, which is to say they are in the enforce lane now**, blocking
on this content in any deployment that runs that lane:

| rule | benign text that matched |
|---|---|
| `ATR-2026-01750` DoS via Repeat-Word-N-Times | `Here's a Python code that rolls 3 d20 dice…` |
| `ATR-2026-00443` Word-Fragment Concatenation Assembly | `The character "^" is used to indicate powers, here "c^2" is "c to the power of two"` |
| `ATR-2026-01904` Injected Hyperlink — Scam / Malware URL | an ordinary Python async code block |

The worst offenders by volume are not subtle either:

| rule | n | benign text that matched |
|---|---:|---|
| `ATR-2026-00020` System Prompt Leakage | 20 | `As an AI language model, I am programmed to follow ethical and legal guidelines…` |
| `ATR-2026-01756` Symbol / Emoticon Trigger | 12 | `I am glad that I was able to help :)` |
| `ATR-2026-00005` | 9 | a sentence about the Hubble telescope |
| `ATR-2026-00001` Direct Prompt Injection | 8 | a short story about Rick Sanchez |

`ATR-2026-00020` matches the most common assistant boilerplate in existence.
`ATR-2026-00001` is the rule the project leans on hardest, and it fires on
creative writing.

This file does not fix any of them. Narrowing a rule trades away recall, and that
trade has to be measured per rule in its own reviewed change rather than assumed
in bulk. What this corpus changes is that the trade is now measurable at all.
