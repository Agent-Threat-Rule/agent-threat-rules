---
license: mit
task_categories:
  - text-classification
language:
  - en
tags:
  - agent-security
  - prompt-injection
  - skill-security
  - mcp
  - detection
size_categories:
  - n<1K
pretty_name: ATR Skill-Security Benchmark
configs:
  - config_name: default
    data_files: atr-skill-benchmark.jsonl
---

# ATR Skill-Security Benchmark

A labeled corpus of `SKILL.md` files for evaluating detection of malicious agent
skills — prompt injection, tool poisoning, credential theft, malware droppers
and supply-chain attacks hidden inside natural-language agent instructions.

Published as part of [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules),
an open, vendor-neutral detection standard for AI agents (like Sigma, but for
agent attacks).

## Why this exists

`SKILL.md` files are natural-language instructions an AI agent follows literally.
Attackers embed instructions that read like documentation to a human but execute
as commands when an agent processes them. This benchmark pairs real, benign
skills with curated malicious ones so detectors can be measured on both recall
and — crucially — false-positive rate against realistic hard negatives.

## Composition

- 498 samples total: 466 benign, 32 malicious.
- Benign includes 415 real skills from real authors plus evasive-but-benign
  stubs and official MCP skills — these are deliberate hard negatives that stress
  precision.
- Malicious spans context poisoning, rug-pull time bombs, credential/SSH/wallet
  harvesting, reverse shells, base64/unicode-smuggled instructions, DNS
  exfiltration, typosquatting and malware droppers.

The class balance is intentionally precision-oriented: many realistic benign
skills, a focused set of distinct attack types. Report false-positive rate on the
benign split, not just recall on the malicious one.

## Schema

Each line of `atr-skill-benchmark.jsonl` is one sample:

| field | description |
| --- | --- |
| `id` | filename stem |
| `text` | full `SKILL.md` content |
| `label` | `benign` or `malicious` |
| `source_family` | curation family (`real`, `adv`, `ninja`, `openclaw`, `snyk`, `mcp-official`, `evasive-stub`) |
| `attack_type` | attack described (malicious only); `null` for benign |

## Load

```python
from datasets import load_dataset

ds = load_dataset("Agent-Threat-Rule/atr-skill-benchmark", split="train")
print(ds[0]["label"], ds[0]["attack_type"])
```

You can run the ATR reference engine over it with `pip install pyatr`:

```python
from pyatr import scan
flagged = [r for r in ds if scan(r["text"])]
```

## Responsible use

The malicious samples exist to build and evaluate defenses. They are curated
attack instructions, not a distribution channel for working exploits, and should
only be used for detection research and defensive tooling.

## Provenance and citation

- Methodology: `benchmark/METHODOLOGY.md` in the ATR repository.
- Paper (Zenodo): https://doi.org/10.5281/zenodo.19178002
- License: MIT, same as the ATR standard.
