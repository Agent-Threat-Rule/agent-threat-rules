# Vendor guardrail test suites

The adversarial (and, where the vendor ships them, benign) test cases of three guardrail / red-team
projects, extracted from pinned upstream commits by a script, with every sample traceable to
repo + commit + path + line.

| Vendor | Repo | License | Pinned commits |
|---|---|---|---|
| llm-guard | https://github.com/protectai/llm-guard | MIT | `168c1034ffdb33837e7ae6fd6a16b80567c1be03` (`tests/` unchanged since `9e007675`, 2025-09-03) |
| nemo-guardrails | https://github.com/NVIDIA-NeMo/Guardrails | Apache-2.0 | `f17724d50248baaf14575e9efc8c7a363adadfb3` (2026-05-11), `af242f0b47572b5fc8cf3817c0da326f26a99de8` (2026-10-15) |
| promptfoo | https://github.com/promptfoo/promptfoo | MIT | `5f89b7c86ea04e5c03fbe7789dd0e47aed05bf43` (2026-05-11), `ea8b3d073a63769f7be243ac3c3460f72881a930` (2026-10-17) |

The 2026-05-11 pins are the last upstream commits before the 2026-05-12 import that produced
`data/test-corpora/{llm-guard,nemo-guardrails,promptfoo}/corpus.json` and rules ATR-2026-00500..00505;
the second pin is the vendor's head when this corpus was built. A text found at both pins is one sample.

## Files

- `sources.json` — pins, licenses, the inclusion policy, and one selector per (file, rule of extraction).
- `samples.jsonl` — the deduplicated samples (`id`, `sha256`, `vendor`, `label` attack|benign,
  `category`, `role` input|output, `pins`, `text`). Third-party text, redistributed under the
  licenses above; copyright stays with Protect AI, NVIDIA and Promptfoo respectively.
- `manifest.json` — counts, the sha256 of `samples.jsonl`, the license file seen at each pin, and the
  full provenance (repo, commit, path, line, selector) of every sample.
- `legacy-corpora-provenance.json` — whether each of the 94 samples of the 2026-05-12 corpora
  occurs in the vendor repo it is attributed to.

## Inclusion policy (decided before measuring)

- **attack**: a case the vendor's own test asserts its security scanner/rail flags (llm-guard
  `expected_valid=False`; a NeMo test expecting a block, refusal or `jailbreak=True`), or an attack
  example promptfoo ships as a red-team generator few-shot example (`DEFAULT_EXAMPLES`) or documents
  under "Example Test Cases" for the plugin.
- **benign**: a case the vendor's own test asserts passes (llm-guard `expected_valid=True`; NeMo tests
  expecting the normal answer). promptfoo's red-team plugins ship no benign prompts.
- **role=output**: text the vendor checks on an output rail (NeMo injection-detection YARA rail and F5
  output rail, promptfoo's data-exfil grader patterns).
- **excluded**: content-safety, toxicity, topic-control, PII, secrets, ban-substring, code and language
  scanners (policy filters, not attacks on the agent); perplexity calibration strings no rail-level
  test asserts on; mock-only edge cases; grader example responses that are disclosures, not payloads;
  promptfoo cross-session "User A" turns (they only plant the secret).

## Reproduce

```
npm ci
bash scripts/vendor-suites/reproduce.sh           # re-extract + compare sha256, re-audit, measure (no write)
bash scripts/vendor-suites/reproduce.sh --write   # also write a measurement file
```

Measurement: `data/measurements/vendor-guardrail-suites/`.
