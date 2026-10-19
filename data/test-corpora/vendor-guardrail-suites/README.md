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
  licenses in `LICENSES/`; copyright stays with Protect AI, NVIDIA and Promptfoo respectively.
  Strings a vendor's test files did not attribute to anyone else are redistributed under that
  vendor's repository license, with no further claim about where the vendor took them from.
- `LICENSES/` — each vendor's license file, verbatim from its pinned commits (identical at both pins
  of a vendor): `llm-guard.LICENSE` (MIT), `nemo-guardrails.LICENSE.md` (NeMo Guardrails' Apache-2.0
  notice, as the repository ships it; the license text it refers to is
  https://www.apache.org/licenses/LICENSE-2.0), `promptfoo.LICENSE` (MIT). `manifest.json` records
  the sha256 of each at each pin, and `fetch-vendor-suites.py --check` fails when a copy is missing,
  edited or stray, or when that sha256 no longer matches upstream.
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

## How far from out-of-sample (measured, ATR 4.1.5, 2026-10-19)

The measurement file records this, so it can be re-checked and does not depend on this text.

- Recall: 97/126 = 77.0% (hunt), 92/126 = 73.0% (alert), 7/126 = 5.6% (enforce).
- Ablation reference (`breakdown.in_sample_ablation.without_rules_naming_source`): the 16 rules
  whose YAML names promptfoo, llm-guard or NeMo, or carries the `(vendor-corpus-import)` tag,
  removed: 78/126 = 61.9% (hunt), 70/126 = 55.6% (alert), 7/126 = 5.6% (enforce). Hunt lane per
  vendor: llm-guard 26/46, NeMo Guardrails 20/22, promptfoo 32/58. Cite this beside the headline.
- Rule-text overlap (`breakdown.overlaps.rule_text`): 44 rules carry a 40-character run of some
  sample's text in their YAML, 35 of them rules the ablation keeps. Of the 78 hunt-lane detections
  in the ablation, 23 are by such a rule on the sample it overlaps (llm-guard 2, NeMo Guardrails 5,
  promptfoo 16). Removing those rules as well
  (`without_rules_naming_or_sharing_text`, 51 rules): 58/126 = 46.0% (hunt), 5/126 = 4.0% (enforce).
- Other corpora (`breakdown.overlaps.garak_full`): 5 of NeMo Guardrails' 22 attack samples are
  DAN-style jailbreaks that share 58% to 99% of their text with a prompt in `garak-full`'s
  `dan.json` and `inthewild.json` (the same template with a different payload), a corpus other
  rules were mined from. All 5 are detected in the hunt lane of the ablation.
- NeMo Guardrails produced no ATR rule, but it is not out-of-sample either: 8 of its 22 attack
  samples have text carried by some rule's YAML and 5 share a template with garak-full.
- Precision is not cited: the vendors ship 20 benign cases (the hunt lane flags 1, alert and
  enforce 0). `data/stats.json` carries `null` precision, F1 and FP rate for this source
  (`breakdown.precision_not_citable`).

## Reproduce

```
npm ci
bash scripts/vendor-suites/reproduce.sh           # re-extract + compare sha256, re-audit, measure (no write)
bash scripts/vendor-suites/reproduce.sh --write   # also write a measurement file
```

Measurement: `data/measurements/vendor-guardrail-suites/`.
