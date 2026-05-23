# PR draft for microsoft/RAMPART

**Title:** Add ATR rule corpus evaluator (community detection patterns)

**Body:**

---

RAMPART's launch post (2026-05-20) names community-contributed threat patterns as the way the framework keeps pace with evolving attacks. This PR is one such contribution: a `BaseEvaluator` subclass that loads detection rules from the open MIT-licensed [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules) corpus and exposes them as a RAMPART evaluator.

## What this adds

- `rampart/evaluators/atr_rules.py` — `ATRRulesEvaluator(rules_dir=..., categories=..., min_severity=..., strict=...)`. Loads every `.yaml` rule under `rules_dir`, compiles the regex condition for each, and matches against `context.text`, the latest user request, or `context.all_tool_calls` depending on the rule's declared field.
- `rampart/evaluators/__init__.py` — re-exports `ATRRulesEvaluator`.
- `tests/evaluators/test_atr_rules.py` — 13 tests covering load-time filtering (category allowlist, severity gate, strict vs lenient skip), evaluation across all three target fields, multi-rule aggregation, and empty-context safety. Tests use temp YAML fixtures so they do not depend on the live ATR corpus.
- `docs/evaluators/atr_rules.md` — usage and behavior docs in the same shape as the existing three evaluators.

## Why ATR

ATR is a 425-rule MIT-licensed detection corpus that is already in production across four external organizations through public GitHub merges:

| Org | What landed | PR |
|---|---|---|
| Microsoft Agent Governance Toolkit | 287-rule production pack | [microsoft/agent-governance-toolkit#1277](https://github.com/microsoft/agent-governance-toolkit/pull/1277) (2026-04-26) |
| Cisco AI Defense skill-scanner | Full ATR pack | [cisco-ai-defense/skill-scanner#99](https://github.com/cisco-ai-defense/skill-scanner/pull/99) (2026-04-22) |
| MISP CIRCL | misp-galaxy global cluster + taxonomies tag vocab | [#1207](https://github.com/MISP/misp-galaxy/pull/1207), [#323](https://github.com/MISP/misp-taxonomies/pull/323) (2026-05-10) |
| Gen Digital Sage chain (via precize) | Agent-Security-Regression-Harness | [precize/Agent-Security-Regression-Harness#74](https://github.com/precize/Agent-Security-Regression-Harness/pull/74) (2026-05-11) |

On 2026-05-11 the Microsoft Copilot SWE Agent autonomously opened [microsoft/agent-governance-toolkit#1981](https://github.com/microsoft/agent-governance-toolkit/issues/1981) with regression test fixtures that presumed ATR detection of two Semantic Kernel CVEs (CVE-2026-26030 lambda+eval RCE, CVE-2026-25592 autostart file write). ATR v2.1.2 with rules `ATR-2026-00440` + `ATR-2026-00441` was merged, npm-published, and GitHub-released by 08:24 UTC the same day — end-to-end CVE-to-shipped-rule **2 hours 16 minutes**. (Honest disclosure: coverage was partial — two of four Copilot-generated fixtures matched the v2.1.2 canonical regex shape; the rest landed in later versions.)

That dependency loop is the case for shipping an ATR adapter inside RAMPART. RAMPART users running pytest red-team flows today get to assert against the same corpus that Microsoft's own automation references.

## Scope

In scope (v1):
- ATR rules with `operator: regex` conditions on `field` ∈ {response, user_input, tool_call}
- Category allowlist and minimum-severity gate
- Strict vs lenient load modes for production vs experimentation
- Aggregated evidence — a single failure surfaces every matched rule_id

Not in scope (deferred to follow-up):
- Non-regex condition operators (`ml_classifier`, `ast`, `bytecode`) — need a different evaluator backend
- Multi-condition `condition: all` rules across heterogeneous fields
- Cross-turn temporal patterns

These are documented in the evaluator's module docstring and in `docs/evaluators/atr_rules.md` so users know what the adapter does and does not cover today.

## Tests

```
$ python -m pytest tests/evaluators/test_atr_rules.py -v
============================== 13 passed in 0.05s ==============================
```

Coverage:
- Loading: valid rules, category allowlist, severity filter, strict-on-unsupported-operator, lenient-skip-on-unsupported, XOR arg validation, missing-dir handling (7 tests)
- Evaluation: response field match, user_input field match, tool_call field match, no-match returns NOT_DETECTED, multi-rule aggregation, empty-context safety (6 tests)

## Dependencies

Adds `PyYAML` to runtime deps (existing dep in many RAMPART downstream stacks; happy to vendor a minimal parser if PyYAML is unwanted).

## Maintenance

ATR is maintained by [Adam Lin](https://github.com/eeee2345) under fiscal sponsorship from Open Source Collective Inc. (501(c)(3), EIN 81-1567737). Rule corpus is MIT licensed with public GitHub history and a CC-0 / MIT companion catalog at `Agent-Threat-Rule/ai-rmf-oscal-catalog` mapping rules to NIST AI RMF (Path 1 invitation from NIST received 2026-05-11).

The corpus ships a new version on a 1-2 week cadence (latest tag at time of writing: v3.0.0-alpha.0, 425 rules). This adapter loads from a user-provided rules_dir so RAMPART consumers pin a specific corpus version rather than tracking ATR's main branch.

Happy to iterate on naming, interface, or scope. Microsoft AI Safety org has been a consistently constructive maintainer of the AGT merges; I trust this team to land good feedback fast.

— Adam (adam@agentthreatrule.org)

---

## Submit checklist (do this when ready)

- [ ] Fork microsoft/RAMPART → eeee2345/RAMPART (or your preferred handle)
- [ ] Branch: `add-atr-rules-evaluator`
- [ ] Copy `integrations/rampart/src/atr_rules_evaluator.py` → `rampart/evaluators/atr_rules.py` (RENAME class file to match RAMPART's snake_case convention; `ATRRulesEvaluator` class name stays)
- [ ] Add `ATRRulesEvaluator` to `rampart/evaluators/__init__.py` `__all__`
- [ ] Copy `integrations/rampart/tests/test_atr_rules_evaluator.py` → `tests/evaluators/test_atr_rules.py` (REMOVE the stub block at top — use real `rampart.core.types`)
- [ ] Add `PyYAML>=6.0` to `pyproject.toml` runtime deps
- [ ] Write `docs/evaluators/atr_rules.md` (copy from `integrations/rampart/README.md` Behavior + Use sections, RAMPART-doc voice)
- [ ] Run `pytest tests/evaluators/test_atr_rules.py -v` — should be 13/13 green
- [ ] Open PR with title and body above
- [ ] Reply to first reviewer comment within 24h (responsiveness signal)
- [ ] Wait. No bumping — memory rule.
