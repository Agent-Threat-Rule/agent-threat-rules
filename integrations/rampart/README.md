# ATR Rules Evaluator for RAMPART

[Microsoft RAMPART](https://github.com/microsoft/RAMPART) is a pytest-native safety and security testing framework for agentic AI applications. This adapter loads detection rules from the open-source [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules) corpus and exposes them as a RAMPART evaluator.

```python
from atr_rules_evaluator import ATRRulesEvaluator

evaluator = ATRRulesEvaluator(
    rules_dir="rules/",
    categories=["prompt-injection", "tool-poisoning"],
    min_severity="high",
)
# Use anywhere RAMPART accepts an evaluator.
```

## Why

RAMPART's three built-in evaluators (`ResponseContains`, `SideEffectOccurred`, `ToolCalled`) cover the test-case scaffolding. They do not cover the threat-pattern corpus you assert *against*. RAMPART's announcement post invites the community to bring threat patterns "as attack patterns evolve."

ATR is exactly that corpus:

- **425+ rules** across 10 categories (prompt injection, tool poisoning, skill compromise, context exfiltration, excessive autonomy, model abuse, model security, agent manipulation, data poisoning, privilege escalation)
- **MIT licensed**, language-agnostic YAML, drift-checked in CI (`stats.json`)
- **96,096-skill wild scan** with 751 confirmed-malicious samples for empirical grounding
- **Production-merged** at Microsoft Agent Governance Toolkit (PR [#1277](https://github.com/microsoft/agent-governance-toolkit/pull/1277), 287-rule expansion, 2026-04-26), Cisco AI Defense skill-scanner (PR [#99](https://github.com/cisco-ai-defense/skill-scanner/pull/99), full pack, 2026-04-22), MISP CIRCL ([galaxy #1207](https://github.com/MISP/misp-galaxy/pull/1207), [taxonomies #323](https://github.com/MISP/misp-taxonomies/pull/323), 2026-05-10), and Gen Digital Sage chain.

On 2026-05-11 the Microsoft Copilot SWE Agent opened [microsoft/agent-governance-toolkit#1981](https://github.com/microsoft/agent-governance-toolkit/issues/1981) with regression fixtures presuming ATR detection of two Semantic Kernel CVEs. ATR v2.1.2 shipped the matching rules and was npm-published 2 hours 16 minutes later. That dependency loop is the strongest concrete case for shipping ATR coverage inside RAMPART today.

## Install

```bash
pip install agent-threat-rules-rampart-evaluator
# or, from source:
pip install -e integrations/rampart/
```

You also need the rule corpus on disk:

```bash
git clone https://github.com/Agent-Threat-Rule/agent-threat-rules.git
# rules live under agent-threat-rules/rules/<category>/
```

## Use

```python
import pytest
from rampart.assertions import assert_does_not_match
from atr_rules_evaluator import ATRRulesEvaluator

ATR_EVAL = ATRRulesEvaluator(
    rules_dir="agent-threat-rules/rules",
    categories=["prompt-injection", "tool-poisoning"],
    min_severity="high",
)


@pytest.mark.parametrize("attack", LOAD_ATTACK_CORPUS())
async def test_agent_resists_atr_violations(agent, attack):
    """ATR rules should not fire on the agent's response to attack input."""
    result = await agent.run(attack)
    assert_does_not_match(result, evaluator=ATR_EVAL)
```

## Behavior

- Loads every `.yaml` rule under `rules_dir` (recursive).
- For each rule, compiles the first `regex`-operator condition into a `re.Pattern`. Rules whose conditions use other operators (e.g., `ml_classifier`, `ast`) are skipped at load time (or raise in `strict=True` mode).
- At evaluation time, walks all loaded rules and matches each against the appropriate field of the current `EvalContext`:
  - `field: response | llm_output | model_output | output` → matched against `context.text` (current turn's response)
  - `field: user_input | prompt | input` → matched against the latest user request
  - `field: tool_call | tool_invocation | tool_args` → matched against a concatenated rendering of `context.all_tool_calls`
- Returns `EvalOutcome.DETECTED` if any rule matches, with evidence listing every matched `rule_id`, severity, category, and target field.

## What's in scope

- ATR rules with regex conditions across the three RAMPART-accessible fields above
- Category and severity allowlists for trimming the active rule set
- Soft-skip vs strict load modes
- Aggregated evidence so a single test failure surfaces every fired rule

## What's not (yet)

- ATR rules with `ml_classifier`, `ast`, or `bytecode` operators — those need a different evaluator backend
- Multi-condition compound rules using `condition: all` semantics across heterogeneous fields
- Cross-turn temporal patterns (e.g., "first turn says X then second turn says Y")

These are listed for transparency, not as blockers. v1 of the adapter is the regex-corpus path because that's where the existing ATR production usage is concentrated.

## Tests

```bash
cd integrations/rampart
python -m pytest tests/ -v
```

13 tests cover loading edge cases (category filter, severity gate, strict vs lenient, XOR args, malformed YAML) and evaluation edge cases (response match, user_input match, tool_call match, no-match, multi-match aggregation, empty context).

## Provenance

- ATR rules are MIT licensed (`agent-threat-rules/LICENSE`)
- ATR DOI: [10.5281/zenodo.19178002](https://doi.org/10.5281/zenodo.19178002)
- ATR fiscal sponsor: Open Source Collective Inc. (501(c)(3), EIN 81-1567737)
- Maintainer: Adam Lin, adam@agentthreatrule.org
