"""Tests for the OpenAI Agents SDK integration.

Attack payloads come from the ATR rules' own ``test_cases`` fixtures, so this
file carries no attack string of its own. The scan-logic tests need only pyatr;
the guardrail tests additionally need ``openai-agents`` and are skipped without it.

    pip install pyatr openai-agents pytest
    pytest integrations/openai-agents/tests
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
RULES_DIR = REPO_ROOT / "rules"
sys.path.insert(0, str(HERE.parent))

from openai_agents_atr import ATRDecision, ATRGuard, _HAS_AGENTS_SDK, _input_text  # noqa: E402

needs_sdk = pytest.mark.skipif(not _HAS_AGENTS_SDK, reason="openai-agents not installed")


# ---------------------------------------------------------------------------
# Fixtures drawn from the rule corpus
# ---------------------------------------------------------------------------


def _load_cases() -> tuple[list[tuple], list[tuple]]:
    """Collect tool-traffic test cases: (rule_id, severity, kind, name, payload)."""
    positives: list[tuple] = []
    negatives: list[tuple] = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(rule, dict) or rule.get("status") in ("draft", "deprecated"):
            continue
        cases = rule.get("test_cases") or {}
        for bucket, out in (("true_positives", positives), ("true_negatives", negatives)):
            for case in cases.get(bucket) or []:
                if not isinstance(case, dict):
                    continue
                if "tool_args" in case:
                    out.append((rule["id"], rule["severity"], "call", case.get("tool_name", "tool"), case["tool_args"]))
                elif isinstance(case.get("tool_call"), dict):
                    call = case["tool_call"]
                    out.append((rule["id"], rule["severity"], "call", call.get("name", "tool"), call.get("args", "")))
                elif "tool_response" in case:
                    out.append((rule["id"], rule["severity"], "result", "fetch", case["tool_response"]))
    return positives, negatives


POSITIVES, NEGATIVES = _load_cases()


@pytest.fixture(scope="module")
def guard() -> ATRGuard:
    return ATRGuard(rules_dir=RULES_DIR, block_severity="low")


def _check(guard: ATRGuard, kind: str, name: str, payload: Any) -> ATRDecision:
    if kind == "call":
        return guard.check_tool_call(name, payload)
    return guard.check_tool_output(name, payload)


def _first(kind: str) -> tuple:
    return next(case for case in POSITIVES if case[2] == kind)


# ---------------------------------------------------------------------------
# Scan logic (pyatr only)
# ---------------------------------------------------------------------------


def test_corpus_has_tool_fixtures() -> None:
    assert sum(c[2] == "call" for c in POSITIVES) >= 50
    assert sum(c[2] == "result" for c in POSITIVES) >= 50


@pytest.mark.parametrize("rule_id,severity,kind,name,payload", POSITIVES, ids=[f"{c[0]}-{c[2]}" for c in POSITIVES])
def test_rule_fixture_fires_through_adapter(guard, rule_id, severity, kind, name, payload) -> None:
    decision = _check(guard, kind, name, payload)
    assert rule_id in [m.rule_id for m in decision.matches]


@pytest.mark.parametrize("rule_id,severity,kind,name,payload", NEGATIVES, ids=[f"{c[0]}-{c[2]}" for c in NEGATIVES])
def test_rule_negative_does_not_fire_its_rule(guard, rule_id, severity, kind, name, payload) -> None:
    decision = _check(guard, kind, name, payload)
    assert rule_id not in [m.rule_id for m in decision.matches]


def test_benign_tool_traffic_is_clean(guard) -> None:
    assert not guard.check_tool_call("get_weather", '{"city": "Paris"}').matches
    assert not guard.check_tool_output("get_weather", {"temp_c": 18, "sky": "clear"}).matches
    assert not guard.check_input("What's the weather in Paris tomorrow?").matches


def test_empty_values_are_not_scanned(guard) -> None:
    assert guard.check_tool_output("noop", None).matches == ()
    assert guard.check_input("   ").matches == ()


def test_block_severity_threshold() -> None:
    rule_id, severity, kind, name, payload = next(c for c in POSITIVES if c[1] != "critical")
    engine = ATRGuard(rules_dir=RULES_DIR).engine
    strict = _check(ATRGuard(engine=engine, block_severity="critical"), kind, name, payload)
    loose = _check(ATRGuard(engine=engine, block_severity=severity), kind, name, payload)
    assert rule_id in [m.rule_id for m in strict.matches]
    assert strict.blocking is None or strict.blocking.severity == "critical"
    assert loose.blocked


def test_findings_are_recorded_and_reported() -> None:
    seen: list[dict] = []
    g = ATRGuard(rules_dir=RULES_DIR, on_flag=seen.append)
    rule_id, _, kind, name, payload = _first("call")
    decision = _check(g, kind, name, payload)
    assert seen and seen == g.audit_log
    assert {"where", "tool", "rule", "title", "severity"} <= set(seen[0])
    info = decision.info()
    assert rule_id in info["rules"] and info["where"] == "tool_args"
    json.dumps(info)  # output_info must be serializable for tracing


def test_input_text_extraction() -> None:
    assert _input_text("hello") == "hello"
    items = [
        {"role": "user", "content": "first"},
        {"role": "user", "content": [{"type": "input_text", "text": "second"}]},
        {"type": "function_call_output", "call_id": "c1", "output": "third"},
    ]
    assert _input_text(items).split("\n") == ["first", "second", "third"]


def test_long_values_are_clipped_to_head_and_tail(guard) -> None:
    rule_id, _, _, name, payload = _first("result")
    padding = "lorem ipsum dolor sit amet " * 2000  # ~54k characters of benign text
    g = ATRGuard(engine=guard.engine, max_scan_chars=8_000)
    for text in (payload + padding, padding + payload):  # payload at the head, then the tail
        decision = g.check_tool_output(name, text)
        assert decision.truncated and decision.info()["truncated"] is True
        assert rule_id in [m.rule_id for m in decision.matches]
    middle = g.check_tool_output(name, padding + payload + padding)
    assert middle.truncated and rule_id not in [m.rule_id for m in middle.matches]
    full = ATRGuard(engine=guard.engine, max_scan_chars=None).check_tool_output(name, payload)
    assert not full.truncated


def test_rejects_bad_options() -> None:
    with pytest.raises(ValueError):
        ATRGuard(block_severity="severe")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ATRGuard(on_block="drop")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ATRGuard(max_scan_chars=1)


def test_zero_rules_is_an_error(tmp_path) -> None:
    with pytest.raises(RuntimeError):
        ATRGuard(rules_dir=tmp_path).engine


# ---------------------------------------------------------------------------
# SDK guardrails
# ---------------------------------------------------------------------------


def _tool_data(name: str, arguments: str, output: Any = None):
    from agents import Agent
    from agents.tool_context import ToolContext
    from agents.tool_guardrails import ToolInputGuardrailData, ToolOutputGuardrailData

    ctx = ToolContext(context=None, tool_name=name, tool_call_id="call_1", tool_arguments=arguments)
    agent = Agent(name="test")
    if output is None:
        return ToolInputGuardrailData(context=ctx, agent=agent)
    return ToolOutputGuardrailData(context=ctx, agent=agent, output=output)


@needs_sdk
def test_tool_input_guardrail_rejects_without_echoing_payload() -> None:
    rule_id, severity, _, name, payload = _first("call")
    g = ATRGuard(rules_dir=RULES_DIR, block_severity=severity)
    result = asyncio.run(g.tool_input_guardrail.guardrail_function(_tool_data(name, payload)))
    assert result.behavior["type"] == "reject_content"
    assert rule_id in result.output_info["rules"]
    # The message names the most severe blocking rule, which may be another rule
    # that also fires on this fixture.
    assert result.output_info["blocking_rule"] in result.behavior["message"]
    assert payload not in result.behavior["message"]


@needs_sdk
def test_tool_input_guardrail_can_halt_the_run() -> None:
    _, severity, _, name, payload = _first("call")
    g = ATRGuard(rules_dir=RULES_DIR, block_severity=severity, on_block="raise")
    result = asyncio.run(g.tool_input_guardrail.guardrail_function(_tool_data(name, payload)))
    assert result.behavior["type"] == "raise_exception"


@needs_sdk
def test_tool_output_guardrail_records_by_default_and_blocks_when_asked() -> None:
    rule_id, severity, _, name, payload = _first("result")
    data = _tool_data(name, "{}", output=payload)
    record = ATRGuard(rules_dir=RULES_DIR, block_severity=severity)
    allowed = asyncio.run(record.tool_output_guardrail.guardrail_function(data))
    assert allowed.behavior["type"] == "allow"
    assert rule_id in allowed.output_info["rules"]
    block = ATRGuard(rules_dir=RULES_DIR, block_severity=severity, block_on_result=True)
    assert asyncio.run(block.tool_output_guardrail.guardrail_function(data)).behavior["type"] == "reject_content"


@needs_sdk
def test_agent_guardrails_trip_and_pass() -> None:
    from agents import Agent

    _, severity, _, _, payload = _first("result")
    g = ATRGuard(rules_dir=RULES_DIR, block_severity=severity)
    agent = Agent(name="test")
    assert asyncio.run(g.input_guardrail.guardrail_function(None, agent, "Plan a trip to Lisbon")).tripwire_triggered is False
    tripped = asyncio.run(g.output_guardrail.guardrail_function(None, agent, payload))
    assert tripped.tripwire_triggered is (tripped.output_info["blocking_rule"] is not None)


@needs_sdk
def test_input_guardrail_runs_before_the_model() -> None:
    guardrail = ATRGuard(rules_dir=RULES_DIR).input_guardrail
    assert getattr(guardrail, "run_in_parallel", False) is False


@needs_sdk
def test_protect_is_idempotent_and_keeps_existing_guardrails() -> None:
    from agents import function_tool, tool_input_guardrail, ToolGuardrailFunctionOutput

    @tool_input_guardrail
    def house_rule(data):
        return ToolGuardrailFunctionOutput.allow()

    @function_tool
    def get_weather(city: str) -> str:
        """Weather for a city."""
        return "clear"

    get_weather.tool_input_guardrails = [house_rule]
    g = ATRGuard(rules_dir=RULES_DIR)
    g.protect(get_weather)
    g.protect([get_weather])
    assert [x.name for x in get_weather.tool_input_guardrails] == ["house_rule", "atr_tool_input"]
    assert [x.name for x in get_weather.tool_output_guardrails] == ["atr_tool_output"]


@needs_sdk
def test_end_to_end_runner_blocks_tool_call() -> None:
    """Drive a real Runner with a scripted model: the guarded tool must not run."""
    from agents import Agent, Runner, function_tool
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage
    from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

    probe = ATRGuard(rules_dir=RULES_DIR, block_severity="low")
    # The model sends the payload as JSON arguments to `run_command`; use a
    # fixture that still fires in that shape.
    rule_id, severity, payload = next(
        (rid, sev, p)
        for rid, sev, kind, _, p in POSITIVES
        if kind == "call"
        and rid in [m.rule_id for m in probe.check_tool_call("run_command", json.dumps({"command": p})).matches]
    )
    ran: list[str] = []

    @function_tool
    def run_command(command: str) -> str:
        """Run a command."""
        ran.append(command)
        return "ran"

    class ScriptedModel(Model):
        def __init__(self) -> None:
            self.turn = 0

        async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
            self.turn += 1
            if self.turn == 1:
                item = ResponseFunctionToolCall(
                    id="fc_1", call_id="call_1", name="run_command", type="function_call",
                    arguments=json.dumps({"command": payload}), status="completed",
                )
            else:
                item = ResponseOutputMessage(
                    id="msg_1", role="assistant", status="completed", type="message",
                    content=[ResponseOutputText(type="output_text", text="done", annotations=[])],
                )
            return ModelResponse(output=[item], usage=Usage(), response_id=None)

        def stream_response(self, *args: Any, **kwargs: Any):  # pragma: no cover - not used
            raise NotImplementedError

    g = ATRGuard(rules_dir=RULES_DIR, block_severity=severity)
    agent = Agent(name="test", model=ScriptedModel(), tools=g.protect(run_command))
    result = asyncio.run(Runner.run(agent, "go"))
    assert ran == [], "a blocked tool call must not execute"
    assert result.final_output == "done"
    assert any(e["rule"] == rule_id and e["where"] == "tool_args" for e in g.audit_log)
