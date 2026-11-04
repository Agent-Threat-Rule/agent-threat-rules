"""Tests for the ATR guard capability for Pydantic AI.

Fixture rules match a harmless marker, so the block path is exercised without
any attack string in this repository's integration code.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pydantic_ai_atr  # noqa: E402
from pydantic_ai_atr import ATRGuard, ModelRetry  # noqa: E402

MARKER = "atr-fixture-marker"

# id suffix -> (field, maturity, severity)
FIXTURES = {
    "00001": ("tool_args", "stable", "critical"),
    "00002": ("tool_args", "experimental", "critical"),
    "00003": ("tool_response", "stable", "critical"),
    "00004": ("tool_response", "test", "critical"),
    "00005": ("tool_args", "stable", "medium"),
    "00006": ("tool_name", "stable", "critical"),
}


@pytest.fixture(scope="module")
def rules_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("pyd-rules")
    for suffix, (field, maturity, severity) in FIXTURES.items():
        rule = {
            "id": f"ATR-2099-{suffix}",
            "title": f"fixture {suffix}",
            "severity": severity,
            "status": "experimental",
            "maturity": maturity,
            "detection": {
                "condition": "any",
                "conditions": [{"field": field, "operator": "contains", "value": f"{MARKER}-{suffix}"}],
            },
        }
        (directory / f"ATR-2099-{suffix}.yaml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    return directory


def _payload(*suffixes: str) -> dict:
    return {"query": " ".join(f"{MARKER}-{s}" for s in suffixes)}


def test_default_blocks_stable_critical_tool_args(rules_dir: Path) -> None:
    guard = ATRGuard(rules_dir=rules_dir)
    match = guard.check_tool_call("search", _payload("00001"))
    assert match is not None and match.rule_id == "ATR-2099-00001"


def test_default_records_but_does_not_block_non_stable_critical(rules_dir: Path) -> None:
    guard = ATRGuard(rules_dir=rules_dir)
    assert guard.check_tool_call("search", _payload("00002")) is None
    assert [(e["rule"], e["maturity"], e["blocks"]) for e in guard.audit_log] == [
        ("ATR-2099-00002", "experimental", False)
    ]


def test_hunt_lane_blocks_every_rule(rules_dir: Path) -> None:
    guard = ATRGuard(rules_dir=rules_dir, block_lane="hunt")
    match = guard.check_tool_call("search", _payload("00002"))
    assert match is not None and match.rule_id == "ATR-2099-00002"


def test_severity_floor_still_applies(rules_dir: Path) -> None:
    assert ATRGuard(rules_dir=rules_dir).check_tool_call("search", _payload("00005")) is None
    match = ATRGuard(rules_dir=rules_dir, block_severity="medium").check_tool_call("search", _payload("00005"))
    assert match is not None and match.rule_id == "ATR-2099-00005"


def test_tool_result_is_a_tool_response_event(rules_dir: Path) -> None:
    guard = ATRGuard(rules_dir=rules_dir)
    match = guard.check_tool_result("fetch", f"page text {MARKER}-00003")
    assert match is not None and match.rule_id == "ATR-2099-00003"
    # a tool_args rule does not fire on a result, and vice versa
    assert guard.check_tool_result("fetch", f"{MARKER}-00001") is None
    assert guard.check_tool_call("fetch", {"q": f"{MARKER}-00003"}) is None


def test_tool_name_field_is_scanned(rules_dir: Path) -> None:
    guard = ATRGuard(rules_dir=rules_dir)
    match = guard.check_tool_call(f"{MARKER}-00006", {"q": "hello"})
    assert match is not None and match.rule_id == "ATR-2099-00006"
    assert guard.check_tool_result(f"{MARKER}-00006", "hello") is None


def test_result_entries_carry_maturity_blocks_and_truncated(rules_dir: Path) -> None:
    flagged: list[dict] = []
    guard = ATRGuard(rules_dir=rules_dir, on_flag=flagged.append)
    guard.check_tool_result("fetch", f"{MARKER}-00003 {MARKER}-00004")
    by_rule = {e["rule"]: e for e in guard.audit_log}
    assert flagged == guard.audit_log
    assert (by_rule["ATR-2099-00003"]["maturity"], by_rule["ATR-2099-00003"]["blocks"]) == ("stable", True)
    assert (by_rule["ATR-2099-00004"]["maturity"], by_rule["ATR-2099-00004"]["blocks"]) == ("test", False)
    assert all(e["where"] == "tool_result" and e["truncated"] is False for e in guard.audit_log)


def test_fallback_for_old_pyatr_blocks_only_in_hunt(rules_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pydantic_ai_atr, "lane_allows", pydantic_ai_atr._lane_allows_without_maturity)
    assert ATRGuard(rules_dir=rules_dir).check_tool_call("search", _payload("00001")) is None
    assert ATRGuard(rules_dir=rules_dir, block_lane="hunt").check_tool_call("search", _payload("00001")) is not None


def test_alert_lane_includes_test_maturity(rules_dir: Path) -> None:
    assert ATRGuard(rules_dir=rules_dir).check_tool_result("fetch", f"{MARKER}-00004") is None
    match = ATRGuard(rules_dir=rules_dir, block_lane="alert").check_tool_result("fetch", f"{MARKER}-00004")
    assert match is not None and match.rule_id == "ATR-2099-00004"


def test_long_value_is_clipped_and_reported(rules_dir: Path) -> None:
    guard = ATRGuard(rules_dir=rules_dir, max_scan_chars=100)
    tail = f"{'x' * 500} {MARKER}-00003"
    assert guard.check_tool_result("fetch", tail) is not None
    assert guard.audit_log[-1]["truncated"] is True
    middle = f"{'x' * 300} {MARKER}-00003 {'x' * 300}"
    assert ATRGuard(rules_dir=rules_dir, max_scan_chars=100).check_tool_result("fetch", middle) is None


@pytest.mark.parametrize(
    "kwargs",
    [{"block_lane": "enfroce"}, {"block_severity": "info"}, {"max_scan_chars": 1}],
)
def test_invalid_options_are_rejected(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        ATRGuard(**kwargs)


def test_empty_rules_dir_fails_loudly(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="0 rules"):
        ATRGuard(rules_dir=tmp_path).check_tool_call("search", {"q": "hello"})


def test_bundled_rules_load_and_benign_call_passes() -> None:
    guard = ATRGuard()
    assert guard.check_tool_call("get_weather", {"city": "Paris"}) is None
    assert len(guard.engine.rules) > 0


@pytest.mark.asyncio
async def test_hooks_raise_model_retry(rules_dir: Path) -> None:
    class Call:
        tool_name = "search"

    guard = ATRGuard(rules_dir=rules_dir, block_on_result=True)
    with pytest.raises(ModelRetry, match="ATR-2099-00001"):
        await guard.before_tool_execute(None, call=Call(), tool_def=None, args=_payload("00001"))
    args = _payload("00002")
    assert await guard.before_tool_execute(None, call=Call(), tool_def=None, args=args) is args
    with pytest.raises(ModelRetry, match="ATR-2099-00003"):
        await guard.after_tool_execute(None, call=Call(), tool_def=None, args={}, result=f"{MARKER}-00003")
    # a non-stable match in a result is recorded but not rejected, even with block_on_result
    result = f"{MARKER}-00004"
    assert await guard.after_tool_execute(None, call=Call(), tool_def=None, args={}, result=result) is result


@pytest.mark.parametrize(("suffix", "runs"), [("00001", False), ("00002", True)])
def test_agent_run_blocks_tool_before_it_executes(rules_dir: Path, suffix: str, runs: bool) -> None:
    """End to end with a real pydantic-ai Agent: a stable match stops the tool, a hunt-only match does not."""
    pytest.importorskip("pydantic_ai")
    from pydantic_ai import Agent
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
    from pydantic_ai.models.function import AgentInfo, FunctionModel

    def model(messages: list, info: AgentInfo) -> ModelResponse:
        returned = [p for m in messages for p in getattr(m, "parts", []) if p.part_kind == "retry-prompt"]
        returned += [p for m in messages for p in getattr(m, "parts", []) if isinstance(p, ToolReturnPart)]
        if returned:
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(parts=[ToolCallPart("search", {"query": f"{MARKER}-{suffix}"})])

    ran: list[str] = []
    agent = Agent(FunctionModel(model), capabilities=[ATRGuard(rules_dir=rules_dir)])

    @agent.tool_plain
    def search(query: str) -> str:
        ran.append(query)
        return "results"

    result = agent.run_sync("look something up")
    assert ran == ([f"{MARKER}-{suffix}"] if runs else [])
    assert result.output == "done"
