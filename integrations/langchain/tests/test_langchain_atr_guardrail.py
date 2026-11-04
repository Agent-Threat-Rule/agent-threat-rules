"""Tests for the LangChain ATR guardrail middleware.

Advisory by default: every match is recorded, nothing is halted or refused.
With blocking=True only a match from a maturity: stable rule at or above
block_severity (high or critical) halts. `scan` is replaced with a stub that
returns hand-built matches, so these cases do not depend on the bundled rules.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import langchain_atr_guardrail as guardrail  # noqa: E402
from langchain_atr_guardrail import ATRGuardrailMiddleware  # noqa: E402
from pyatr.types import ATRMatch  # noqa: E402


class _Msg:
    def __init__(self, content: str) -> None:
        self.content = content


def _match(maturity: str, severity: str) -> ATRMatch:
    return ATRMatch(
        rule_id=f"ATR-2099-{maturity}-{severity}",
        title="fixture",
        severity=severity,
        confidence="high",
        matched_patterns=("fixture",),
        maturity=maturity,
    )


@pytest.fixture
def stub_scan(monkeypatch: pytest.MonkeyPatch):
    def use(*matches: ATRMatch) -> None:
        monkeypatch.setattr(guardrail, "scan", lambda text: list(matches))

    return use


def _after_model(mw: ATRGuardrailMiddleware):
    return mw.after_model({"messages": [_Msg("model output")]})


def test_default_records_and_never_halts(stub_scan) -> None:
    stub_scan(_match("stable", "critical"))
    mw = ATRGuardrailMiddleware()
    assert mw.blocking is False
    assert _after_model(mw) is None
    assert [(e["rule"], e["blocks"]) for e in mw.audit_log] == [("ATR-2099-stable-critical", False)]


@pytest.mark.parametrize(
    ("maturity", "severity", "halts"),
    [("stable", "critical", True), ("stable", "high", True), ("stable", "medium", False),
     ("test", "critical", False), ("experimental", "critical", False)],
)
def test_blocking_halts_only_on_enforce_lane_high_and_critical(stub_scan, maturity: str, severity: str, halts: bool) -> None:
    stub_scan(_match(maturity, severity))
    mw = ATRGuardrailMiddleware(blocking=True)
    assert (_after_model(mw) == {"jump_to": "end"}) is halts
    assert len(mw.audit_log) == 1  # every match is recorded either way


def test_block_severity_critical_narrows_and_lower_floors_are_rejected(stub_scan) -> None:
    stub_scan(_match("stable", "high"))
    assert _after_model(ATRGuardrailMiddleware(blocking=True, block_severity="critical")) is None
    for floor in ("medium", "low", "info"):
        with pytest.raises(ValueError, match="block_severity"):
            ATRGuardrailMiddleware(blocking=True, block_severity=floor)
    with pytest.raises(TypeError, match="blocking"):
        ATRGuardrailMiddleware(blocking="false")  # type: ignore[arg-type]


def test_tool_call_runs_by_default_and_only_eligible_matches_refuse_it(stub_scan) -> None:
    class Request:
        tool_call = {"name": "search", "args": {"q": "x"}, "id": "1"}

    ran: list[str] = []

    def handler(request):
        ran.append("ran")
        return _Msg("result")

    stub_scan(_match("stable", "critical"))
    ATRGuardrailMiddleware().wrap_tool_call(Request(), handler)
    assert ran == ["ran"]

    stub_scan(_match("test", "critical"))
    ATRGuardrailMiddleware(blocking=True).wrap_tool_call(Request(), handler)
    assert ran == ["ran", "ran"]
