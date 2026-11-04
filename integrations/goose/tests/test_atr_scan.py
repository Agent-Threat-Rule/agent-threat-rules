"""Tests for the goose PreToolUse hook (scripts/atr_scan.py).

The hook is advisory by default (exit 0, matches reported on stderr). With
ATR_BLOCKING=1 it exits 2 only for a match from a maturity: stable rule at
high or critical severity. Matches are built directly, so these cases do not
depend on which bundled rules a given pyatr ships.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import atr_scan  # noqa: E402
from pyatr import lane_allows  # noqa: E402
from pyatr.types import ATRMatch  # noqa: E402


def _match(maturity: str, severity: str, rule_id: str = "ATR-2099-00001") -> ATRMatch:
    return ATRMatch(
        rule_id=rule_id,
        title="fixture",
        severity=severity,
        confidence="high",
        matched_patterns=("fixture",),
        maturity=maturity,
    )


@pytest.mark.parametrize(
    ("env", "expected"),
    [({}, False), ({"ATR_BLOCKING": ""}, False), ({"ATR_BLOCKING": "1"}, True), ({"ATR_BLOCKING": " ON "}, True),
     ({"ATR_BLOCKING": "0"}, False), ({"ATR_BLOCKING": "enabled"}, False)],
)
def test_blocking_is_off_unless_atr_blocking_says_on(env: dict, expected: bool, capsys) -> None:
    assert atr_scan.blocking_enabled(env) is expected
    if env.get("ATR_BLOCKING") == "enabled":
        assert "NOT enabled" in capsys.readouterr().err


def test_default_never_denies_even_a_stable_critical(capsys) -> None:
    assert atr_scan.decide("bash", [_match("stable", "critical")], lane_allows, blocking=False) == 0
    assert "reported" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("maturity", "severity", "code"),
    [("stable", "critical", 2), ("stable", "high", 2), ("stable", "medium", 0),
     ("test", "critical", 0), ("experimental", "critical", 0), ("deprecated", "critical", 0)],
)
def test_blocking_denies_only_enforce_lane_high_and_critical(maturity: str, severity: str, code: int) -> None:
    assert atr_scan.decide("bash", [_match(maturity, severity)], lane_allows, blocking=True) == code


def test_old_pyatr_without_maturity_never_denies() -> None:
    assert atr_scan.decide("bash", [_match("stable", "critical")], atr_scan._lane_allows_without_maturity, blocking=True) == 0


def test_hook_process_exits_0_by_default() -> None:
    """The real script, end to end: no ATR_BLOCKING, so it never exits 2."""
    env = {k: v for k, v in os.environ.items() if k != "ATR_BLOCKING"}
    payload = json.dumps({"tool_name": "bash", "tool_input": {"command": "echo hello"}})
    r = subprocess.run([sys.executable, str(SCRIPTS / "atr_scan.py")], input=payload, capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == 0
