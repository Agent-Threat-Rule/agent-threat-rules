"""Blocking eligibility in pyatr, and the `pyatr scan` exit code.

Blocking is opt-in: `pyatr scan` exits 0 whatever it finds unless --fail-on is
given, and then only a match from a maturity: stable rule (the enforce lane)
at or above the threshold -- high or critical -- makes it exit 2. Fixture
rules match harmless markers so these cases do not move with the rule set.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from pyatr import ATREngine, AgentEvent
from pyatr.cli import main
from pyatr.enforcement import (
    BLOCKING_SEVERITIES,
    blocking_matches,
    blocking_severities_from,
    is_blocking_eligible,
    parse_blocking_severity,
)

MARKER = "pyatr-blocking-fixture"

# id suffix -> (maturity, severity, extra fields)
FIXTURES = {
    "00001": ("stable", "critical", {}),
    "00002": ("stable", "high", {}),
    "00003": ("stable", "medium", {}),
    "00004": ("test", "critical", {}),
    "00005": ("experimental", "critical", {}),
    "00006": ("stable", "critical", {"confirm": "embedding", "detection_method": "pattern"}),
}


@pytest.fixture(scope="module")
def rules_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("blocking-rules")
    for suffix, (maturity, severity, extra) in FIXTURES.items():
        rule = {
            "id": f"ATR-2099-9{suffix}",
            "title": f"blocking fixture {suffix}",
            "severity": severity,
            "status": "experimental",
            "maturity": maturity,
            "detection": {
                "condition": "any",
                "conditions": [{"field": "user_input", "operator": "contains", "value": f"{MARKER}-{suffix}"}],
            },
        }
        if "confirm" in extra:
            rule["confirm"] = extra["confirm"]
        (directory / f"ATR-2099-9{suffix}.yaml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    return directory


def _matches(rules_dir: Path, suffix: str):
    engine = ATREngine()
    engine.load_rules_from_directory(rules_dir)
    text = f"{MARKER}-{suffix}"
    return engine.evaluate(AgentEvent(content=text, event_type="llm_input", fields={"user_input": text}))


def test_only_stable_high_and_critical_are_eligible(rules_dir: Path) -> None:
    expected = {"00001": True, "00002": True, "00003": False, "00004": False, "00005": False, "00006": False}
    for suffix, eligible in expected.items():
        matches = _matches(rules_dir, suffix)
        assert len(matches) == 1, suffix  # CONTROL: the fixture fired in the hunt lane
        assert is_blocking_eligible(matches[0]) is eligible, suffix


def test_threshold_narrows_to_critical_and_never_widens(rules_dir: Path) -> None:
    high = _matches(rules_dir, "00002")[0]
    assert blocking_matches([high], blocking_severities_from("critical")) == []
    assert blocking_matches([high], blocking_severities_from("high")) == [high]
    medium = _matches(rules_dir, "00003")[0]
    assert not is_blocking_eligible(medium, ("critical", "high", "medium"))
    assert BLOCKING_SEVERITIES == ("critical", "high")
    assert parse_blocking_severity(" HIGH ") == "high"
    for bad in ("medium", "low", "bogus", ""):
        assert parse_blocking_severity(bad) is None
        with pytest.raises(ValueError, match="blocking severity"):
            blocking_severities_from(bad)


def _events_file(tmp_path: Path, suffix: str) -> str:
    path = tmp_path / "events.json"
    path.write_text(json.dumps([{"content": f"{MARKER}-{suffix}", "event_type": "llm_input"}]), encoding="utf-8")
    return str(path)


def test_scan_exits_0_by_default_even_on_a_stable_critical(rules_dir: Path, tmp_path: Path, capsys) -> None:
    rc = main(["scan", _events_file(tmp_path, "00001"), "--rules-dir", str(rules_dir)])
    assert rc == 0
    assert "ATR-2099-900001" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("suffix", "fail_on", "expected"),
    [
        ("00001", "high", 2),
        ("00002", "high", 2),
        ("00002", "critical", 0),
        ("00003", "high", 0),
        ("00004", "high", 0),
        ("00005", "critical", 0),
        ("00006", "high", 0),
    ],
)
def test_fail_on_counts_enforce_lane_matches_only(rules_dir: Path, tmp_path: Path, suffix: str, fail_on: str, expected: int) -> None:
    rc = main(["scan", _events_file(tmp_path, suffix), "--rules-dir", str(rules_dir), "--fail-on", fail_on])
    assert rc == expected


def test_fail_on_rejects_a_threshold_below_high(rules_dir: Path, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", _events_file(tmp_path, "00003"), "--rules-dir", str(rules_dir), "--fail-on", "medium"])
    assert exc.value.code == 2  # argparse usage error, not a wider gate
