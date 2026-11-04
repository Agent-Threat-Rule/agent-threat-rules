"""Tests for maturity lanes in the pyATR engine (parity with the TypeScript engine)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from pyatr.engine import ATREngine
from pyatr.types import AgentEvent

RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"

MARKER = "lane-marker-token"

# (rule id suffix, maturity, confirm) -> lanes in which the rule may fire
CASES = [
    ("00001", "stable", None, {"enforce", "alert", "hunt"}),
    ("00002", "test", None, {"alert", "hunt"}),
    ("00003", "experimental", None, {"hunt"}),
    ("00004", "draft", None, {"hunt"}),
    ("00005", None, None, {"hunt"}),
    ("00006", "needs-human-poc", None, {"hunt"}),
    ("00007", "deprecated", None, set()),
    ("00008", "stable", "embedding", {"hunt"}),
]


@pytest.fixture(scope="module")
def rules_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("lane-rules")
    for suffix, maturity, confirm, _lanes in CASES:
        data: dict = {
            "id": f"ATR-2099-{suffix}",
            "title": f"lane fixture {suffix}",
            "severity": "critical",
            "status": "experimental",
            "detection": {
                "condition": "any",
                "conditions": [{"field": "content", "operator": "contains", "value": MARKER}],
            },
        }
        if maturity is not None:
            data["maturity"] = maturity
        if confirm is not None:
            data["confirm"] = confirm
        (directory / f"ATR-2099-{suffix}.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return directory


def _fired(rules_dir: Path, lane: str) -> set[str]:
    engine = ATREngine(lane=lane)
    engine.load_rules_from_directory(rules_dir)
    event = AgentEvent(content=f"text with {MARKER} inside", event_type="llm_input")
    return {m.rule_id for m in engine.evaluate(event)}


@pytest.mark.parametrize("lane", ["enforce", "alert", "hunt"])
def test_lane_selects_rules_by_maturity(rules_dir: Path, lane: str) -> None:
    expected = {f"ATR-2099-{s}" for s, _m, _c, lanes in CASES if lane in lanes}
    assert _fired(rules_dir, lane) == expected


def test_default_lane_is_hunt(rules_dir: Path) -> None:
    engine = ATREngine()
    assert engine.lane == "hunt"
    engine.load_rules_from_directory(rules_dir)
    event = AgentEvent(content=MARKER, event_type="llm_input")
    assert {m.rule_id for m in engine.evaluate(event)} == _fired(rules_dir, "hunt")


def test_match_carries_normalized_maturity(rules_dir: Path) -> None:
    engine = ATREngine()
    engine.load_rules_from_directory(rules_dir)
    by_id = {m.rule_id: m.maturity for m in engine.evaluate(AgentEvent(content=MARKER))}
    assert by_id["ATR-2099-00001"] == "stable"
    assert by_id["ATR-2099-00005"] == "experimental"  # missing maturity
    assert by_id["ATR-2099-00006"] == "experimental"  # unknown maturity


def test_unknown_lane_is_rejected() -> None:
    with pytest.raises(ValueError, match="lane must be one of"):
        ATREngine(lane="enfroce")


def test_corpus_maturities_parse() -> None:
    engine = ATREngine()
    engine.load_rules_from_directory(RULES_DIR)
    maturities = {r.maturity for r in engine.rules}
    assert "stable" in maturities, "the corpus should contain maturity=stable rules"
    assert maturities <= {"draft", "experimental", "test", "stable", "deprecated"}
