"""pyATR - Python reference engine for Agent Threat Rules (ATR)."""

from pathlib import Path

from pyatr.types import AgentEvent, ATRMatch, ATRRule
from pyatr.engine import ATREngine
from pyatr.validator import validate, ValidationResult, ValidationError
from pyatr.test_runner import run_tests, TestRunResult, RuleTestResult, TestCaseResult

try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("pyatr")
except Exception:  # pragma: no cover - source checkout without install
    __version__ = "0.2.7"
__all__ = [
    "ATREngine",
    "AgentEvent",
    "ATRMatch",
    "ATRRule",
    "ValidationError",
    "ValidationResult",
    "RuleTestResult",
    "TestCaseResult",
    "TestRunResult",
    "scan",
    "validate",
    "run_tests",
]

# Source-tree fallback used only when running from a checkout without a
# generated in-package bundle (see ATREngine.load_default_rules).
_DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"


def scan(text: str, *, rules_dir: str | Path | None = None) -> list[ATRMatch]:
    """Convenience function: evaluate text against all ATR rules.

    Loads rules on first call (cached). When ``rules_dir`` is omitted the
    rules bundled inside the installed package are used, so this works after
    a plain ``pip install pyatr`` with no source checkout. Returns a list of
    ATRMatch sorted by severity.
    """
    if not hasattr(scan, "_engine"):
        engine = ATREngine()
        if rules_dir is not None:
            engine.load_rules_from_directory(Path(rules_dir))
        else:
            engine.load_default_rules()
        scan._engine = engine  # type: ignore[attr-defined]
    return scan._engine.evaluate(AgentEvent(content=text, event_type="llm_input", fields={"user_input": text}))  # type: ignore[attr-defined]
