#!/usr/bin/env python3
"""ATR PreToolUse hook -- reports tool calls that match ATR detection rules.

Reads the goose HookContext JSON from stdin and scans the tool_input with
pyatr. Every match is reported on stderr. The hook is ADVISORY BY DEFAULT: it
exits 0 and the tool call runs.

Blocking is opt-in: set ATR_BLOCKING=1 (or true/yes/on) in the environment
goose runs hooks in. Then, and only then, the hook exits 2 (denial) -- and only
for a match that may block: a rule in the enforce lane (``maturity: stable``)
at high or critical severity. Matches of other rules are reported and never
block. This hook used to exit 2 by default on any high or critical match of any
rule, experimental ones included.

Any error in the scanner (import failure, parse error, timeout) allows the call
through -- a broken guard must never block legitimate work. An ATR_BLOCKING
value that is not a recognised spelling is reported on stderr and read as off,
for the same reason.
"""
import json
import os
import sys

BLOCKING_ENV_VAR = "ATR_BLOCKING"
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}

# Mirrors pyatr.enforcement (BLOCKING_LANE / BLOCKING_SEVERITIES). Kept local so
# the hook works with any pyatr that has lane_allows (0.4.1+).
_BLOCKING_LANE = "enforce"
_BLOCKING_SEVERITIES = {"critical", "high"}


def blocking_enabled(env: dict | None = None) -> bool:
    """Read ATR_BLOCKING with the same spellings as the ATR CLI; default off."""
    raw = (env if env is not None else os.environ).get(BLOCKING_ENV_VAR)
    if raw is None or not raw.strip():
        return False
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value not in _FALSE_VALUES:
        print(
            f"[ATR] {BLOCKING_ENV_VAR}={raw!r} is not one of "
            f"{sorted(_TRUE_VALUES)} / {sorted(_FALSE_VALUES)}; blocking is NOT enabled.",
            file=sys.stderr,
        )
    return False


def is_blocking_eligible(match, lane_allows) -> bool:
    """Enforce lane and high/critical severity: the only matches that may block."""
    if str(match.severity).lower() not in _BLOCKING_SEVERITIES:
        return False
    return bool(lane_allows(match, _BLOCKING_LANE))


def _lane_allows_without_maturity(match, lane: str) -> bool:
    """Lane gate for pyatr < 0.4.1, whose matches carry no maturity: none is stable."""
    return lane == "hunt"


def _scan(text: str):
    """Return (matches, lane_allows), or None when pyatr cannot run."""
    try:
        import pyatr

        lane_allows = getattr(pyatr, "lane_allows", _lane_allows_without_maturity)
        return pyatr.scan(text), lane_allows
    except ImportError:
        print(
            "[atr-threat-detection] pyatr not installed; install with: pip install pyatr",
            file=sys.stderr,
        )
    except Exception:
        pass
    return None


def decide(tool_name: str, matches, lane_allows, blocking: bool) -> int:
    """Report every match on stderr; return the exit code (2 = deny, 0 = allow)."""
    eligible = [m for m in matches if is_blocking_eligible(m, lane_allows)] if blocking else []
    for m in matches:
        tag = "blocking" if m in eligible else "reported"
        print(
            f"[ATR] {tag}: tool '{tool_name}' matched [{m.rule_id}] {m.title} "
            f"(severity={m.severity}, maturity={getattr(m, 'maturity', 'unknown')})",
            file=sys.stderr,
        )
    return 2 if eligible else 0


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input")
    if tool_input is None:
        sys.exit(0)

    # Flatten tool_input to a string for ATR scanning.
    text = json.dumps(tool_input) if not isinstance(tool_input, str) else tool_input
    scanned = _scan(text)
    if scanned is None:
        sys.exit(0)
    matches, lane_allows = scanned
    sys.exit(decide(tool_name, matches, lane_allows, blocking_enabled()))


if __name__ == "__main__":
    main()
