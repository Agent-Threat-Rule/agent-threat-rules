"""What may drive a block, for every Python surface that can block.

Blocking is off by default everywhere ATR ships. Once a user turns it on, a
match may block (exit non-zero, abort a run, refuse a tool call) only when its
rule is in the enforce lane -- ``maturity: stable``, as ``lane_allows`` decides,
which also refuses an unconfirmed ``confirm: embedding`` rule -- and its
severity is high or critical. Every other match is reported and never blocks.

This mirrors ``isBlockingEligible`` in src/enforcement.ts. The detection lane a
caller scans in decides what is reported; it does not widen what may block.
A pyatr match carries no status (the engine skips draft and deprecated rules
before matching) and no model decision (pyatr has no model layer), so the lane
and the severity are the whole rule here.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from pyatr.engine import lane_allows
from pyatr.types import ATRMatch

#: The lane whose rules may drive a block. Not configurable.
BLOCKING_LANE = "enforce"

#: Severities that may drive a block, most severe first.
BLOCKING_SEVERITIES: tuple[str, ...] = ("critical", "high")

#: The lowest severity that may drive a block, and the default threshold.
BLOCKING_MIN_SEVERITY = "high"


def parse_blocking_severity(value: str) -> str | None:
    """Return ``"high"`` or ``"critical"`` for a value a person typed, else None.

    ``medium``, ``low`` and typos return None so the caller reports them; a
    threshold below high is never mapped to a default.
    """
    normalized = str(value).strip().lower()
    return normalized if normalized in BLOCKING_SEVERITIES else None


def blocking_severities_from(threshold: str) -> tuple[str, ...]:
    """The severities at or above ``threshold``, which must be high or critical.

    Raises ValueError naming the value otherwise.
    """
    parsed = parse_blocking_severity(threshold)
    if parsed is None:
        raise ValueError(
            f"blocking severity must be one of {BLOCKING_SEVERITIES}, got {threshold!r}: "
            "only high and critical matches from stable rules may block"
        )
    return ("critical",) if parsed == "critical" else BLOCKING_SEVERITIES


def is_blocking_eligible(match: ATRMatch, severities: Sequence[str] = BLOCKING_SEVERITIES) -> bool:
    """May this match drive a block? Enforce lane and high/critical severity.

    ``severities`` can narrow the set (``("critical",)``); a value outside
    BLOCKING_SEVERITIES is ignored rather than honoured, so it cannot widen it.
    """
    severity = str(match.severity).lower()
    if severity not in BLOCKING_SEVERITIES or severity not in severities:
        return False
    return lane_allows(match, BLOCKING_LANE)


def blocking_matches(matches: Iterable[ATRMatch], severities: Sequence[str] = BLOCKING_SEVERITIES) -> list[ATRMatch]:
    """The matches that may drive a block, in their original order."""
    return [m for m in matches if is_blocking_eligible(m, severities)]
