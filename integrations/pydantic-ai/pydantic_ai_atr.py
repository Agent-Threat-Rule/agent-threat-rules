# Runtime threat detection for Pydantic AI (v2+) agents via a Capability.
#
# Scans every tool call against ATR (Agent Threat Rules) -- an open,
# vendor-neutral detection standard for AI agents (MIT; like Sigma, but for
# prompt injection, tool poisoning, MCP attacks and skill compromise). Rules
# ship bundled in the pip package.
#
# Pydantic AI v2 exposes tool-execution lifecycle hooks on a Capability. This
# integration subclasses AbstractCapability (the documented path for reusable,
# distributable capabilities) and uses two hooks:
#   - before_tool_execute: scan the tool name + validated args BEFORE the tool
#                          runs; raise ModelRetry to block a call, which
#                          Pydantic AI surfaces to the model as a failed call.
#   - after_tool_execute:  scan the tool RESULT to catch indirect prompt
#                          injection returned by tools (web pages, files, other
#                          MCP servers). Records by default; blocks when
#                          block_on_result=True.
#
# Each check builds a typed AgentEvent (a `tool_call` event carrying
# `tool_name` and `tool_args`, or a `tool_response` event) so that rules
# written for tool traffic see the field they read. Every rule is evaluated
# and every match is recorded, but only matches whose rule is in
# `block_lane` (default "enforce": maturity stable) can block. Rules of lower
# maturity are for hunting and alerting, not for stopping an agent.
#
#   pip install pydantic-ai "pyatr>=0.4.1"
#
# Usage:
#   from pydantic_ai import Agent
#   from pydantic_ai_atr import ATRGuard
#   agent = Agent("openai:gpt-5", tools=[...], capabilities=[ATRGuard()])

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Callable

from pyatr import AgentEvent, ATREngine
from pyatr.types import SEVERITY_ORDER


def _lane_allows_without_maturity(match: Any, lane: str) -> bool:
    """Lane gate for pyatr < 0.4.1, whose matches carry no maturity: none is stable."""
    return lane == "hunt"


try:
    from pyatr import lane_allows
except ImportError:  # installed without the pyatr>=0.4.1 pin
    lane_allows = _lane_allows_without_maturity  # type: ignore[assignment]


try:
    from pydantic_ai import ModelRetry
    from pydantic_ai.capabilities import AbstractCapability

    _HAS_PYDANTIC_AI = True
except Exception:  # allow import (and unit-testing the scan logic) without pydantic-ai
    AbstractCapability = object  # type: ignore[assignment,misc]
    _HAS_PYDANTIC_AI = False

    class ModelRetry(Exception):  # type: ignore[no-redef]
        """Fallback so the module imports without pydantic-ai for standalone testing."""


LANES = ("enforce", "alert", "hunt")

_CLIP_MARK = "\n[... ATR: middle of value not scanned ...]\n"


def _text_of(value: Any) -> str:
    """Flatten tool args / results (str | dict | list | None) to scannable text."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            return str(value)
    return str(value)


def _clip(text: str, limit: int | None) -> tuple[str, bool]:
    """Keep the head and tail of text longer than limit; report whether it was cut."""
    if limit is None or len(text) <= limit:
        return text, False
    half = limit // 2
    return text[:half] + _CLIP_MARK + text[-half:], True


def _at_or_above(severity: str, floor: str) -> bool:
    """True if severity is at least as severe as floor (critical is highest)."""
    return SEVERITY_ORDER.get(severity, 99) <= SEVERITY_ORDER[floor]


class ATRGuard(AbstractCapability):
    """Enforce ATR rules over a Pydantic AI agent's tool calls.

    Attach via ``Agent(..., capabilities=[ATRGuard()])``. Every rule is
    evaluated against each tool call and tool result, and every match is
    recorded in ``audit_log``. A match blocks only when its severity is at or
    above ``block_severity`` and its rule is in ``block_lane``. A blocked tool
    call is raised as ``ModelRetry`` before the tool runs.

    Args:
        block_severity: Minimum severity that can block. One of
            ``"low" | "medium" | "high" | "critical"``. Default ``"critical"``.
        block_lane: Lane whose rules can block. ``"enforce"`` (default) is
            rules with ``maturity: stable``; ``"alert"`` adds ``test``;
            ``"hunt"`` is every rule, at the cost of false positives.
        block_on_result: Also block (not just record) when a tool RESULT has a
            blocking match. Default ``False`` (record only).
        on_flag: Optional callback invoked with each finding's audit entry.
        max_scan_chars: Longest value scanned in full. A longer value is
            scanned as its first and last ``max_scan_chars // 2`` characters,
            and its audit entries report ``truncated: True``. ``None`` scans
            everything.
        rules_dir: Load rules from this directory instead of the rules bundled
            with pyatr.
    """

    def __init__(
        self,
        *,
        block_severity: str = "critical",
        block_lane: str = "enforce",
        block_on_result: bool = False,
        on_flag: Callable[[dict], None] | None = None,
        max_scan_chars: int | None = 10_000,
        rules_dir: str | Path | None = None,
    ) -> None:
        if block_severity not in SEVERITY_ORDER:
            raise ValueError(f"block_severity must be one of {sorted(SEVERITY_ORDER)}, got {block_severity!r}")
        if block_lane not in LANES:
            raise ValueError(f"block_lane must be one of {LANES}, got {block_lane!r}")
        if max_scan_chars is not None and max_scan_chars < 2:
            raise ValueError(f"max_scan_chars must be None or at least 2, got {max_scan_chars!r}")
        self.block_severity = block_severity
        self.block_lane = block_lane
        self.block_on_result = block_on_result
        self.on_flag = on_flag
        self.max_scan_chars = max_scan_chars
        self.audit_log: list[dict] = []
        self._rules_dir = rules_dir
        self._engine: ATREngine | None = None
        self._engine_lock = threading.Lock()

    @property
    def engine(self) -> ATREngine:
        """The pyatr engine (hunt lane, every rule), loaded on first use."""
        if self._engine is None:
            with self._engine_lock:
                if self._engine is None:
                    engine = ATREngine()
                    loaded = (
                        engine.load_rules_from_directory(self._rules_dir)
                        if self._rules_dir is not None
                        else engine.load_default_rules()
                    )
                    if not loaded:
                        # A guard with no rules passes everything; never let that be silent.
                        raise RuntimeError("ATRGuard loaded 0 rules; check the pyatr install or rules_dir")
                    self._engine = engine
        return self._engine

    def _blocks(self, match: Any) -> bool:
        return _at_or_above(match.severity, self.block_severity) and lane_allows(match, self.block_lane)

    def _record(self, where: str, tool_name: str, match: Any, *, blocks: bool, truncated: bool) -> None:
        entry = {
            "where": where,
            "tool": tool_name,
            "rule": match.rule_id,
            "title": match.title,
            "severity": match.severity,
            "maturity": getattr(match, "maturity", None),
            "blocks": blocks,
            "truncated": truncated,
        }
        self.audit_log.append(entry)
        if self.on_flag:
            self.on_flag(entry)

    def _blocking_match(self, event: AgentEvent, *, where: str, tool_name: str, truncated: bool) -> Any | None:
        """Evaluate event, record every match, and return the first that blocks."""
        has_text = event.content.strip() or any(v.strip() for v in event.fields.values())
        blocking = None
        for match in self.engine.evaluate(event) if has_text else []:  # most severe first
            blocks = self._blocks(match)
            self._record(where, tool_name, match, blocks=blocks, truncated=truncated)
            if blocking is None and blocks:
                blocking = match
        return blocking

    def check_tool_call(self, tool_name: str, args: Any) -> Any | None:
        """Scan a tool call as a typed ``tool_call`` event; return the blocking match, if any."""
        text, cut = _clip(_text_of(args), self.max_scan_chars)
        event = AgentEvent(
            content=f"{tool_name}\n{text}".strip(),
            event_type="tool_call",
            fields={"tool_name": tool_name, "tool_args": text},
        )
        return self._blocking_match(event, where="tool_args", tool_name=tool_name, truncated=cut)

    def check_tool_result(self, tool_name: str, result: Any) -> Any | None:
        """Scan a tool result as a typed ``tool_response`` event; return the blocking match, if any."""
        text, cut = _clip(_text_of(result), self.max_scan_chars)
        event = AgentEvent(content=text, event_type="tool_response")
        return self._blocking_match(event, where="tool_result", tool_name=tool_name, truncated=cut)

    async def before_tool_execute(self, ctx: Any, *, call: Any, tool_def: Any, args: Any) -> Any:
        name = getattr(call, "tool_name", "")
        match = self.check_tool_call(name, args)
        if match is not None:
            raise ModelRetry(f"[ATR] blocked tool '{name}' by {match.rule_id}: {match.title}")
        return args

    async def after_tool_execute(self, ctx: Any, *, call: Any, tool_def: Any, args: Any, result: Any) -> Any:
        name = getattr(call, "tool_name", "")
        match = self.check_tool_result(name, result)
        if match is not None and self.block_on_result:
            raise ModelRetry(f"[ATR] rejected result of tool '{name}' by {match.rule_id}: {match.title}")
        return result


if __name__ == "__main__":
    # Benign smoke test: confirm the module imports, rules load, and a harmless
    # tool call is not flagged. (The block path is exercised in tests/ against
    # fixture rules, so this security module carries no exploit string of its own.)
    guard = ATRGuard()
    m = guard.check_tool_call("get_weather", {"city": "Paris"})
    assert m is None and not guard.audit_log, "benign tool call must not flag"
    print(f"OK: {len(guard.engine.rules)} rules loaded, benign tool call passes clean")
