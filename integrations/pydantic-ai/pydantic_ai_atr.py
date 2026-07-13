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
#                          runs; raise ModelRetry to block a call at/above
#                          block_severity, which Pydantic AI surfaces to the
#                          model as a failed call.
#   - after_tool_execute:  scan the tool RESULT to catch indirect prompt
#                          injection returned by tools (web pages, files, other
#                          MCP servers). Records by default; blocks when
#                          block_on_result=True.
#
#   pip install pydantic-ai pyatr
#
# Usage:
#   from pydantic_ai import Agent
#   from pydantic_ai_atr import ATRGuard
#   agent = Agent("openai:gpt-5", tools=[...], capabilities=[ATRGuard()])

from __future__ import annotations

import json
from typing import Any, Callable

from pyatr import scan
from pyatr.types import SEVERITY_ORDER

try:
    from pydantic_ai import ModelRetry
    from pydantic_ai.capabilities import AbstractCapability

    _HAS_PYDANTIC_AI = True
except Exception:  # allow import (and unit-testing the scan logic) without pydantic-ai
    AbstractCapability = object  # type: ignore[assignment,misc]
    _HAS_PYDANTIC_AI = False

    class ModelRetry(Exception):  # type: ignore[no-redef]
        """Fallback so the module imports without pydantic-ai for standalone testing."""


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


def _at_or_above(severity: str, floor: str) -> bool:
    """True if severity is at least as severe as floor (critical is highest)."""
    return SEVERITY_ORDER.get(severity, 99) <= SEVERITY_ORDER.get(floor, 0)


class ATRGuard(AbstractCapability):
    """Enforce ATR rules over a Pydantic AI agent's tool calls.

    Attach via ``Agent(..., capabilities=[ATRGuard()])``. A tool call whose name
    or arguments trip a rule at/above ``block_severity`` is blocked before it
    runs (raised as ``ModelRetry``); tool results are scanned for indirect
    injection.

    Args:
        block_severity: Minimum severity that blocks a tool call. One of
            ``"info" | "low" | "medium" | "high" | "critical"``. Default ``"critical"``.
        block_on_result: Also block (not just record) when a tool RESULT trips a
            rule at/above ``block_severity``. Default ``False`` (record only).
        on_flag: Optional callback invoked with each finding's audit entry.
    """

    def __init__(
        self,
        *,
        block_severity: str = "critical",
        block_on_result: bool = False,
        on_flag: Callable[[dict], None] | None = None,
    ) -> None:
        self.block_severity = block_severity
        self.block_on_result = block_on_result
        self.on_flag = on_flag
        self.audit_log: list[dict] = []

    def _record(self, where: str, tool_name: str, match: Any) -> None:
        entry = {
            "where": where,
            "tool": tool_name,
            "rule": match.rule_id,
            "title": match.title,
            "severity": match.severity,
        }
        self.audit_log.append(entry)
        if self.on_flag:
            self.on_flag(entry)

    def _blocking_match(self, text: str, *, where: str, tool_name: str) -> Any | None:
        """Scan text, record every finding, and return the first at/above block_severity."""
        blocking = None
        for match in scan(text) if text.strip() else []:
            self._record(where, tool_name, match)
            if blocking is None and _at_or_above(match.severity, self.block_severity):
                blocking = match
        return blocking

    async def before_tool_execute(self, ctx: Any, *, call: Any, tool_def: Any, args: Any) -> Any:
        name = getattr(call, "tool_name", "")
        text = f"{name}\n{_text_of(args)}".strip()
        match = self._blocking_match(text, where="tool_args", tool_name=name)
        if match is not None:
            raise ModelRetry(f"[ATR] blocked tool '{name}' by {match.rule_id}: {match.title}")
        return args

    async def after_tool_execute(self, ctx: Any, *, call: Any, tool_def: Any, args: Any, result: Any) -> Any:
        name = getattr(call, "tool_name", "")
        match = self._blocking_match(_text_of(result), where="tool_result", tool_name=name)
        if match is not None and self.block_on_result:
            raise ModelRetry(f"[ATR] rejected result of tool '{name}' by {match.rule_id}: {match.title}")
        return result


if __name__ == "__main__":
    # Benign smoke test: confirm the module imports, rules load, and a harmless
    # tool call is not flagged. (The block path is exercised against ATR's own
    # rule fixtures in the integration tests, not with a live payload here, so
    # this security module carries no exploit string of its own.)
    guard = ATRGuard()
    m = guard._blocking_match(
        'get_weather\n{"city": "Paris"}', where="tool_args", tool_name="get_weather"
    )
    assert m is None and not guard.audit_log, "benign tool call must not flag"
    print("OK: module imports, rules load, benign tool call passes clean")
