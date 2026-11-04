# Runtime threat detection for LangChain agents via a custom AgentMiddleware.
#
# Scans the agent's model output and every tool call against ATR (Agent Threat
# Rules) -- an open, vendor-neutral detection standard for AI agents (MIT; like
# Sigma, but for prompt injection, tool poisoning, MCP attacks and skill
# compromise). Rules ship bundled in the pip package.
#
# Two scan points:
#   - after_model:   scan the model's output.
#   - wrap_tool_call: scan tool-call arguments BEFORE execution, and the tool
#                     RESULT after execution to catch indirect prompt injection
#                     returned by tools (web pages, files, other MCP servers).
#
# ADVISORY BY DEFAULT. Every match is recorded in `audit_log` (and passed to
# `on_flag`); nothing is halted or refused. Pass `blocking=True` to let the
# middleware act: it then halts the agent (jump_to "end") after a model output,
# or refuses a tool call before it runs, only for a match that may block -- a
# rule in the enforce lane (`maturity: stable`) at or above `block_severity`,
# which must be "high" (default) or "critical". Matches of other rules are
# recorded and never block. This middleware used to block by default on any
# critical match of any rule, experimental ones included.
#
#   pip install langchain "pyatr>=0.4.1"
#
# Usage:
#   from langchain.agents import create_agent
#   agent = create_agent(model="gpt-5.5", tools=[...],
#                        middleware=[ATRGuardrailMiddleware()])                # report only
#   #                    middleware=[ATRGuardrailMiddleware(blocking=True)])   # may block

from __future__ import annotations

import json
from typing import Any, Callable

from pyatr import scan
from pyatr.types import SEVERITY_ORDER


def _lane_allows_without_maturity(match: Any, lane: str) -> bool:
    """Lane gate for pyatr < 0.4.1, whose matches carry no maturity: none is stable."""
    return lane == "hunt"


try:
    from pyatr import lane_allows
except ImportError:  # installed without the pyatr>=0.4.1 pin
    lane_allows = _lane_allows_without_maturity  # type: ignore[assignment]

# Mirrors pyatr.enforcement: only the enforce lane at high/critical may block.
BLOCKING_LANE = "enforce"
BLOCKING_SEVERITIES = ("critical", "high")

try:
    from langchain.agents.middleware import AgentMiddleware, hook_config
    from langchain_core.messages import ToolMessage
    _HAS_LANGCHAIN = True
except Exception:  # allow import (and unit-testing the scan logic) without langchain
    AgentMiddleware = object  # type: ignore[assignment,misc]
    ToolMessage = None  # type: ignore[assignment]
    _HAS_LANGCHAIN = False

    def hook_config(**_kwargs):  # no-op decorator fallback
        def _wrap(fn):
            return fn
        return _wrap


def _text_of(content: Any) -> str:
    """Flatten LangChain message/tool content (str | list[block] | dict) to text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return content.get("text") or json.dumps(content, ensure_ascii=False)
    if isinstance(content, list):
        out = []
        for block in content:
            if isinstance(block, str):
                out.append(block)
            elif isinstance(block, dict):
                out.append(block.get("text") or json.dumps(block, ensure_ascii=False))
            else:
                out.append(str(block))
        return "\n".join(out)
    return str(content)


def _at_or_above(severity: str, floor: str) -> bool:
    """True if severity is at least as severe as floor (critical is highest)."""
    return SEVERITY_ORDER.get(severity, 99) <= SEVERITY_ORDER.get(floor, 0)


class ATRGuardrailMiddleware(AgentMiddleware):
    """Report ATR matches over a LangChain agent's model output and tool calls.

    Advisory unless ``blocking=True``; see the module header.
    """

    def __init__(
        self,
        *,
        blocking: bool = False,
        block_severity: str = "high",
        on_flag: Callable[[dict], None] | None = None,
    ) -> None:
        super().__init__()
        if not isinstance(blocking, bool):
            # "false" is truthy; refuse it rather than turn blocking on.
            raise TypeError(f"blocking must be a bool, got {blocking!r}")
        if block_severity not in BLOCKING_SEVERITIES:
            raise ValueError(
                f"block_severity must be one of {BLOCKING_SEVERITIES}, got {block_severity!r}: "
                "only high and critical matches from stable rules may block"
            )
        self.blocking = blocking
        self.block_severity = block_severity
        self.on_flag = on_flag
        self.audit_log: list[dict] = []

    def _blocks(self, match) -> bool:
        """Blocking on, enforce lane, and at or above block_severity."""
        return (
            self.blocking
            and _at_or_above(match.severity, self.block_severity)
            and lane_allows(match, BLOCKING_LANE)
        )

    def _record(self, where: str, match) -> bool:
        """Record a match; return whether it blocks."""
        blocks = self._blocks(match)
        entry = {
            "where": where,
            "rule": match.rule_id,
            "title": match.title,
            "severity": match.severity,
            "maturity": getattr(match, "maturity", None),
            "blocks": blocks,
        }
        self.audit_log.append(entry)
        if self.on_flag:
            self.on_flag(entry)
        return blocks

    @hook_config(can_jump_to=["end"])
    def after_model(self, state, runtime=None) -> dict[str, Any] | None:
        messages = state.get("messages") if isinstance(state, dict) else getattr(state, "messages", None)
        if not messages:
            return None
        text = _text_of(getattr(messages[-1], "content", None))
        halt = False
        for match in scan(text) if text.strip() else []:
            if self._record("model_output", match):
                halt = True
        return {"jump_to": "end"} if halt else None

    def wrap_tool_call(self, request, handler: Callable):
        tool_call = getattr(request, "tool_call", None) or {}
        name = tool_call.get("name", "")
        args_text = _text_of(tool_call.get("args"))
        pre = f"{name}\n{args_text}".strip()

        # Pre-execution: with blocking on, refuse a tool call before it runs.
        for match in scan(pre) if pre else []:
            if self._record("tool_args", match) and ToolMessage is not None:
                return ToolMessage(
                    content=f"[ATR] blocked tool '{name}' by {match.rule_id}: {match.title}",
                    tool_call_id=tool_call.get("id", ""),
                    name=name,
                    status="error",
                )

        result = handler(request)

        # Post-execution: catch indirect prompt injection in the tool result.
        result_text = _text_of(getattr(result, "content", None))
        for match in scan(result_text) if result_text.strip() else []:
            self._record("tool_result", match)
        return result


if __name__ == "__main__":
    # Self-check without needing langchain installed: a benign output records
    # nothing and halts nothing. The block path is exercised in tests/ against
    # fixture rules, so this module carries no attack string of its own.
    class _Msg:
        def __init__(self, content):
            self.content = content

    mw = ATRGuardrailMiddleware()
    out = mw.after_model({"messages": [_Msg("The weather in Paris is sunny.")]})
    print("after_model on benign ->", out, "| findings:", len(mw.audit_log))
    assert out is None and not mw.audit_log, "benign must not flag"
    print("OK")
