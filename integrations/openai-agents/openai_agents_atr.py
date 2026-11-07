# Runtime threat detection for OpenAI Agents SDK agents via guardrails.
#
# Scans agent traffic against ATR (Agent Threat Rules) -- an open,
# vendor-neutral detection standard for AI agents (MIT; like Sigma, but for
# prompt injection, tool poisoning, MCP attacks and skill compromise). Rules
# ship bundled in the pyatr pip package.
#
# The OpenAI Agents SDK has two guardrail layers, and this module plugs ATR
# into both:
#
#   Tool guardrails (run around every FunctionTool call, including tools
#   exposed by a local MCP server):
#     - tool_input_guardrail:  scan the tool name + raw arguments BEFORE the
#                              tool runs, as an ATR `tool_call` event.
#     - tool_output_guardrail: scan the tool's return value AFTER it runs, as
#                              an ATR `tool_response` event -- the channel for
#                              indirect prompt injection (web pages, files,
#                              other MCP servers).
#
#   Agent guardrails:
#     - input_guardrail:  scan the run's input as an ATR `llm_input` event.
#                         The SDK runs input guardrails for the FIRST agent
#                         in a run only.
#     - output_guardrail: scan the final output as an ATR `llm_output` event
#                         (e.g. credentials or system-prompt text leaking).
#
# Each check builds a typed AgentEvent rather than passing raw text as user
# input, so rules that read `tool_args`, `tool_name` or `tool_response` see the
# field they were written for.
#
#   pip install openai-agents pyatr
#
# Usage:
#   from agents import Agent, function_tool
#   from openai_agents_atr import ATRGuard
#
#   guard = ATRGuard()
#   tools = guard.protect(fetch_url, run_query)      # attach tool guardrails
#   agent = Agent(
#       name="assistant",
#       tools=tools,
#       input_guardrails=[guard.input_guardrail],
#       output_guardrails=[guard.output_guardrail],
#   )

from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Literal

from pyatr import ATREngine, AgentEvent, ATRMatch
from pyatr.types import SEVERITY_ORDER

try:
    from agents.guardrail import GuardrailFunctionOutput, InputGuardrail, OutputGuardrail
    from agents.tool_guardrails import (
        ToolGuardrailFunctionOutput,
        ToolInputGuardrail,
        ToolOutputGuardrail,
    )

    _HAS_AGENTS_SDK = True
except ImportError:  # import (and unit-test the scan logic) without the SDK
    _HAS_AGENTS_SDK = False


__all__ = ["ATRGuard", "ATRDecision"]

Severity = Literal["critical", "high", "medium", "low"]
OnBlock = Literal["reject", "raise"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _text_of(value: Any) -> str:
    """Flatten SDK values (str, dict, list, pydantic models, None) to scannable text."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    dump = getattr(value, "model_dump_json", None)  # pydantic models (structured output)
    if callable(dump):
        try:
            return dump()
        except Exception:
            pass
    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            return str(value)
    return str(value)


def _input_text(value: Any) -> str:
    """Extract the text a model will read from a run input.

    A run input is either a string or a list of response input items. Items
    carry text either as ``content: str`` or as a list of parts with a
    ``text`` key. Only that text is scanned, so item ids and roles cannot
    trip a rule on their own.
    """
    if isinstance(value, str):
        return value
    if not isinstance(value, (list, tuple)):
        return _text_of(value)
    chunks: list[str] = []
    for item in value:
        content = item.get("content") if isinstance(item, dict) else getattr(item, "content", None)
        if isinstance(content, str):
            chunks.append(content)
        elif isinstance(content, (list, tuple)):
            for part in content:
                text = part.get("text") if isinstance(part, dict) else getattr(part, "text", None)
                if isinstance(text, str):
                    chunks.append(text)
        else:
            # Tool-call outputs replayed into the input carry an `output` key.
            output = item.get("output") if isinstance(item, dict) else getattr(item, "output", None)
            if output is not None:
                chunks.append(_text_of(output))
    return "\n".join(chunks)


def _at_or_above(severity: str, floor: str) -> bool:
    """True if severity is at least as severe as floor (critical is highest)."""
    return SEVERITY_ORDER.get(severity, 99) <= SEVERITY_ORDER.get(floor, 0)


_CLIP_MARK = "\n[... ATR: middle of value not scanned ...]\n"


def _clip(text: str, limit: int | None) -> tuple[str, bool]:
    """Keep the head and tail of text longer than limit; report whether it was cut.

    Injected instructions in tool output usually sit near the start or the end
    of a document, and a cut that is reported beats one that is silent.
    """
    if limit is None or len(text) <= limit:
        return text, False
    half = limit // 2
    return text[:half] + _CLIP_MARK + text[-half:], True


@dataclass(frozen=True)
class ATRDecision:
    """Outcome of one ATR check.

    ``matches`` holds every rule that fired; ``blocking`` is the most severe
    one at or above the guard's ``block_severity``, or ``None``. ``truncated``
    is true when the value exceeded ``max_scan_chars`` and its middle was not
    scanned.
    """

    where: str
    matches: tuple[ATRMatch, ...]
    blocking: ATRMatch | None
    truncated: bool = False

    @property
    def blocked(self) -> bool:
        return self.blocking is not None

    def info(self) -> dict[str, Any]:
        """Serializable summary, used as the guardrail's ``output_info``."""
        return {
            "where": self.where,
            "blocked": self.blocked,
            "blocking_rule": self.blocking.rule_id if self.blocking else None,
            "rules": [m.rule_id for m in self.matches],
            "truncated": self.truncated,
        }


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


class ATRGuard:
    """Enforce ATR rules over an OpenAI Agents SDK agent.

    Args:
        block_severity: Minimum severity that blocks. One of
            ``"critical" | "high" | "medium" | "low"``. Default ``"critical"``.
        on_block: What a blocked TOOL call does. ``"reject"`` (default) skips
            the tool and returns a short refusal to the model so the run
            continues; ``"raise"`` halts the run with
            ``ToolInputGuardrailTripwireTriggered`` /
            ``ToolOutputGuardrailTripwireTriggered``. Agent input/output
            guardrails always halt the run, since that is the only behaviour
            the SDK offers for them.
        block_on_result: Also block (not just record) when a tool RESULT trips
            a rule at or above ``block_severity``. Default ``False``.
        on_flag: Optional callback invoked with each finding's audit entry.
            Inside a run it is called from a worker thread.
        max_scan_chars: Longest value scanned in full. A longer value is
            scanned as its first and last ``max_scan_chars // 2`` characters,
            and the decision reports ``truncated=True``. pyatr's cost grows
            with input length (roughly 2.4 s for 10,000 characters with every
            rule loaded), so this bounds the time one check can take. ``None``
            scans everything. Default ``10_000``.
        rules_dir: Load rules from this directory instead of the rules bundled
            in pyatr (for example a checkout of the ATR repository).
        engine: A pre-loaded ``pyatr.ATREngine`` to share across guards.
    """

    def __init__(
        self,
        *,
        block_severity: Severity = "critical",
        on_block: OnBlock = "reject",
        block_on_result: bool = False,
        on_flag: Callable[[dict], None] | None = None,
        max_scan_chars: int | None = 10_000,
        rules_dir: str | Path | None = None,
        engine: ATREngine | None = None,
    ) -> None:
        if block_severity not in SEVERITY_ORDER:
            raise ValueError(f"block_severity must be one of {sorted(SEVERITY_ORDER)}, got {block_severity!r}")
        if on_block not in ("reject", "raise"):
            raise ValueError(f"on_block must be 'reject' or 'raise', got {on_block!r}")
        if max_scan_chars is not None and max_scan_chars < 2:
            raise ValueError(f"max_scan_chars must be None or at least 2, got {max_scan_chars!r}")
        self.block_severity = block_severity
        self.on_block = on_block
        self.block_on_result = block_on_result
        self.on_flag = on_flag
        self.max_scan_chars = max_scan_chars
        self.audit_log: list[dict] = []
        self._rules_dir = Path(rules_dir) if rules_dir is not None else None
        self._engine = engine
        self._engine_lock = threading.Lock()

    # -- engine ------------------------------------------------------------

    @property
    def engine(self) -> ATREngine:
        """The pyatr engine, loaded on first use (access it at startup to preload)."""
        if self._engine is None:
            with self._engine_lock:  # scans run on worker threads; load the rules once
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

    # -- scanning (SDK-independent, unit-testable) -------------------------

    def _decide(
        self, event: AgentEvent, *, where: str, tool_name: str = "", truncated: bool = False
    ) -> ATRDecision:
        has_text = event.content.strip() or any(v.strip() for v in event.fields.values())
        matches = tuple(self.engine.evaluate(event)) if has_text else ()
        blocking = None
        for match in matches:  # evaluate() returns most severe first
            self._record(where, tool_name, match)
            if blocking is None and _at_or_above(match.severity, self.block_severity):
                blocking = match
        return ATRDecision(where=where, matches=matches, blocking=blocking, truncated=truncated)

    def _record(self, where: str, tool_name: str, match: ATRMatch) -> None:
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

    def check_tool_call(self, tool_name: str, arguments: Any) -> ATRDecision:
        """Scan a tool call before it runs. ``arguments`` is the raw JSON string or a dict."""
        args, cut = _clip(_text_of(arguments), self.max_scan_chars)
        event = AgentEvent(
            content=f"{tool_name}\n{args}".strip(),
            event_type="tool_call",
            fields={"tool_name": tool_name, "tool_args": args},
        )
        return self._decide(event, where="tool_args", tool_name=tool_name, truncated=cut)

    def check_tool_output(self, tool_name: str, output: Any) -> ATRDecision:
        """Scan a tool's return value."""
        text, cut = _clip(_text_of(output), self.max_scan_chars)
        event = AgentEvent(content=text, event_type="tool_response")
        return self._decide(event, where="tool_result", tool_name=tool_name, truncated=cut)

    def check_input(self, value: Any) -> ATRDecision:
        """Scan a run input (string or list of input items)."""
        text, cut = _clip(_input_text(value), self.max_scan_chars)
        event = AgentEvent(content=text, event_type="llm_input")
        return self._decide(event, where="agent_input", truncated=cut)

    def check_output(self, value: Any) -> ATRDecision:
        """Scan an agent's final output."""
        text, cut = _clip(_text_of(value), self.max_scan_chars)
        event = AgentEvent(content=text, event_type="llm_output")
        return self._decide(event, where="agent_output", truncated=cut)

    # -- SDK guardrail functions -------------------------------------------

    def _tool_verdict(self, decision: ATRDecision, *, tool_name: str, enforce: bool) -> Any:
        info = decision.info()
        if not (enforce and decision.blocked):
            return ToolGuardrailFunctionOutput.allow(output_info=info)
        if self.on_block == "raise":
            return ToolGuardrailFunctionOutput.raise_exception(output_info=info)
        rule = decision.blocking
        # Name the rule, never echo the matched text back into the model's context.
        message = (
            f"[ATR] Tool '{tool_name}' was blocked by {rule.rule_id} ({rule.title}). "
            "Do not retry this call with the same content."
        )
        return ToolGuardrailFunctionOutput.reject_content(message=message, output_info=info)

    # Scanning is CPU-bound and can take seconds on long values, so each SDK
    # guardrail runs it in a worker thread instead of blocking the event loop.

    async def _tool_input_fn(self, data: Any) -> Any:
        ctx = data.context
        decision = await asyncio.to_thread(self.check_tool_call, ctx.tool_name, ctx.tool_arguments)
        return self._tool_verdict(decision, tool_name=ctx.tool_name, enforce=True)

    async def _tool_output_fn(self, data: Any) -> Any:
        name = data.context.tool_name
        decision = await asyncio.to_thread(self.check_tool_output, name, data.output)
        return self._tool_verdict(decision, tool_name=name, enforce=self.block_on_result)

    async def _input_fn(self, ctx: Any, agent: Any, value: Any) -> Any:
        decision = await asyncio.to_thread(self.check_input, value)
        return GuardrailFunctionOutput(output_info=decision.info(), tripwire_triggered=decision.blocked)

    async def _output_fn(self, ctx: Any, agent: Any, value: Any) -> Any:
        decision = await asyncio.to_thread(self.check_output, value)
        return GuardrailFunctionOutput(output_info=decision.info(), tripwire_triggered=decision.blocked)

    # -- SDK guardrail objects ---------------------------------------------

    @staticmethod
    def _require_sdk() -> None:
        if not _HAS_AGENTS_SDK:
            raise ImportError("openai-agents is not installed: pip install openai-agents")

    @property
    def tool_input_guardrail(self) -> "ToolInputGuardrail":
        """Guardrail for ``FunctionTool.tool_input_guardrails``."""
        self._require_sdk()
        return ToolInputGuardrail(guardrail_function=self._tool_input_fn, name="atr_tool_input")

    @property
    def tool_output_guardrail(self) -> "ToolOutputGuardrail":
        """Guardrail for ``FunctionTool.tool_output_guardrails``."""
        self._require_sdk()
        return ToolOutputGuardrail(guardrail_function=self._tool_output_fn, name="atr_tool_output")

    @property
    def input_guardrail(self) -> "InputGuardrail":
        """Guardrail for ``Agent(input_guardrails=[...])``.

        It runs before the agent starts (``run_in_parallel=False``), so a
        blocked input never reaches the model. The SDK's default runs input
        guardrails concurrently with the first model call.
        """
        self._require_sdk()
        try:
            return InputGuardrail(guardrail_function=self._input_fn, name="atr_input", run_in_parallel=False)
        except TypeError:  # older SDK versions have no run_in_parallel option
            return InputGuardrail(guardrail_function=self._input_fn, name="atr_input")

    @property
    def output_guardrail(self) -> "OutputGuardrail":
        """Guardrail for ``Agent(output_guardrails=[...])``."""
        self._require_sdk()
        return OutputGuardrail(guardrail_function=self._output_fn, name="atr_output")

    def protect(self, *tools: Any) -> list[Any]:
        """Attach ATR's tool input and output guardrails to each function tool.

        Existing guardrails on a tool are kept, and ATR's are added once
        (calling ``protect`` twice does not double-scan). Returns the tools
        so the call can be used inline: ``Agent(tools=guard.protect(a, b))``.
        Hosted tools (web search, file search, code interpreter, hosted MCP)
        and handoffs do not run tool guardrails in the SDK; they are returned
        unchanged.
        """
        protected: list[Any] = []
        for tool in _flatten(tools):
            if hasattr(tool, "tool_input_guardrails"):
                tool.tool_input_guardrails = _with(tool.tool_input_guardrails, self.tool_input_guardrail)
                tool.tool_output_guardrails = _with(tool.tool_output_guardrails, self.tool_output_guardrail)
            protected.append(tool)
        return protected


def _flatten(tools: Iterable[Any]) -> Iterable[Any]:
    for tool in tools:
        if isinstance(tool, (list, tuple)):
            yield from tool
        else:
            yield tool


def _with(existing: list | None, guardrail: Any) -> list:
    current = list(existing or [])
    if any(getattr(g, "name", None) == guardrail.name for g in current):
        return current
    return current + [guardrail]


if __name__ == "__main__":
    # Benign smoke test: the module imports, rules load, and a harmless tool
    # call passes clean. Block paths are exercised against ATR's own rule
    # fixtures in tests/, so this module carries no attack string of its own.
    guard = ATRGuard()
    decision = guard.check_tool_call("get_weather", '{"city": "Paris"}')
    assert not decision.matches, f"benign tool call flagged: {decision.info()}"
    print(f"OK: {len(guard.engine.rules)} rules loaded, benign tool call passes clean")
