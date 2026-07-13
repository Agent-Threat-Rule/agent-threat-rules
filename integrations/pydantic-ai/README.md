# ATR guard for Pydantic AI

Runtime threat detection for [Pydantic AI](https://ai.pydantic.dev) (v2+) agents,
built as a **Capability** that scans every tool call against
[Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules) —
an open, MIT-licensed detection standard for AI agent threats (like Sigma, but for
prompt injection, tool poisoning, MCP attacks, and skill compromise).

## Install

```bash
pip install pydantic-ai pyatr
```

## Use

```python
from pydantic_ai import Agent
from pydantic_ai_atr import ATRGuard

agent = Agent(
    "openai:gpt-5",
    tools=[...],
    capabilities=[ATRGuard()],   # blocks critical tool calls before they run
)
```

`ATRGuard` subclasses `pydantic_ai.capabilities.AbstractCapability` — the documented
path for reusable, distributable capabilities — and overrides two lifecycle hooks:

| Hook | What it does |
|------|--------------|
| `before_tool_execute` | Scans the tool name + validated arguments **before** the tool runs. A finding at/above `block_severity` raises `ModelRetry`, which Pydantic AI surfaces to the model as a failed call. |
| `after_tool_execute` | Scans the tool **result** for indirect prompt injection returned by tools (web pages, files, other MCP servers). Records by default; set `block_on_result=True` to reject. |

## Options

| Argument | Default | Meaning |
|----------|---------|---------|
| `block_severity` | `"critical"` | Minimum severity that blocks a tool call. |
| `block_on_result` | `False` | Also block (not just record) on a flagged tool result. |
| `on_flag` | `None` | Callback invoked with each finding's audit entry. |

Every finding is appended to `guard.audit_log` (list of `{where, tool, rule, title, severity}`).

## Notes

- Rules ship bundled inside the `pyatr` package — no source checkout needed.
- ATR is vendor-neutral and independent of any product; the rules are MIT-licensed.
- Detection is deterministic pattern matching: milliseconds per call, same answer every time.
