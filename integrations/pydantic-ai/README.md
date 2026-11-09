# ATR guard for Pydantic AI

Runtime threat detection for [Pydantic AI](https://ai.pydantic.dev) (v2+) agents,
built as a **Capability** that scans every tool call against
[Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules) —
an open, MIT-licensed detection standard for AI agent threats (like Sigma, but for
prompt injection, tool poisoning, MCP attacks, and skill compromise).

## Install

```bash
pip install pydantic-ai "pyatr>=0.4.1"
```

## Use

```python
from pydantic_ai import Agent
from pydantic_ai_atr import ATRGuard

agent = Agent(
    "openai:gpt-5",
    tools=[...],
    capabilities=[ATRGuard()],   # blocks critical stable-rule matches before the tool runs
)
```

## What blocks

Every loaded ATR rule (pyatr skips `draft` and `deprecated` ones) is evaluated
against every tool call and tool result, and every match is recorded. A match
blocks only when both hold:

- its severity is at or above `block_severity` (default `"critical"`), and
- its rule is in `block_lane` (default `"enforce"`, rules with `maturity: stable`;
  a rule marked `confirm: embedding` is in the hunt lane only, since pyatr has no
  embedding check).

Rules of lower maturity are meant for hunting and alerting, not for stopping an
agent, and they produce false positives on benign tool traffic. Set
`block_lane="alert"` to also block on `maturity: test` rules, or
`block_lane="hunt"` to block on every rule at the cost of those false positives.
If the guard runs against pyatr older than 0.4.1 (installed without the
dependency pin), matches carry no maturity, so only `block_lane="hunt"` can block.

Tool calls are scanned as a `tool_call` event carrying `tool_name` and
`tool_args`, and tool results as a `tool_response` event, so rules written for
tool traffic see the field they read.

`ATRGuard` subclasses `pydantic_ai.capabilities.AbstractCapability` — the documented
path for reusable, distributable capabilities — and overrides two lifecycle hooks:

| Hook | What it does |
|------|--------------|
| `before_tool_execute` | Scans the tool name + validated arguments **before** the tool runs. A blocking match raises `ModelRetry`, which Pydantic AI surfaces to the model as a failed call. |
| `after_tool_execute` | Scans the tool **result** for indirect prompt injection returned by tools (web pages, files, other MCP servers). Records by default; set `block_on_result=True` to reject. |

## Options

| Argument | Default | Meaning |
|----------|---------|---------|
| `block_severity` | `"critical"` | Minimum severity that can block: `"low"`, `"medium"`, `"high"` or `"critical"`. |
| `block_lane` | `"enforce"` | Lane whose rules can block: `"enforce"`, `"alert"` or `"hunt"`. |
| `block_on_result` | `False` | Also block (not just record) on a blocking match in a tool result. |
| `on_flag` | `None` | Callback invoked with each finding's audit entry. |
| `max_scan_chars` | `10000` | Longer values are scanned as their first and last halves of this many characters, and their entries report `truncated: True`; text in the unscanned middle is not detected. `None` scans everything, at a cost that grows with the length of the value. |
| `rules_dir` | `None` | Load rules from a directory instead of the rules bundled with pyatr. |

Every finding is appended to `guard.audit_log` (list of `{where, tool, rule, title, severity, maturity, blocks, truncated}`).

The rules load on the first tool call. Read `guard.engine` at startup to load them earlier.

## Tests

```bash
pip install pydantic-ai "pyatr>=0.4.1" pytest pytest-asyncio
pytest tests
```

## Notes

- Rules ship bundled inside the `pyatr` package — no source checkout needed.
- ATR is vendor-neutral and independent of any product; the rules are MIT-licensed.
- Detection is deterministic pattern matching: the same input gives the same answer every time.
