# ATR Guardrail Middleware for LangChain

Runtime threat detection for LangChain agents. Scans an agent's model output and
every tool call against [ATR (Agent Threat Rules)](https://github.com/Agent-Threat-Rule/agent-threat-rules) —
an open, vendor-neutral detection standard for AI agents (MIT; like Sigma, but
for prompt injection, tool poisoning, MCP attacks and skill compromise).

## Install

```bash
pip install langchain pyatr
```

ATR rules ship bundled inside `pyatr`, so no network or rule download is needed.

## Use

```python
from langchain.agents import create_agent
from langchain_atr_guardrail import ATRGuardrailMiddleware

agent = create_agent(
    model="gpt-5.5",
    tools=[...],
    middleware=[ATRGuardrailMiddleware()],
)
```

## What it does

Two enforcement points, no changes to your agent logic:

- `after_model` — scans the model's output; halts the agent (`jump_to="end"`) on
  a finding at or above `block_severity` (default `critical`).
- `wrap_tool_call` — scans tool-call arguments before execution and blocks a
  critical call outright; scans the tool result after execution to catch
  indirect prompt injection returned by tools (web pages, files, other MCP
  servers).

Every finding is appended to `middleware.audit_log` (rule id, title, severity,
where it fired), giving you a tamper-evident trail — useful for EU AI Act
Article 12 style event logging.

## Configure

```python
ATRGuardrailMiddleware(
    block_severity="critical",   # block at/above this severity; "high" is stricter
    on_flag=lambda entry: ...,   # callback per finding (ship to your SIEM, etc.)
)
```

## Notes

`ATRGuardrailMiddleware` is engine-backed by the ATR standard; the pattern
(a middleware that scans model output and tool I/O) is reusable for any rule
source. See [`langchain_atr_guardrail.py`](./langchain_atr_guardrail.py) — it is
self-contained and runnable (`python langchain_atr_guardrail.py` runs a built-in
self-check of the detection logic).
