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
    middleware=[ATRGuardrailMiddleware()],             # report only (default)
    # middleware=[ATRGuardrailMiddleware(blocking=True)],  # may halt / refuse
)
```

## What it does

Two scan points, no changes to your agent logic:

- `after_model` — scans the model's output.
- `wrap_tool_call` — scans tool-call arguments before execution, and the tool
  result after execution to catch indirect prompt injection returned by tools
  (web pages, files, other MCP servers).

**Advisory by default**: every finding is recorded and nothing is halted or
refused. With `blocking=True`, a finding halts the agent (`jump_to="end"`) after
a model output, or refuses a tool call before it runs, only when its rule has
`maturity: stable` (the ATR enforce lane) and its severity is at or above
`block_severity` (`"high"` by default, or `"critical"`). Findings from rules of
lower maturity are recorded and never block. Earlier versions blocked by
default on any critical finding, experimental rules included.

Every finding is appended to `middleware.audit_log` (rule id, title, severity,
maturity, whether it blocked, where it fired), giving you a tamper-evident trail — useful for EU AI Act
Article 12 style event logging.

## Configure

```python
ATRGuardrailMiddleware(
    blocking=False,              # True lets stable high/critical findings block
    block_severity="high",       # "high" (default) or "critical"; lower is an error
    on_flag=lambda entry: ...,   # callback per finding (ship to your SIEM, etc.)
)
```

## Notes

`ATRGuardrailMiddleware` is engine-backed by the ATR standard; the pattern
(a middleware that scans model output and tool I/O) is reusable for any rule
source. See [`langchain_atr_guardrail.py`](./langchain_atr_guardrail.py) — it is
self-contained and runnable (`python langchain_atr_guardrail.py` runs a built-in
self-check). It needs `pyatr>=0.4.1`, whose matches carry the rule maturity;
with an older pyatr no finding can block. Tests: `pytest integrations/langchain/tests`.
