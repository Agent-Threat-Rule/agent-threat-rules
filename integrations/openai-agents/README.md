# ATR guard for the OpenAI Agents SDK

Runtime threat detection for [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/)
agents, built on the SDK's own guardrails. It checks tool calls, tool results,
run input and final output against
[Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules),
an open, MIT-licensed detection standard for AI agent threats. ATR is like Sigma,
but for prompt injection, tool poisoning, MCP attacks and skill compromise.

## Install

```bash
pip install openai-agents "pyatr>=0.4.1"
```

pyatr 0.4.1 or later is required: it carries each rule's `maturity`, which
the guard uses to decide what may block. (Skip 0.4.0, whose bundled rules
lost `maturity` in packaging.)

Then copy `openai_agents_atr.py` into your project, or install this directory:
`pip install ./integrations/openai-agents`.

## Use

```python
from agents import Agent, Runner, function_tool
from openai_agents_atr import ATRGuard

@function_tool
def fetch_url(url: str) -> str:
    """Fetch a web page."""
    ...

guard = ATRGuard()   # blocks critical findings from stable rules; records everything
guard.engine         # optional: load the rules now, not on the first tool call

agent = Agent(
    name="assistant",
    tools=guard.protect(fetch_url),           # tool input + output guardrails
    input_guardrails=[guard.input_guardrail],
    output_guardrails=[guard.output_guardrail],
)

result = await Runner.run(agent, "Summarise https://example.com")
print(guard.audit_log)
```

For tools exposed by a local MCP server, the SDK accepts
`tool_input_guardrails=[guard.tool_input_guardrail]` and
`tool_output_guardrails=[guard.tool_output_guardrail]` on the server and applies
them to every tool the server exposes.

## What gets checked

| Guardrail | SDK hook | ATR event | Blocks by |
|---|---|---|---|
| `tool_input_guardrail` | Before a function tool runs | `tool_call`, with `tool_name` and `tool_args` set | Skipping the tool and sending the model a short refusal that names the rule (or halting the run if `on_block="raise"`) |
| `tool_output_guardrail` | After a function tool returns | `tool_response` | Recording only, unless `block_on_result=True` |
| `input_guardrail` | On the run's input, **before** the model is called (`run_in_parallel=False`) | `llm_input` | Raising `InputGuardrailTripwireTriggered` |
| `output_guardrail` | On the final output | `llm_output` | Raising `OutputGuardrailTripwireTriggered` |

Each check sends a **typed** ATR event. That way, rules written for tool
arguments or tool responses read the field they were written for, instead of
everything being scanned as user input. Across the corpus's tool-traffic
fixtures (181 true positives in `rules/`), the typed events fire the intended
rule on all 181. Scanning the same text as user input fires it on 30.

The refusal message names the rule and its title. It never repeats the matched
text back into the model's context.

## What blocks by default

The guard scans every rule and records every match, but **by default only
rules in ATR's enforce lane (`maturity: stable`) can block**, and only at
`critical` severity. That mirrors the TypeScript engine, whose enforce lane is
the one meant for automatic blocking. On 120 benign skills from
`data/skill-benchmark/benign`, each checked as a tool result and as an agent
input (240 checks), the default blocked none. Blocking on every rule
(`block_lane="hunt"`) blocked 28.

The cost is coverage: most critical rules are not yet stable, so their matches
are recorded and reported in `output_info` but do not block.

| `block_lane` | Rules that can block |
|---|---|
| `"enforce"` (default) | `maturity: stable` |
| `"alert"` | `stable` and `test` |
| `"hunt"` | every rule, at the cost of false positives |

Rules marked `confirm: embedding` block in the hunt lane only, since pyatr has
no embedding check. A match from a pyatr older than 0.4.1 carries no maturity
and is treated as not stable, so it never blocks under the default.

## Options

| Argument | Default | Meaning |
|---|---|---|
| `block_severity` | `"critical"` | Minimum severity that blocks: `critical`, `high`, `medium` or `low`. |
| `block_lane` | `"enforce"` | ATR lane a rule must be in to block: `"enforce"`, `"alert"` or `"hunt"` (see above). |
| `on_block` | `"reject"` | For tool calls: `"reject"` skips the tool and lets the run continue; `"raise"` halts the run. |
| `block_on_result` | `False` | Also block, not just record, when a tool **result** is flagged. |
| `on_flag` | `None` | Callback invoked with each finding's audit entry. During a run it is called from a worker thread. |
| `max_scan_chars` | `10_000` | Longest value scanned in full. A longer value is scanned as its first and last halves of this size, and the decision reports `truncated: true`. `None` scans everything. |
| `rules_dir` | bundled rules | Load rules from a directory, such as a checkout of this repository. |
| `engine` | `None` | Share one loaded `pyatr.ATREngine` across several guards. |

Every finding is appended to `guard.audit_log` as
`{where, tool, rule, title, severity, maturity}`. The same summary is attached as each
guardrail's `output_info`, so it appears in the SDK's traces.

You can also call `check_tool_call`, `check_tool_output`, `check_input` and
`check_output` directly; each returns an `ATRDecision`.

## Limits

- **Function tools only.** The SDK does not run tool guardrails for hosted
  tools (web search, file search, code interpreter, hosted MCP, image
  generation), built-in execution tools (computer, shell, apply-patch, local
  shell), or handoffs. `protect()` returns those unchanged.
- **Input guardrails cover the first agent only.** The SDK runs input
  guardrails only for the first agent in a run. Tool guardrails apply on every
  agent whose tools you protect.
- **Scan time grows with input length.** With every rule loaded, pyatr took
  about 0.4 s on 2,000 characters, 5 s on 20,000 and roughly 5 minutes on
  200,000. That is why `max_scan_chars` defaults to 10,000. Scans run in a
  worker thread, so a slow check does not block other work on the event loop,
  but the run itself still waits for it. Text in the middle of a clipped value
  is not scanned; `truncated` in the decision and in `output_info` tells you
  when that happened.
- **The audit log grows without bound.** In a long-lived process, read and
  clear `guard.audit_log`, or use `on_flag` instead.
- **Pattern matching.** pyatr is ATR's pattern engine. Detection is
  deterministic, but it catches known phrasings better than paraphrases. See
  [`LIMITATIONS.md`](../../LIMITATIONS.md).

## Tests

```bash
pip install "pyatr>=0.4.1" openai-agents pytest pyyaml
pytest integrations/openai-agents/tests
```

The attack payloads come from the rules' own `test_cases` fixtures, so this
integration carries no attack strings of its own. One test drives a real
`Runner` with a scripted model and checks that a blocked tool never executes.
