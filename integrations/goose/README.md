# ATR integration for goose

Blocks tool calls that match ATR detection rules inside [goose](https://github.com/aaif-goose/goose) using the `PreToolUse` hook.

433 rules across prompt injection, tool poisoning, credential exfiltration, and 9 other AI agent attack categories.

## Requirements

```
pip install pyatr
```

## Install

```
goose plugin install https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/integrations/goose
```

Or locally:

```
git clone https://github.com/Agent-Threat-Rule/agent-threat-rules
goose plugin install ./agent-threat-rules/integrations/goose
```

## How it works

The `PreToolUse` hook reads the tool name and input from stdin as a `HookContext` JSON blob, scans the stringified `tool_input` with `pyatr`, and exits 2 (block) on any `critical` or `high` severity match. Any scanner error (import failure, timeout, parse error) exits 0 — a broken guard must never block legitimate work.

## What gets blocked

| Category | Example |
|---|---|
| Prompt injection | Instructions embedded in tool responses to override agent behaviour |
| Tool poisoning | MCP tool descriptions that hijack agent goals |
| Credential exfiltration | Tool calls attempting to read and send `.env` or SSH keys |
| Privilege escalation | Commands requesting elevated system access |

Full rule list: [Agent-Threat-Rule/agent-threat-rules/rules](https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/rules)

## Configuration

Adjust `_BLOCK_SEVERITIES` in `scripts/atr_scan.py` to tune which severity levels trigger a block (default: `critical`, `high`).
