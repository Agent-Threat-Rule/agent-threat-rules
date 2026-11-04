# ATR integration for goose

Reports tool calls that match ATR detection rules inside [goose](https://github.com/aaif-goose/goose) using the `PreToolUse` hook, and, when you turn blocking on, blocks the ones that match stable rules.

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

The `PreToolUse` hook reads the tool name and input from stdin as a `HookContext` JSON blob, scans the stringified `tool_input` with `pyatr`, and prints every match to stderr.

**Advisory by default**: the hook exits 0 and the tool call runs. Set `ATR_BLOCKING=1` (or `true` / `yes` / `on`) in the environment goose runs hooks in to turn blocking on; the hook then exits 2 (block) only for a `critical` or `high` match from a rule with `maturity: stable` (the ATR enforce lane). Matches from rules of lower maturity are printed and never block. Earlier versions exited 2 by default on any `critical` or `high` match, experimental rules included.

Any scanner error (import failure, timeout, parse error) exits 0 — a broken guard must never block legitimate work. An unrecognised `ATR_BLOCKING` value is reported on stderr and read as off. Blocking needs `pyatr>=0.4.1`, whose matches carry the rule maturity.

## What it detects

| Category | Example |
|---|---|
| Prompt injection | Instructions embedded in tool responses to override agent behaviour |
| Tool poisoning | MCP tool descriptions that hijack agent goals |
| Credential exfiltration | Tool calls attempting to read and send `.env` or SSH keys |
| Privilege escalation | Commands requesting elevated system access |

Full rule list: [Agent-Threat-Rule/agent-threat-rules/rules](https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/rules)

## Configuration

`ATR_BLOCKING` is the only switch. The blocking threshold is fixed at `high`/`critical` from stable rules, the same rule every ATR integration blocks on. Tests: `pytest integrations/goose/tests`.
