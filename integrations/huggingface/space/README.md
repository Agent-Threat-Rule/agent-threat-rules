---
title: ATR Agent Threat Scanner
emoji: 🛡️
colorFrom: indigo
colorTo: blue
sdk: gradio
app_file: app.py
pinned: false
license: mit
short_description: Scan agent artifacts against Agent Threat Rules (ATR)
tags:
  - agent-security
  - prompt-injection
  - mcp
  - detection
---

# ATR Agent Threat Scanner

A live demo of [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules) — an open, vendor-neutral detection standard for AI agents. Like Sigma, but for prompt injection, tool poisoning, MCP attacks and skill compromise.

Paste an agent artifact (a user prompt, a tool call/response, an MCP tool description, or a `SKILL.md`), pick the event type, and see which ATR rules fire, with severity and confidence.

The demo runs the [`pyatr`](https://pypi.org/project/pyatr/) reference engine in-process using the rules bundled in the package — no network calls, no data leaves the Space.

## Links

- Standard and rules: https://github.com/Agent-Threat-Rule/agent-threat-rules
- Python engine: https://pypi.org/project/pyatr/
- Paper (Zenodo): https://doi.org/10.5281/zenodo.19178002

## License

MIT — same as the ATR standard.
