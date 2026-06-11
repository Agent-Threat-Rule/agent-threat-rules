# ATR Scan

Scans agent configuration files for known threat patterns using
[Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
(ATR), an open detection rule standard for AI agent security. Findings
show up in the Problems panel.

## What it scans

On open and on save, files matching these patterns (configurable):

- `**/SKILL.md`
- `**/.mcp.json`, `**/mcp.json`
- `**/claude_desktop_config.json`
- `**/.cursorrules`
- `**/CLAUDE.md`
- `**/AGENTS.md`, `**/agents.md`

Two commands are also available from the Command Palette:

- `ATR: Scan Current File` - scans whatever file is open, regardless of
  pattern. Also bound to the status bar item.
- `ATR: Scan Workspace` - scans every file in the workspace matching the
  configured patterns (node_modules excluded).

## What it reports

Each finding is a diagnostic in the form `[<rule id>] <rule title>`,
plus the rule's remediation message when one exists. The rule id is also
set as the diagnostic code. Severity mapping:

| ATR severity | VS Code severity |
|---|---|
| critical, high | Error |
| medium | Warning |
| low, informational | Information |

The extension ships the full ATR rule set (the `rules/` tree from the
`agent-threat-rules` npm package) inside the extension package. Scanning
runs entirely locally. Nothing is uploaded anywhere.

## What it does NOT do

- ATR rules are signature-based pattern detection. A clean scan is not a
  guarantee that a file is safe; novel or obfuscated attacks can evade
  pattern matching. Known evasion techniques are documented in the ATR
  repository (LIMITATIONS.md).
- It does not block saves, quarantine files, or modify anything. It only
  reports diagnostics.
- It does not scan runtime agent traffic. This is static file scanning
  only. For runtime evaluation use the `agent-threat-rules` engine API
  directly.

## Settings

| Setting | Default | Description |
|---|---|---|
| `atrScan.enabled` | `true` | Scan automatically on open and save. |
| `atrScan.minSeverity` | `medium` | Minimum rule severity reported (`critical`, `high`, `medium`, `low`, `informational`). |
| `atrScan.filePatterns` | see above | Glob patterns for automatic scanning. |

## Development

```
cd editors/vscode
npm install
npm test          # bundle + headless engine smoke test
npm run package   # produce the .vsix
```

Rules are copied from `node_modules/agent-threat-rules/rules` into
`dist/rules` at build time; the engine loads them from there at runtime.

## License

MIT
