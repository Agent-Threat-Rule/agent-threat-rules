# Changelog

## 0.1.0

Initial release.

- Scan-on-save and scan-on-open for agent configuration files
  (SKILL.md, .mcp.json, mcp.json, claude_desktop_config.json,
  .cursorrules, CLAUDE.md, AGENTS.md, agents.md).
- Findings published as diagnostics in the Problems panel with rule id,
  title, and remediation message.
- Commands: `ATR: Scan Current File`, `ATR: Scan Workspace`.
- Status bar item with last scan result; click to rescan current file.
- Settings: `atrScan.enabled`, `atrScan.minSeverity`,
  `atrScan.filePatterns`.
- Bundles the full ATR rule set from agent-threat-rules 3.3.x; all
  scanning is local.
