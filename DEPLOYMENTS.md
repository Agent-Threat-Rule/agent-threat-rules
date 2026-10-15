# ATR Deployment Reports

Known deployments of Agent Threat Rules (ATR) in production or staging environments.

This file tracks real-world usage to validate rule effectiveness, surface false positives, and guide future rule development.

---

## 1. Guard Integration (Self-Dogfood)

| Field | Value |
|-------|-------|
| **Deployer** | ATR Community |
| **Framework** | Node.js Guard v0.2.x |
| **Integration method** | npm library (`agent-threat-rules` via custom `GuardATREngine` wrapper) |
| **Rules loaded** | 61 rules (44 experimental + 17 draft) across 9 categories |
| **Since** | v0.2.0 |
| **Status** | Active |

### Integration Architecture

The Guard wraps the ATR engine in a `GuardATREngine` class that bridges ATR with a four-stage detection pipeline:

```
SecurityEvent
  -> ATR Layer 1 (regex pattern matching, 61 rules)
  -> DetectAgent (merge ATR matches with Sigma/YARA detections)
  -> AnalyzeAgent (LLM triage for complex cases; skipped for whitelisted skills)
  -> RespondAgent (action execution: block_tool, kill_agent, quarantine_session, revoke_skill, reduce_permissions)
  -> ReportAgent (notification, Threat Cloud sync, dashboard)
```

### Rule Loading

Rules are loaded from two sources at startup:

1. **Bundled rules** -- shipped with the npm package (61 rules)
2. **Cloud rules** -- fetched from a community threat feed and added via `addCloudRule()` (community-contributed)

Hot-reload is enabled for local custom rules.

### Session Tracking

The `SessionTracker` correlates events across agent sessions, enabling behavioral detection rules that span multiple events. Sessions idle for 30+ minutes are automatically evicted.

### Skill Fingerprinting and Whitelist

The integration includes a `SkillFingerprintStore` that tracks tool invocation patterns. When a skill's fingerprint stabilizes (consistent behavior over time), it is auto-promoted to the whitelist. If behavioral drift is detected post-promotion, the skill is automatically revoked from the whitelist and a synthetic `ATR-DRIFT-DETECT` match enters the detection pipeline.

### ATR-Specific Response Actions

Five ATR response actions are implemented:

- `block_tool` -- prevent tool invocation
- `kill_agent` -- terminate agent process (SIGTERM, fallback SIGKILL)
- `quarantine_session` -- isolate session, write quarantine marker
- `revoke_skill` -- remove skill from whitelist
- `reduce_permissions` -- restrict session capabilities (deny_write, deny_exec, deny_network)

### Observations

- ATR rules run synchronously on every security event; latency is negligible for 61 rules.
- Rule matches merge cleanly with Sigma/YARA detections in a unified `DetectionResult`.
- Whitelisted skills with no ATR matches skip LLM analysis, reducing cost and latency.
- Cloud rule sync runs on a 1-hour interval, adding new ATR rules without restart.

---

## 2. Batch Skill Audit

| Field | Value |
|-------|-------|
| **Deployer** | ATR Community |
| **Framework** | ATR Skill Auditor (Node.js, batch mode) |
| **Integration method** | Direct ATR engine evaluation |
| **Rules loaded** | 61 rules |
| **Date** | 2026-03-14 |
| **Status** | Completed |

### Scan Summary

| Metric | Value |
|--------|-------|
| Skills/commands/agents scanned | 97 |
| CRITICAL findings | 1 |
| HIGH findings | 15 |
| MEDIUM findings | 66 |
| LOW findings | 15 |
| Auto-whitelisted skills | 15 |

### Methodology

All 97 skills were evaluated against the full ATR rule set. Each skill's declared capabilities, permission requests, and behavioral patterns were converted to `AgentEvent` format and run through Layer 1 regex detection.

Skills that passed all checks with zero findings were candidates for auto-whitelist promotion based on fingerprint stability.

### Findings Distribution

- The single CRITICAL finding involved a skill requesting unrestricted filesystem and network access with no declared scope.
- HIGH findings were concentrated in the `privilege-escalation` and `excessive-autonomy` categories.
- MEDIUM findings were primarily informational scope warnings.
- LOW findings flagged minor hygiene issues (e.g., overly broad tool descriptions).

---

## 3. Cisco AI Defense skill-scanner

| Field | Value |
|-------|-------|
| **Deployer** | Cisco AI Defense |
| **Framework** | cisco-ai-defense/skill-scanner |
| **Integration method** | ATR community rule pack shipped as first-party rules |
| **Rules loaded** | ATR community rule pack (subset of ATR detection rules) |
| **Since** | 2026-04-03 |
| **Status** | Merged to main |
| **Reference** | [PR #79](https://github.com/cisco-ai-defense/skill-scanner/pull/79) |

---

## 4. Microsoft Agent Governance Toolkit

| Field | Value |
|-------|-------|
| **Deployer** | Microsoft |
| **Framework** | microsoft/agent-governance-toolkit — examples |
| **Integration method** | Example directories: an ACS annotator adapter and an ATR-to-ACS manifest import example |
| **Rules loaded** | No ATR rule files are committed in the repository. The annotator example runs the rule set bundled in its optional `pyatr` dependency; the import example compiles an ATR rules directory supplied by the user. The rule-pack YAML from the earlier example PRs was removed upstream on 2026-07-30 (AGT PR #3451). |
| **Since** | 2026-04-13 (first example PR) |
| **Status** | Examples merged to main |
| **Reference** | [PR #3025](https://github.com/microsoft/agent-governance-toolkit/pull/3025) · [PR #2308](https://github.com/microsoft/agent-governance-toolkit/pull/2308) · [PR #908](https://github.com/microsoft/agent-governance-toolkit/pull/908) |

---

## 5. OWASP Agentic AI Top 10 (precize)

| Field | Value |
|-------|-------|
| **Deployer** | precize / OWASP community |
| **Framework** | precize/Agentic-AI-Top10-Vulnerability |
| **Integration method** | ATR detection rule mapping for 12 vulnerability categories |
| **Rules loaded** | Cross-referenced mapping (full ATR rule set) |
| **Since** | 2026-03-30 |
| **Status** | Merged to main |
| **Reference** | [PR #14](https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14) |

---

## Submit a Deployment Report

If you are using ATR rules in your project, we welcome deployment reports. They help us:

- Validate rule effectiveness across diverse frameworks
- Identify false positives and coverage gaps
- Prioritize new rule development based on real-world usage

### How to Submit

1. Open an issue using the **Deployment Report** template: [Submit Report](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=deployment-report.yml)
2. Include at minimum:
   - Framework name and language
   - Integration method (npm, YAML loader, API, etc.)
   - Number of rules loaded
   - Any false positives or missed detections observed
3. Optionally, submit a PR to add your deployment to this file.

### Template

```markdown
## [Your Project Name]

| Field | Value |
|-------|-------|
| **Deployer** | [Organization or individual] |
| **Framework** | [Framework name and version] |
| **Integration method** | [npm / YAML parser / REST API / MCP / etc.] |
| **Rules loaded** | [Number] |
| **Since** | [Version or date] |
| **Status** | [Active / Testing / Deprecated] |

### Integration Notes
[How ATR rules are loaded and evaluated in your system]

### Observations
[False positives, missed detections, performance notes, etc.]
```

---

## Deployment Count

| # | Project | Method | Rules | Status |
|---|---------|--------|-------|--------|
| 1 | Guard Integration | npm (`agent-threat-rules`) | 61 | Active |
| 2 | Batch Skill Audit | Direct engine | 61 | Completed |
| 3 | Cisco AI Defense skill-scanner | First-party rule pack | ATR community pack | Merged 2026-04-03 |
| 4 | Microsoft Agent Governance Toolkit | Example directories | None shipped | Examples merged 2026-04-13 onward |
| 5 | OWASP Agentic AI Top 10 (precize) | Mapping reference | Full rule set | Merged 2026-03-30 |

## Ecosystem References (documentation listings)

ATR is also listed as a detection standard in these community resources:

- [CryptoAILab/Awesome-LM-SSP PR #108](https://github.com/CryptoAILab/Awesome-LM-SSP/pull/108) (merged 2026-04-02)
- [wearetyomsmnv/Awesome-LLM-agent-Security PR #6](https://github.com/wearetyomsmnv/Awesome-LLM-agent-Security/pull/6) (merged 2026-04-08)
- [nibzard/awesome-agentic-patterns PR #58](https://github.com/nibzard/awesome-agentic-patterns/pull/58) (merged 2026-04-09)
- [TalEliyahu/Awesome-AI-Security PR #53](https://github.com/TalEliyahu/Awesome-AI-Security/pull/53) (merged 2026-04-10)
