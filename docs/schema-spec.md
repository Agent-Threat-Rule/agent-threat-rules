# ATR Schema Specification — SUPERSEDED

> **STATUS: SUPERSEDED 2026-05-16**. The normative specification is now
> [`SPEC.md`](../SPEC.md) v1.0.0 (Draft). The canonical machine-readable
> schema remains [`spec/atr-schema.yaml`](../spec/atr-schema.yaml). This
> document is retained for historical context and MUST NOT be cited as
> normative.

This document defines every field in the ATR (Agent Threat Rules) schema. The canonical schema file is `spec/atr-schema.yaml`.

---

## Document Structure

An ATR rule is a single YAML document. The top-level structure:

```yaml
# Metadata
title: string          # required
id: string             # required, format: ATR-YYYY-NNN
status: string         # required, enum
description: string    # required
author: string         # required
date: string           # required, format: YYYY/MM/DD
modified: string       # optional, format: YYYY/MM/DD
schema_version: string # required

# Classification
detection_tier: string # required, enum
maturity: string       # required, enum
severity: string       # required, enum

# References
references: object     # optional

# Tags
tags: object           # required

# Agent Source
agent_source: object   # required

# Detection
detection: object      # required

# Response
response: object       # required

# Test Cases
test_cases: object     # optional (required for PR acceptance)

# Evasion Tests
evasion_tests: array   # optional
```

---

## Metadata Fields

### title

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Description | Human-readable rule name. Should describe what the rule detects, not the attack category |
| Example | `"Direct Prompt Injection via User Input"` |

### id

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Pattern | `^ATR-\d{4}-\d{3}$` |
| Description | Unique rule identifier. Format: `ATR-YYYY-NNN` where YYYY is the year and NNN is a sequential number. Use a placeholder for drafts; maintainers assign final IDs |
| Example | `"ATR-2026-001"` |

### status

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Enum | `draft`, `experimental`, `stable`, `deprecated` |
| Description | Rule lifecycle status |

Status meanings:

| Status | Meaning |
|--------|---------|
| `draft` | Work in progress, not ready for testing |
| `experimental` | New rule, may have high false positive rate |
| `stable` | Validated in production, reliable detection |
| `deprecated` | Replaced or no longer relevant |

### description

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Description | Detailed description of the attack this rule detects. Should explain what IS detected and what IS NOT detectable by this rule. Use YAML `\|` for multi-line |
| Example | `"Detects direct prompt injection attempts where a user embeds malicious instructions. Note: Cannot detect paraphrased attacks."` |

### author

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Description | Rule author name, handle, or organization |
| Example | `"ATR Community"`, `"@security_researcher"` |

### date

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Pattern | `^\d{4}/\d{2}/\d{2}$` |
| Description | Creation date |
| Example | `"2026/03/11"` |

### modified

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | No |
| Pattern | `^\d{4}/\d{2}/\d{2}$` |
| Description | Last modification date |
| Example | `"2026/03/15"` |

### schema_version

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Description | ATR schema version this rule conforms to |
| Example | `"0.1"` |

---

## Classification Fields

### detection_tier

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Enum | `pattern`, `behavioral`, `protocol` |

| Tier | Description | Detection Method |
|------|-------------|-----------------|
| `pattern` | Regex-based pattern matching on text content | String operators: `regex`, `contains`, `exact`, `starts_with` |
| `behavioral` | Threshold-based detection on agent metrics | Numeric operators: `gt`, `lt`, `eq`, `gte`, `lte`, `deviation_from_baseline` |
| `protocol` | Multi-step sequence detection across events | Ordered/unordered step sequences within time windows |

### maturity

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Enum | `experimental`, `test`, `stable`, `deprecated` |

| Maturity | Meaning |
|----------|---------|
| `experimental` | New rule, limited testing |
| `test` | Validated against test cases, not yet production-proven |
| `stable` | Production-validated, low false positive rate |
| `deprecated` | Superseded or no longer applicable |

### severity

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Enum | `critical`, `high`, `medium`, `low`, `informational` |

See the rule writing guide for severity calibration criteria.

---

## References

| Property | Value |
|----------|-------|
| Type | `object` |
| Required | No (but required for PR acceptance) |

### references.owasp_llm

| Property | Value |
|----------|-------|
| Type | `array` of `string` |
| Description | OWASP LLM Top 10 (2025) references |
| Example | `["LLM01:2025"]` |

### references.owasp_agentic

| Property | Value |
|----------|-------|
| Type | `array` of `string` |
| Description | OWASP Top 10 for Agentic Applications (2026) references |
| Example | `["ASI01:2026"]` |

### references.mitre_atlas

| Property | Value |
|----------|-------|
| Type | `array` of `string` |
| Description | MITRE ATLAS technique IDs |
| Example | `["AML.T0051 - LLM Prompt Injection"]` |

### references.mitre_attack

| Property | Value |
|----------|-------|
| Type | `array` of `string` |
| Description | MITRE ATT&CK technique IDs (when traditional attack techniques apply) |
| Example | `["T1059 - Command and Scripting Interpreter"]` |

### references.cve

| Property | Value |
|----------|-------|
| Type | `array` of `string` |
| Description | Related CVE identifiers |
| Example | `["CVE-2025-53773", "CVE-2025-32711"]` |

---

## Tags

| Property | Value |
|----------|-------|
| Type | `object` |
| Required | Yes |

### tags.category

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Enum | See below |

| Category | Description |
|----------|-------------|
| `prompt-injection` | User/external input overrides agent instructions |
| `tool-poisoning` | Tool responses contain malicious content |
| `context-exfiltration` | Agent leaks system prompt, API keys, or internal data |
| `agent-manipulation` | One agent manipulates another agent's behavior |
| `privilege-escalation` | Agent accesses resources beyond authorized scope |
| `excessive-autonomy` | Agent operates beyond intended boundaries |
| `data-poisoning` | Training or retrieval data has been tampered with |
| `model-abuse` | Model weights, behavior, or training pipeline are targeted |
| `skill-compromise` | MCP skills/tools are impersonated, hijacked, or over-permissioned |

### tags.subcategory

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | No |
| Description | More specific classification within the category. Free-form string |
| Example | `"direct"`, `"indirect"`, `"mcp-response"`, `"system-prompt"` |

### tags.confidence

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | No |
| Enum | `high`, `medium`, `low` |
| Description | Expected accuracy. `high` = low false positive rate |

---

## Agent Source

| Property | Value |
|----------|-------|
| Type | `object` |
| Required | Yes |

Defines what kind of agent data this rule inspects. Analogous to Sigma's `logsource`.

### agent_source.type

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Enum | See below |

| Type | Description | Typical Fields |
|------|-------------|---------------|
| `llm_io` | LLM input/output text | `user_input`, `agent_output` |
| `tool_call` | Tool/function invocations | `tool_name`, `tool_args` |
| `mcp_exchange` | MCP protocol messages | `tool_response` |
| `agent_behavior` | Agent behavioral metrics | metrics (numeric) |
| `multi_agent_comm` | Inter-agent communication | `agent_message`, `content` |
| `context_window` | Context window contents | `content` |
| `memory_access` | Agent memory operations | `content` |
| `skill_lifecycle` | Skill install/update/remove events | `content`, `tool_name` |
| `skill_permission` | Skill permission requests | `content`, `tool_name` |
| `skill_chain` | Multi-skill execution sequences | `content`, `tool_name` |

### agent_source.framework

| Property | Value |
|----------|-------|
| Type | `array` of `string` |
| Required | No |
| Description | AI frameworks this rule applies to |
| Example | `["langchain", "crewai", "autogen", "any"]` |

### agent_source.provider

| Property | Value |
|----------|-------|
| Type | `array` of `string` |
| Required | No |
| Description | LLM providers this rule applies to |
| Example | `["openai", "anthropic", "ollama", "any"]` |

---

## Detection

| Property | Value |
|----------|-------|
| Type | `object` |
| Required | Yes |

### detection.conditions (Array Format)

| Property | Value |
|----------|-------|
| Type | `array` of condition objects |

Each condition object:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `field` | `string` | Yes | Field to inspect (`user_input`, `agent_output`, `tool_name`, `tool_args`, `tool_response`, `content`, `agent_message`) |
| `operator` | `string` | Yes | Match operator: `regex`, `contains`, `exact`, `starts_with` |
| `value` | `string` | Yes | Pattern to match. For `regex` operator, this is a regex string |
| `description` | `string` | No | Human-readable description of what this condition detects |

Example:

```yaml
conditions:
  - field: user_input
    operator: regex
    value: "(?i)\\bignore\\b\\s+\\bprevious\\b"
    description: "Ignore-previous-instructions pattern"
```

### detection.conditions (Named-Map Format)

| Property | Value |
|----------|-------|
| Type | `object` (string keys to condition blocks) |

Each named condition block can be one of:

**Pattern condition:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `field` | `string` | Yes | Field to inspect |
| `patterns` | `array` of `string` | Yes | Patterns to match |
| `match_type` | `string` | Yes | `contains`, `regex`, `exact`, `starts_with` |
| `case_sensitive` | `boolean` | No | Default: `false` |

**Behavioral condition:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `metric` | `string` | Yes | Behavioral metric name (`tool_call_frequency`, `pattern_frequency`, `event_count`, etc.) |
| `operator` | `string` | Yes | `gt`, `lt`, `eq`, `gte`, `lte`, `deviation_from_baseline` |
| `threshold` | `number` | Yes | Numeric threshold value |
| `window` | `string` | No | Time window (e.g., `"5m"`, `"1h"`, `"30s"`) |

**Sequence condition:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ordered` | `boolean` | Yes | Whether steps must occur in order |
| `within` | `string` | Yes | Maximum time span for the full sequence (e.g., `"10m"`) |
| `steps` | `array` of step objects | Yes | Ordered list of conditions forming the attack sequence |

Each step object:

| Field | Type | Description |
|-------|------|-------------|
| `field` | `string` | Field to inspect |
| `patterns` | `array` of `string` | Patterns to match |
| `match_type` | `string` | Match operator |
| `metric` | `string` | Behavioral metric (for threshold steps) |
| `operator` | `string` | Comparison operator |
| `threshold` | `number` | Numeric threshold |

### detection.condition

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | Yes |
| Description | How to combine conditions |

For array format:

| Value | Meaning |
|-------|---------|
| `any` or `or` | Trigger if ANY condition matches |
| `all` or `and` | Trigger only if ALL conditions match |

For named-map format: Boolean expression referencing condition names.

```yaml
condition: "pattern_match AND (frequency_check OR sequence_detect)"
```

### detection.false_positives

| Property | Value |
|----------|-------|
| Type | `array` of `string` |
| Required | No |
| Description | Known scenarios that may trigger false positives |
| Example | `["Security researchers testing defenses", "Users discussing prompt injection as a topic"]` |

---

## Response

| Property | Value |
|----------|-------|
| Type | `object` |
| Required | Yes |

### response.actions

| Property | Value |
|----------|-------|
| Type | `array` of `string` |
| Required | Yes |
| Enum values | See below |

| Action | Description |
|--------|-------------|
| `block_input` | Reject the user/agent input |
| `block_output` | Suppress the agent output |
| `block_tool` | Prevent the tool call from executing |
| `quarantine_session` | Isolate the entire session |
| `reset_context` | Clear agent context/memory |
| `alert` | Send alert to security team |
| `snapshot` | Capture full session state for forensics |
| `escalate` | Escalate to human reviewer |
| `reduce_permissions` | Reduce agent's available tools/capabilities |
| `kill_agent` | Terminate the agent process |

### response.auto_response_threshold

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | No |
| Enum | `low`, `medium`, `high`, `critical` |
| Description | Severity threshold for automatic response. Below this threshold, only alert; above, execute all response actions |

### response.message_template

| Property | Value |
|----------|-------|
| Type | `string` |
| Required | No |
| Description | Template for alert messages |

Supported placeholders:

| Placeholder | Description |
|-------------|-------------|
| `{matched_pattern}` | The pattern that triggered the match |
| `{truncated_input}` | First N characters of the input |
| `{truncated_output}` | First N characters of the output |
| `{source_ip_or_user}` | Source identifier |
| `{tool_name}` | Name of the tool involved |
| `{mcp_server_url}` | MCP server URL |
| `{rule_id}` | The ATR rule ID |
| `{severity}` | The rule's severity level |
| `{session_id}` | Session identifier |

---

## Test Cases

| Property | Value |
|----------|-------|
| Type | `object` |
| Required | No (but required for PR acceptance) |

### test_cases.true_positives

| Property | Value |
|----------|-------|
| Type | `array` of test case objects |

Each test case:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `input` | `string` | Conditional | User input text. Required for `llm_io` rules. Can also be an object with `tool_name`, `tool_args`, `response` fields for tool-based rules |
| `tool_response` | `string` | Conditional | Tool/MCP response text. Required for `mcp_exchange` rules |
| `agent_output` | `string` | Conditional | Agent output text |
| `tool_name` | `string` | No | Tool name for `tool_call` rules |
| `tool_args` | `string` | No | Tool arguments |
| `expected` | `string` | Yes | Must be `"triggered"` |
| `description` | `string` | No | Why this test case should trigger |

### test_cases.true_negatives

Same structure as `true_positives`, except `expected` must be `"not_triggered"`.

---

## Evasion Tests

| Property | Value |
|----------|-------|
| Type | `array` of evasion test objects |
| Required | No |

Each evasion test:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `input` | `string` | Yes | The evasion attempt input |
| `expected` | `string` | Yes | `"triggered"` or `"not_triggered"` |
| `bypass_technique` | `string` | Yes | Technique name: `paraphrase`, `language_switch`, `indirect_reference`, `encoding`, `social_engineering`, `fictional_framing` |
| `notes` | `string` | No | Why this evasion works or does not work |

---

## Complete Minimal Example

```yaml
title: "Example Detection Rule"
id: ATR-2026-999
status: experimental
description: |
  Minimal example demonstrating all required fields.
author: "ATR Community"
date: "2026/03/11"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: medium

references:
  owasp_llm:
    - "LLM01:2025"

tags:
  category: prompt-injection
  confidence: medium

agent_source:
  type: llm_io

detection:
  conditions:
    - field: user_input
      operator: regex
      value: "(?i)\\bexample\\s+attack\\s+pattern\\b"
  condition: any
  false_positives:
    - "Legitimate use of the phrase 'example attack pattern' in documentation"

response:
  actions: [alert]

test_cases:
  true_positives:
    - input: "This is an example attack pattern for testing"
      expected: triggered
  true_negatives:
    - input: "Normal conversation without attack indicators"
      expected: not_triggered
```
