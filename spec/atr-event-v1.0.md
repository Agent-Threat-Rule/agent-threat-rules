# ATR Event Format v1.0 — OpenTelemetry-aligned

> **STATUS: PROPOSED v1.0 — NOT YET RATIFIED.** This specification describes
> a target event format for community comment. The current TypeScript production
> engine continues to emit its existing event shape. Adopters should NOT
> migrate to this format until ratification. See `STANDARDIZATION-STATUS.md`
> for full status.

**Status:** Draft for AEP-002 ratification — NOT RATIFIED
**Date:** 2026-05-25
**License:** MIT
**Required by (on ratification):** Conformant engine output, downstream SIEM/SOAR ingestion, EU AI Act Article 50 evidence chains

---

## Purpose

When a conformant ATR engine fires a rule, it emits an **event**.
This document specifies the event format.

Three requirements forced the design:

1. **OpenTelemetry alignment.** Existing agent-observability stacks
   (LangSmith, Logfire, Datadog APM, Honeycomb) already ingest OTEL
   spans. An ATR event that maps cleanly into an OTEL span attribute
   set is consumable by these stacks zero-modification.

2. **EU AI Act Article 50 evidence.** Article 50 obligations (apply
   2 August 2026) require deployer-side evidence of AI interaction.
   ATR events must carry sufficient identity + provenance + signature
   data to land in an audit binder without supplementary munging.

3. **NIST AI RMF MEASURE function.** OSCAL assessment-result format
   requires structured observation records. ATR events must be
   one-to-one mappable to OSCAL `observation` entries so audit
   pipelines (AWS Config, RegScale, Centraleyes) can ingest natively.

---

## Event JSON Schema reference

Machine-readable schema: `spec/schema/event.schema.json`.

This document is the normative prose specification. In case of
discrepancy between the two, **the prose spec governs**; the JSON
Schema must be corrected to match (via AEP).

---

## Required fields

All conformant engines MUST emit these fields on every event.

### Identification

| Field | Type | Description |
|---|---|---|
| `@timestamp` | RFC 3339 UTC string | When the rule fired. |
| `atr.event_id` | UUID v7 (time-ordered) | Globally unique event identifier. |
| `atr.spec_version` | string | ATR spec version this event conforms to. v1.0 = `"1.0"`. |
| `atr.engine_id` | string | Identifier of the engine that produced the event. Format: `<vendor>/<product>/<version>`. Example: `atr/typescript-reference/3.1.0`, `cisco/ai-defense/2.4.1`, `microsoft/agent-governance-toolkit/2026.05`. |

### Rule attribution

| Field | Type | Description |
|---|---|---|
| `atr.rule_id` | string | The matched rule ID. Format per ATR Rule Format Spec § 2: `ATR-YYYY-NNNNN` for canonical rules, `ATR-XX-YYYY-NNNNN` for sovereign-prefixed rules. |
| `atr.rule_version` | integer | The `rule_version` field from the matched rule's YAML. |
| `atr.rule_status` | enum | `draft` / `experimental` / `stable` / `deprecated` per rule's `status` field. |
| `atr.rule_maturity` | enum | `draft` / `test` / `stable` per rule's `maturity` field. |
| `atr.rule_review_status` | enum | `unreviewed` / `community_reviewed` / `tsc_approved` per governance/CHARTER.md § 5. |

### Detection result

| Field | Type | Description |
|---|---|---|
| `atr.severity` | enum | `critical` / `high` / `medium` / `low` / `informational` from matched rule. |
| `atr.category` | string | Rule's top-level category from `spec/category-registry/v1.0.yaml`, OR `unknown` if engine encountered unregistered category (per forward-compatibility rule). |
| `atr.subcategory` | string \| null | Optional finer classification from rule's `tags.subcategory`. |
| `atr.confidence` | number 0.0-1.0 | Engine's confidence in the match. For deterministic regex matches: `1.0`. For probabilistic / ML-judge matches (future): per the rule's declared semantics. |
| `atr.matched_field` | enum | Which field triggered the match. One of: `user_input`, `agent_output`, `tool_call`, `tool_response`, `skill_content`, `mcp_exchange`, `memory_write`, `multi_agent_message`. |
| `atr.matched_value_redacted` | string | The matched portion of the input. **MUST be redacted by default** — sensitive content (api keys, PII) replaced with `[REDACTED:type:length]`. Engines MAY disable redaction in `forensic_mode`, which MUST be explicitly enabled per deployment. |

### Agent + session context

| Field | Type | Description |
|---|---|---|
| `agent.id` | string | Stable identifier of the agent instance. |
| `agent.platform` | string | Agent platform name. Common values: `claude_code`, `cursor`, `openclaw`, `codex_cli`, `windsurf`, `gemini_cli`, `cline`, `continue`, `langchain`, `autogen`, `crewai`. Engines SHOULD use this canonical set; unknown values are accepted. |
| `agent.platform_version` | string \| null | Version of the agent platform. |
| `session.id` | string | Stable identifier of the agent session. |
| `service.name` | string | OTEL semantic convention. The service that hosts the agent. |
| `service.version` | string | OTEL semantic convention. |

### Response

| Field | Type | Description |
|---|---|---|
| `atr.response_action` | array of enum | Recommended response actions from rule's `response.actions`. Subset of: `block_input`, `block_output`, `redact`, `alert`, `snapshot`, `quarantine`, `terminate_session`. |
| `atr.response_taken` | array of enum | What the engine / agent platform actually did. May differ from recommended if local policy overrides. |
| `atr.response_threshold_met` | boolean | Whether the rule's `auto_response_threshold` was met. |

### Evidence + provenance

| Field | Type | Description |
|---|---|---|
| `evidence.observation_id` | UUID | Identifier for cross-reference into OSCAL `observation` records. Same as `atr.event_id` recommended unless an existing system has its own. |
| `evidence.signature` | base64 ed25519 | Signature over the canonical JSON encoding of this event. Signed by the engine's deployment-time key. Required for EU AI Act Article 50 evidence chains and NIST AI RMF audit pipelines. May be omitted in `dev_mode` deployments. |
| `evidence.signature_key_id` | string | Identifier of the signing key. SHOULD reference a key registered with the deployer's CA. |
| `evidence.upstream_chain` | array \| null | When this event is part of a multi-agent chain (A2A), the upstream event IDs that led to this detection. Enables forensic chain reconstruction. |

## Optional fields

### Tool call detail (when `atr.matched_field == "tool_call"` or `"tool_response"`)

| Field | Type |
|---|---|
| `tool.name` | string |
| `tool.args` | object (redacted) |
| `tool.privilege_class` | string |
| `tool.target_jurisdiction` | ISO 3166-1 alpha-2 \| `und` |

The `tool.target_jurisdiction` field is for EU AI Act + GDPR cross-
border data-flow audit. Required when the engine knows where the
tool's effect lands (e.g., an `s3.put` tool call where bucket region
is known).

### Multi-agent chain detail (when `atr.matched_field == "multi_agent_message"`)

| Field | Type |
|---|---|
| `agent.from_id` | string |
| `agent.to_id` | string |
| `agent.delegation_chain` | array of {agent_id, capability_grant, granted_by} |
| `agent.identity_assertion` | JWT \| null |

The `agent.identity_assertion` field anticipates the IETF AI agent
auth drafts (`draft-klrc-aiagent-auth-00`, `draft-ni-a2a-ai-agent-
security-requirements-01`) — once those reach RFC, the field carries
the canonical assertion format.

### Memory write detail (when `atr.matched_field == "memory_write"`)

| Field | Type |
|---|---|
| `memory.store_id` | string |
| `memory.write_key` | string |
| `memory.persistence_scope` | enum | `session` \| `user` \| `agent_global` |

This captures the SpAIware (Rehberger 2026) attack class — memory-
poisoning persistence across sessions.

### Sovereign attestation (when rule ID is sovereign-prefixed)

| Field | Type |
|---|---|
| `atr.sovereign_attestation` | object {signer, signature, ca_chain} |

Required when the matched rule carries a sovereign prefix
(`ATR-DE-`, `ATR-SG-`, `ATR-TW-`, etc.) per governance/CHARTER.md § 8.2.
Engines MUST validate the attestation against the TSC-maintained
sovereign key registry before honoring the event's elevated trust.

---

## Forbidden fields

The following MUST NOT appear in an ATR event under any circumstance:

- Raw user PII (names, addresses, phone numbers). PII detected by the
  rule is referenced via `atr.matched_value_redacted` with type and
  length only.
- Raw API keys / credentials / tokens. Always redacted.
- Full prompt / response text in `matched_value_redacted`. Only the
  matched fragment, redacted.

Engines that operate in `forensic_mode` MAY emit additional fields
for in-flight audit, but these MUST be explicitly enabled per
deployment AND clearly distinguished in event metadata.

---

## OpenTelemetry mapping (informative)

For OTEL ingestion, ATR events map to spans:

```
OpenTelemetry Span                ATR Event Field
─────────────────────             ──────────────────────────
span.name                          → "atr.detection." + atr.category
span.kind                          → "INTERNAL"
span.start_time                    → @timestamp
span.duration                      → engine's evaluation time
span.status.code                   → "ERROR" if atr.severity in [critical, high]
                                     "OK" otherwise
span.attributes.atr.*              → all atr.* fields
span.attributes.agent.*            → all agent.* fields
span.attributes.session.id         → session.id
span.attributes.service.name       → service.name
span.events                        → [{name: "atr.rule_matched",
                                       attributes: {rule_id, matched_field}}]
span.resource.attributes           → service.name, service.version
```

This mapping is informative; downstream tools may consume the raw
ATR event JSON without OTEL conversion.

---

## OSCAL assessment-result mapping (informative)

For NIST AI RMF + OSCAL pipelines, each ATR event maps to one OSCAL
`observation`:

```
OSCAL observation                  ATR Event Field
──────────────────                 ────────────────────
uuid                                → evidence.observation_id (UUID v7)
collected                           → @timestamp
title                               → "ATR rule " + atr.rule_id + " matched"
description                         → human-readable from rule's `description` field
methods                             → ["AUTOMATED"]
types                               → ["finding"]
subjects                            → [{type: "component",
                                        subject-uuid: agent.id}]
relevant-evidence                   → [{href: link to atr.event_id,
                                        description: "ATR detection event"}]
remarks                             → free-form, may include atr.response_taken
```

This mapping enables zero-write integration with OSCAL profile-based
audit. ATR events stream into OSCAL assessment-result format
without manual munging.

---

## Example event

```json
{
  "@timestamp": "2026-05-25T08:14:32.182Z",
  "atr.event_id": "01927e2d-7b32-7c41-9e84-3b8f2a1e9c54",
  "atr.spec_version": "1.0",
  "atr.engine_id": "atr/typescript-reference/3.1.0",
  "atr.rule_id": "ATR-2026-00525",
  "atr.rule_version": 1,
  "atr.rule_status": "stable",
  "atr.rule_maturity": "test",
  "atr.rule_review_status": "community_reviewed",
  "atr.severity": "critical",
  "atr.category": "skill-compromise",
  "atr.subcategory": "supply-chain-worm",
  "atr.confidence": 1.0,
  "atr.matched_field": "skill_content",
  "atr.matched_value_redacted": "[REDACTED:identifier:18] persistence daemon installed",
  "atr.response_action": ["block_input", "alert", "snapshot"],
  "atr.response_taken": ["block_input", "alert"],
  "atr.response_threshold_met": true,
  "agent.id": "agt-customer-12345-claude-prod-01",
  "agent.platform": "claude_code",
  "agent.platform_version": "1.8.4",
  "session.id": "sess-2026-05-25-bk9a8x",
  "service.name": "example-scanner",
  "service.version": "1.4.13",
  "evidence.observation_id": "01927e2d-7b32-7c41-9e84-3b8f2a1e9c54",
  "evidence.signature": "MEQCIBdJpL3zEoXxKj9F/qqM8DxFJp7Q...",
  "evidence.signature_key_id": "kid:example-scanner-prod-2026-05",
  "evidence.upstream_chain": null
}
```

---

## Versioning

This spec is at v1.0. Field additions are minor-version-compatible
(v1.x) and do not break conformant consumers. Field removals or
semantic changes are major-version (v2.0) and require an AEP.

Conformant engines MUST emit `atr.spec_version` so consumers can
adapt to future versions.

---

## References

- OpenTelemetry semantic conventions: https://opentelemetry.io/docs/specs/semconv/
- OSCAL Assessment Results: https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/
- EU AI Act Article 50: https://artificialintelligenceact.eu/article/50/
- UUID v7 (time-ordered): https://datatracker.ietf.org/doc/rfc9562/
- Ed25519 signing: https://datatracker.ietf.org/doc/rfc8032/
- IETF AI agent auth draft: https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00
- ATR Rule Format Spec v1.0: ATR-SPEC-v1.md
- ATR Category Registry v1.0: spec/category-registry/v1.0.yaml
