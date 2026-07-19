# ATR Correlation Rule Format v1.0

> **STATUS: PROPOSED v1.0 — NOT YET RATIFIED.** This specification describes
> a target correlation format for community comment. No correlation rules
> have shipped to the canonical corpus yet. See `STANDARDIZATION-STATUS.md`
> for full status.

**Status:** Draft for AEP-004 ratification — NOT RATIFIED
**Date:** 2026-05-25
**License:** MIT
**Required by (on ratification):** Detection of multi-step agent attacks (A2A chains, memory-poisoning persistence, delegated authority abuse)

---

## Purpose

A single agent action rarely constitutes an attack. The attack lives
in the **chain**:

- Agent A receives an indirect prompt injection from a retrieved
  document (event 1).
- Agent A calls tool X with the injected parameters (event 2).
- Tool X delegates to Agent B via A2A (event 3).
- Agent B writes a persistence payload to its memory store (event 4).
- Three sessions later, Agent B exfiltrates the user's context to a
  remote URL pulled from memory (event 5).

A single-event rule fires on event 1 (prompt injection class), event
2 (tool poisoning), event 4 (memory write), and event 5 (context
exfiltration) **independently**, with no connection between them.
The defender sees four unrelated alerts and may dismiss each as
low-severity noise.

A correlation rule joins these events into one detection. The output
is a single, high-confidence event that names the attack chain and
points to every constituent event.

This spec defines the correlation rule format. It is modelled on
Sigma's correlation rule specification but adds AI-agent-specific
join keys (agent.id, session.id, agent.delegation_chain).

---

## Correlation JSON Schema reference

Machine-readable schema: `spec/schema/correlation.schema.json`.

This Markdown document is normative; JSON Schema must match.

---

## Required fields

```yaml
correlation:
  schema_version: "1.0"
  id: "ATR-COR-2026-00001"                    # correlation rule ID, separate range from atomic rules
  title: "A2A delegated authority abuse chain"
  description: >
    Detects the multi-agent attack pattern: indirect prompt injection
    upstream → delegated tool call → memory poisoning downstream →
    exfiltration in subsequent session.
  status: "draft"
  severity: "critical"
  author: "ATR Maintainer"
  date: "2026-05-25"
  license: "MIT"
  references:
    owasp_agentic: ["ASI03", "ASI04", "ASI09"]
    mitre_atlas: ["AML.T0048", "AML.T0024"]

source_rules:
  - alias: "injection"
    rule_id: "ATR-2026-00012"                 # indirect prompt injection
  - alias: "tool_call"
    rule_id_pattern: "ATR-2026-001*"          # tool-poisoning class
  - alias: "memory_write"
    rule_id_pattern: "ATR-2026-003*"          # memory write
  - alias: "exfil"
    rule_id_pattern: "ATR-2026-006*"          # context exfiltration

correlation_logic:
  type: "temporal_sequence"                   # see § Correlation types below
  sequence:
    - alias: "injection"
    - alias: "tool_call"
    - alias: "memory_write"
    - alias: "exfil"
  join_keys:
    - "agent.id"                              # all events must share agent.id
    - "session.id"                            # OR be linked across sessions via memory.store_id
  window:
    type: "session_chain"                     # see § Time windows below
    max_session_count: 5                      # exfil may occur up to 5 sessions later
    max_wall_time: "30d"                      # but no longer than 30 days

response:
  severity_uplift: "critical"                 # final correlation severity
  actions: ["alert", "snapshot", "quarantine"]
  message_template: >
    [ATR-COR-2026-00001] Multi-agent attack chain detected. Indirect
    injection at event {injection.event_id} → tool call at
    {tool_call.event_id} → memory poisoning at
    {memory_write.event_id} → exfiltration at {exfil.event_id}.
    Recommend immediate session quarantine plus memory store audit.
```

---

## Correlation types

### `temporal_sequence`

Events must occur in declared order on the timeline. Events between
the named ones are allowed (and ignored). The match fires when the
final event in the sequence is observed.

### `temporal_unordered`

All named events must occur within the window, but order is not
constrained.

### `count_threshold`

A single source-rule fires N or more times within the window. Useful
for brute-force / repeated-attempt detection ("agent attempted
forbidden tool call ≥ 5 times in 1 hour").

### `value_overlap`

Two or more source rules fire AND share a common value in a named
field (e.g., both fire on the same `agent.id` and the same
`tool.target_jurisdiction`).

### `chain_propagation`

Events form a graph: event A produces upstream_chain reference
pointing to event B. Useful for A2A delegated-authority chains where
each link in the chain explicitly references the prior.

Engines MUST implement at least `temporal_sequence`, `count_threshold`,
and `chain_propagation` to claim correlation conformance. The other
two are RECOMMENDED.

---

## Join keys

Correlation requires join keys — fields whose equality across events
ties them into one chain. Standard join keys:

| Key | Source field | Use |
|---|---|---|
| `agent.id` | event.agent.id | Same agent across events |
| `session.id` | event.session.id | Same session |
| `agent.delegation_chain[*].agent_id` | A2A chain | Cross-agent |
| `memory.store_id` | memory write events | Same memory store |
| `tool.target_jurisdiction` | tool call events | Cross-event geographic correlation |
| `evidence.upstream_chain[*]` | event chain | Explicit upstream linkage |

Correlation rules MAY define custom join keys via XPath-like syntax
into the event JSON. Engines MUST implement standard keys; custom
keys are best-effort.

---

## Time windows

| Window type | Description |
|---|---|
| `wall_time` | Events must occur within N seconds / minutes / hours. Format: `"5m"`, `"24h"`. |
| `session_chain` | Events may span N consecutive sessions, with max wall time. |
| `chain_depth` | Events linked via `evidence.upstream_chain` up to N hops. |
| `unbounded` | No window (use sparingly; primarily for static-analysis chains where time is irrelevant). |

---

## False-positive considerations

Correlation rules have a multiplicative FP risk: P(FP) = P(FP_r1) ×
P(FP_r2) × ... × P(FP_rN), assuming independence. This makes
correlation rules ROBUSTLY HIGH PRECISION when the constituent
rules are individually high-precision.

But correlation also has a multiplicative complexity: the engine
maintains state across events, with bounded memory. Specification:

- Engines MUST set a per-correlation-rule maximum state size. If
  exceeded, oldest pending matches are evicted.
- Engines MUST emit a `correlation_state_evicted` event when
  eviction occurs (so audit chains know about lost detections).
- Engines MAY share state across correlation rules (e.g., index of
  events by `agent.id`) for efficiency.

---

## ID numbering

Correlation rules use a distinct ID range:

- Atomic rules: `ATR-YYYY-NNNNN`
- Correlation rules: `ATR-COR-YYYY-NNNNN`

This prevents ID collision and lets downstream consumers easily
filter correlation events. The Numbering Authority issues both
ranges; correlation rules pass the same TSC review process.

---

## Conformance gate

A correlation rule's CI gate has an additional check beyond the
atomic-rule gate:

- Engine MUST be able to load the rule (parse + validate).
- Engine MUST evaluate the correlation against a fixture event
  stream included in the rule's `test_cases.true_positive_streams`.
- Engine MUST NOT fire on `test_cases.true_negative_streams`.

Fixture event streams are JSON Lines files in
`tests/correlation-streams/<rule-id>/`.

---

## Example fixture stream (positive case for ATR-COR-2026-00001)

```jsonl
{"@timestamp":"2026-05-25T10:00:00Z","atr.event_id":"01927e2d-7b32-7c41-9e84-0001","atr.rule_id":"ATR-2026-00012","agent.id":"agt-abc","session.id":"sess-1","atr.matched_field":"agent_output","atr.category":"prompt-injection"}
{"@timestamp":"2026-05-25T10:00:30Z","atr.event_id":"01927e2d-7b32-7c41-9e84-0002","atr.rule_id":"ATR-2026-00115","agent.id":"agt-abc","session.id":"sess-1","atr.matched_field":"tool_call","atr.category":"tool-poisoning"}
{"@timestamp":"2026-05-25T10:01:00Z","atr.event_id":"01927e2d-7b32-7c41-9e84-0003","atr.rule_id":"ATR-2026-00345","agent.id":"agt-abc","session.id":"sess-1","atr.matched_field":"memory_write","atr.category":"context-exfiltration","memory.store_id":"mem-xyz"}
{"@timestamp":"2026-05-27T14:32:00Z","atr.event_id":"01927e2d-7b32-7c41-9e84-0004","atr.rule_id":"ATR-2026-00610","agent.id":"agt-abc","session.id":"sess-22","atr.matched_field":"agent_output","atr.category":"context-exfiltration"}
```

Engine MUST emit one correlation event after consuming all four
above, referencing all four event IDs in `evidence.upstream_chain`
of the output event.

---

## Example fixture stream (negative case)

Same as above but with different `agent.id` values across events.
Engine MUST NOT correlate (join key mismatch).

---

## Performance bounds

Correlation evaluation must remain bounded:

- **Memory:** O(N events × M correlation rules × K state per rule).
  Engines MUST evict oldest state when memory budget exceeded.
- **CPU per event:** O(M correlation rules), with O(1) state update
  per rule on average. Catastrophic-backtracking is forbidden in
  correlation logic.
- **Latency:** Correlation evaluation MUST NOT block atomic-rule
  emission. Atomic events emit immediately; correlation events
  emit on chain completion.

These bounds are guidelines; specific deployment SLAs (e.g., <100ms
p99 per event) belong to the engine's deployment specification, not
the spec.

---

## Versioning

Same versioning as atomic rules: SemVer with PATCH for backward-
compatible additions, MINOR for spec-relevant changes, MAJOR for
breaking changes. v1.0 is the initial release.

---

## References

- Sigma Correlation Rules Specification: https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md
- Sigma rule design lessons: https://sigmahq.io/docs/guide/about.html
- A2A delegation patterns: https://datatracker.ietf.org/doc/draft-ni-a2a-ai-agent-security-requirements/
- SpAIware (memory-poisoning persistence): https://www.sciencedirect.com/science/article/abs/pii/S0167739X25002894
- ATR Event Format Spec v1.0: spec/atr-event-v1.0.md
- ATR Rule Format Spec v1.0: ATR-SPEC-v1.md
