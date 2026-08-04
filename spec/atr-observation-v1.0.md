# ATR Observation Format v1.0 — the input side

> **STATUS: PROPOSED v1.0 — NOT YET RATIFIED.** This specification describes
> a target *input* format for community comment. The current TypeScript
> production engine continues to accept its existing `AgentEvent` shape.
> Adopters should NOT migrate until ratification. See
> `STANDARDIZATION-STATUS.md` for full status.

**Status:** Draft for AEP-005 ratification — NOT RATIFIED
**Date:** 2026-07-29
**License:** MIT
**Required by (on ratification):** Correlation rule evaluation
(`spec/atr-correlation-v1.0.md`), honest coverage reporting, quantitative
detection primitives

---

## Purpose

ATR has an event format for what an engine **emits** when a rule fires
(`spec/atr-event-v1.0.md`). It has no format for what an engine
**ingests**.

The practical consequence is visible in the corpus. The production
`AgentEvent` interface carries a required `content: string` — the text to
analyse — while `sessionId` and `agentId` are optional. A rule therefore
receives a blob of text rather than a description of something that
happened, which is why almost every rule in the canonical corpus is a
regular expression over one string, and why behavioural rules degrade
into matching an agent's own narration of its behaviour.

It also leaves `spec/atr-correlation-v1.0.md` suspended. That spec
defines join keys (`session.id`, `agent.id`, `agent.delegation_chain`)
that no schema in this repository defines or requires.

This document specifies the minimum observation an engine must receive
before correlation, counting, or absence-of-consent detection can mean
anything.

### Non-goals

- **Not a replacement for `AgentEvent`.** The production interface stays.
  An `AgentEvent` is a lossy projection of an Observation; §6 gives the
  mapping.
- **Not a telemetry collector.** ATR defines the shape, not the plumbing.
- **Not a claim of completeness.** §5 exists precisely because most
  deployments will observe a subset of dimensions. Declaring the subset
  honestly is a requirement of this spec, not a footnote.

---

## 1. Design constraints

1. **Small enough to adopt.** Six required fields. A host that cannot
   populate six fields cannot support correlation, and should say so
   rather than emit a degraded stream.
2. **Aligned, not invented.** Where OpenTelemetry GenAI semantic
   conventions already name a concept, this spec adopts the name.
   Unilateral adoption costs nothing and removes a future migration.
3. **Failure is first class.** See §3.
4. **Coverage is declared, not assumed.** See §5.

---

## 2. Required fields

| Field | Type | Notes |
|---|---|---|
| `@timestamp` | RFC 3339 string | Ordering key. Ties broken by `observation.id`. |
| `observation.id` | string | Unique within a stream. Deduplication and evidence-chain anchor. |
| `observation.kind` | enum, §4 | Which dimension this observation belongs to. |
| `agent.id` | string | OTel: `gen_ai.agent.id`. |
| `session.id` | string | OTel: `gen_ai.conversation.id`. |
| `outcome` | enum, §3 | See §3 — this is the field this spec exists for. |

`session.id` and `agent.id` are **required here although optional in
`AgentEvent`**. A correlation rule grouped by a field that may be absent
is not a detection, it is a coin flip.

### 2.1 Recommended: `delegation.root`

| Field | Type | Notes |
|---|---|---|
| `delegation.root` | string | The `session.id` of the originating session in a delegation chain. |

When an agent is not a delegate, `delegation.root` **MUST** equal
`session.id`. It is therefore always populated and always safe to group
by.

This field exists because grouping by `session.id` alone is trivially
defeated: an actor that spawns a sub-agent usually receives a fresh
session identifier from the host, so a two-step chain lands in two
buckets and no correlation rule can ever complete. Grouping by
`delegation.root` survives the hop.

It does not make delegation-based evasion impossible. It makes each hop
leave an edge in a graph that can be reconstructed afterwards. That is
the honest claim.

---

## 3. `outcome`

```
ok | error | denied | refused | timeout | rate_limited
```

| Value | Meaning |
|---|---|
| `ok` | The action was attempted and succeeded. |
| `error` | Attempted, failed for a reason unrelated to policy. |
| `denied` | Refused by a policy or permission boundary. |
| `refused` | Refused by the model or a guardrail (not a permission boundary). |
| `timeout` | No result within the host's limit. |
| `rate_limited` | Throttled by the host or a remote service. |

`denied`, `refused`, `error`, and `timeout` **MUST NOT** be collapsed
into a single boolean. OpenTelemetry GenAI, ECS, and OCSF all reduce
these to an `is_error`-shaped flag, which is why this spec defines its
own enum rather than adopting one.

The distinction carries the load. An agent searching for a way out of a
boundary produces a dense run of `denied` against a small number of
distinct targets with high argument variety. An agent that is merely
broken produces `error`. An agent behaving normally produces neither at
volume. None of those three shapes is visible if the host emits
`is_error: true` for all of them.

Stated plainly: for this class of incident the signal is in the attempts
that failed, not the one that worked.

### 3.1 What this does not do

Thresholds over `outcome` are cheap to compute and cheap to evade, since
the rules are public. A ruleset that publishes "50 denials in 15
minutes" has published a speed limit. Correlation rules over `outcome`
**SHOULD** therefore keep the *logic* in the public corpus and take
*numeric thresholds* from a host-injected profile
(`spec/atr-profile-v1.0.md`). The public artefact stays verifiable; the
operating numbers do not have to be.

---

## 4. `observation.kind`

The first nine values correspond to `agent_source.type` in the rule
schema and cover what the corpus can already express:

```
llm_io | tool_call | tool_response | mcp_exchange | multi_agent_comm
memory_access | skill_lifecycle | context_window | agent_behavior
```

The next three are defined here and have **no corresponding rules in the
canonical corpus at the time of writing**:

```
network | file | process
```

They are specified because they are the dimensions in which several
well-understood agent attack steps actually occur, and because a
dimension that has no name cannot be declared missing. A deployment that
observes only tool-level activity should report that fact (§5) rather
than return "no match" for a question it was never able to ask.

### 4.1 Dimension-specific fields

Fields beyond §2 are **OPTIONAL** and depend on `observation.kind`. A
non-normative starting set:

| Kind | Fields |
|---|---|
| `tool_call` | `tool.name`, `tool.arguments`, `target.host`, `target.path` |
| `tool_response` | `tool.name`, `content` |
| `network` | `target.host`, `target.port`, `target.scheme`, `bytes.out` |
| `file` | `file.path`, `file.operation` |
| `process` | `process.executable`, `process.argv` |

`target.host` and `target.path` are shared across kinds deliberately.
Correlation joins on a canonical target require one name for one
concept; see `spec/atr-correlation-v1.0.md` on join keys.

Canonicalisation before any join: hostnames lowercased with the port
removed, paths resolved, URLs reduced to scheme and host. Two
observations that refer to the same target and do not produce the same
join value will silently never correlate, and the rule author will
reasonably conclude the engine is broken.

---

## 5. Declared coverage

An engine or host that consumes Observations **MUST** be able to report
which dimensions it can actually observe:

```json
{
  "atr.observation_spec_version": "1.0",
  "covered_dimensions": ["llm_io", "tool_call", "tool_response", "mcp_exchange"],
  "uncovered_dimensions": ["network", "file", "process"]
}
```

Rules and correlation rules **MAY** declare `requires_dimensions`. When a
required dimension is not covered, the engine **MUST** report the rule as
`not_evaluated` and **MUST NOT** report it as `no_match`.

This is the difference between "we looked and found nothing" and "we
could not look", and reporting the second as the first is how a coverage
number becomes a lie. It also bounds every claim made anywhere else in
this repository: detection quality has a ceiling set by telemetry
fidelity, and the telemetry is produced by the thing being observed. A
single permitted `shell.exec` can compress thousands of network attempts
into one observation with `outcome: ok`. No rule design fixes that. The
only honest response is to make the blind spot machine-readable.

---

## 6. Mapping from the production `AgentEvent`

An `AgentEvent` is a lossy projection. The mapping is defined so hosts
can migrate incrementally rather than all at once:

| `AgentEvent` | Observation |
|---|---|
| `timestamp` | `@timestamp` |
| `type` | `observation.kind` |
| `sessionId` | `session.id` (required here) |
| `agentId` | `agent.id` (required here) |
| `content` | kind-dependent field, §4.1 |
| `fields` | kind-dependent fields, §4.1 |
| `metrics` | out of scope for v1.0 |
| — | `observation.id` (host must supply) |
| — | `outcome` (host must supply) |
| — | `delegation.root` (defaults to `session.id`) |

A host that supplies only the mappable fields is conformant to §2 minus
`outcome` and **MUST** declare `network`, `file`, and `process` as
uncovered.

---

## 7. Example

A dataset-processing agent reads an environment variable, then reaches an
internal endpoint, then opens an outbound connection. Three observations,
one delegation root, one of them denied:

```json
[
  {
    "@timestamp": "2026-07-29T09:14:02.113Z",
    "observation.id": "obs-8f21a0",
    "observation.kind": "tool_call",
    "agent.id": "dataset-normaliser",
    "session.id": "sess-4419",
    "delegation.root": "sess-4419",
    "outcome": "ok",
    "tool.name": "shell.read_file",
    "file.path": "/proc/self/environ"
  },
  {
    "@timestamp": "2026-07-29T09:14:19.882Z",
    "observation.id": "obs-8f21a1",
    "observation.kind": "network",
    "agent.id": "dataset-normaliser",
    "session.id": "sess-4420",
    "delegation.root": "sess-4419",
    "outcome": "denied",
    "target.host": "169.254.169.254",
    "target.path": "/latest/meta-data/iam/security-credentials/"
  },
  {
    "@timestamp": "2026-07-29T09:15:41.006Z",
    "observation.id": "obs-8f21a2",
    "observation.kind": "network",
    "agent.id": "dataset-normaliser",
    "session.id": "sess-4420",
    "delegation.root": "sess-4419",
    "outcome": "ok",
    "target.host": "collect.example.net",
    "target.scheme": "https",
    "bytes.out": 4192
  }
]
```

The second and third observations carry a different `session.id` from the
first, because a sub-agent was spawned. Grouping by `session.id` splits
this into two buckets and nothing correlates. Grouping by
`delegation.root` keeps it in one.

Note also that this example is constructed, not observed. Fixtures
derived from public incident reporting rather than from a captured
stream **MUST** be marked `derived-not-observed` in their manifest. A
corpus that learns to match the prose of incident write-ups repeats a
failure this project has already documented once.

---

## 8. Open questions

- Whether `metrics` from `AgentEvent` should become first-class
  observation fields or stay host-side.
- Whether `observation.kind` should be extensible by registry (as
  `spec/category-registry/v1.0.yaml` does for categories) rather than a
  closed enum.
- Whether `outcome: refused` is stable enough to define across hosts, or
  whether guardrail refusals belong in a separate dimension.
- How `covered_dimensions` should be attested rather than self-declared.
  Self-declaration is a statement of intent, not a control; a host can
  claim any coverage it likes.

---

## References

- `spec/atr-event-v1.0.md` — the output side
- `spec/atr-correlation-v1.0.md` — consumes the join keys defined here
- `spec/atr-profile-v1.0.md` — where numeric thresholds belong
- OpenTelemetry GenAI semantic conventions — `gen_ai.agent.id`,
  `gen_ai.conversation.id`
