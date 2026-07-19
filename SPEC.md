# ATR Core Specification

Version: 1.0.0
Status: Draft
Date: 2026-05-16
License: MIT
Editor: Adam Lin (林冠辛) <adam@agentthreatrule.org>
Numbering Authority: ATR Technical Committee (transitional BDFL until TSC seated)
Canonical URL: https://agentthreatrule.org/atr/spec
DOI: 10.5281/zenodo.19178002

---

## 1. Abstract

This document specifies the wire format, evaluation semantics, identifier scheme,
and conformance criteria for Agent Threat Rules (ATR), an open detection rule
standard for AI agent security threats. ATR provides a vendor-neutral way to
express, exchange, and execute detections against AI agent artifacts
(SKILL.md files, MCP tool definitions, agent configurations) and AI agent
runtime events (LLM input/output, tool invocations, context windows). Any
software that loads ATR rule YAML and emits matches in conformance with this
specification is an ATR-compatible engine.

## 2. Status of This Document

This is a Draft of ATR Core v1.0.0. Distribution is unlimited. The Draft is
stable for implementation. Changes prior to Final status will be limited to
editorial corrections and clarifications that do not alter rule wire format or
evaluation outcome.

This document is intended to be advanced to Final status after a 30-day public
comment period and after at least two independent implementations have been
verified against the Conformance Test Suite (Section 12).

## 3. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when,
they appear in all capitals, as shown here.

| Term | Definition |
|------|-----------|
| Rule | A YAML document conforming to Section 5 that describes one detection pattern. |
| Rule ID | A globally unique identifier in the form `ATR-YYYY-NNNNN` (Section 4). |
| Engine | Software that loads Rules and evaluates Inputs against them. |
| Input | A structured artifact (SKILL.md, MCP tool definition, agent config) or a runtime AgentEvent submitted to an Engine for evaluation. |
| AgentEvent | A structured representation of an AI agent action (LLM I/O, tool call, context window state). |
| Match | An Engine's output indicating that a Rule's detection condition evaluated to true for a given Input. |
| Numbering Authority | The body authorized to assign permanent Rule IDs (currently the ATR project Maintainer; transitions to the TSC under GOVERNANCE.md). |
| Conformance Level | One of L1, L2, L3 (Section 11). |
| Corpus | The set of Rules officially published under a given ATR version. |

## 4. Rule Identifier

### 4.1 Format

A Rule ID MUST match the regular expression:

```
^ATR-([0-9]{4})-([0-9]{5})$
```

where the first capture group is the four-digit year of first creation and the
second capture group is a zero-padded five-digit sequential number assigned by
the Numbering Authority.

### 4.2 Assignment Rules

1. Rule IDs MUST be assigned by the Numbering Authority and MUST NOT be
   self-assigned by contributors.
2. Once assigned, a Rule ID MUST be considered permanent and MUST NOT be
   reassigned to a different Rule, even if the originally-assigned Rule is
   deprecated.
3. A Rule ID MUST NOT encode classification information (category, severity,
   scan target). Classification is carried in metadata fields per Section 5.
4. A Rule ID MUST be globally unique within the official Corpus.
5. Contributors SHOULD use a placeholder identifier of the form
   `ATR-YYYY-DRAFT-<hex>` in pull requests prior to merge. The Numbering
   Authority assigns the permanent ID on merge.

### 4.3 Forks and Unofficial Assignments

A fork of the ATR repository MAY duplicate existing Rule YAML files but MUST
NOT assign new IDs in the `ATR-YYYY-NNNNN` namespace. Self-assigned IDs from a
fork are not part of the official Corpus and conformant Engines SHOULD NOT
present them as authoritative.

## 5. Rule Document Structure

A conforming Rule is a UTF-8 encoded YAML 1.2 document whose top-level value
is a mapping. The mapping MUST contain at minimum the fields enumerated in
Section 5.1 and MAY contain the fields enumerated in Section 5.2. Unknown
top-level fields MUST be preserved by an Engine that round-trips Rules but
MUST NOT alter evaluation outcomes.

### 5.1 Required Fields

These are the fields enumerated as `required` in the normative JSON Schema
[`spec/schema/rule.schema.json`](spec/schema/rule.schema.json). Where this
table and that schema differ, **the schema governs**.

| Field | Type | Constraints |
|-------|------|-------------|
| `schema_version` | string | MUST match `^\d+\.\d+$` — the rule-format major.minor the Rule targets. |
| `id` | string | MUST match Section 4.1 (`ATR-YYYY-NNNNN`, or `ATR-XX-YYYY-NNNNN` for a sovereign sub-range); MUST be unique in the Corpus. |
| `title` | string | length ≥ 5. Human-readable name. |
| `status` | enum | One of `draft`, `experimental`, `stable`, `deprecated`. |
| `description` | string | length ≥ 20. SHOULD describe the attack class, not the rule mechanics. |
| `author` | string | length ≥ 1. |
| `date` | string | ISO 8601 `YYYY-MM-DD` or `YYYY/MM/DD`. |
| `severity` | enum | One of `critical`, `high`, `medium`, `low`, `informational`. |
| `detection_tier` | enum | One of `pattern`, `behavioral`, `protocol`, `classifier`. |
| `maturity` | enum | One of `draft`, `experimental`, `test`, `stable`, `deprecated`. |
| `tags` | object | MUST contain `category` per Section 5.3. |
| `agent_source` | object | MUST contain `type` per Section 5.4. |
| `detection` | object | MUST conform to Section 6. |
| `response` | object | MUST contain `actions` per Section 5.5. |

`test_cases` is not a schema-required field, but it is REQUIRED for inclusion in
the conformance Corpus and for promotion to `maturity: stable` (Section 5.6).

### 5.2 Optional Fields

| Field | Type | Constraints |
|-------|------|-------------|
| `confidence` | integer | 0–100. Engine confidence percentage. |
| `rule_version` | integer | ≥ 1. Defaults to 1. |
| `references` | array | URLs or CVE identifiers. |
| `compliance` | object | Crosswalk mapping per Section 9. |
| `replaced_by` | string | If `status` is `deprecated`, SHOULD point to a successor Rule ID. |
| `wild_fp_rate` | number | 0.0–1.0; the false-positive rate observed on the published benign Corpus. |
| `test_cases` | object | Bundled true/false-positive fixtures; see Section 5.6. |

### 5.3 Tags

```yaml
tags:
  category: prompt-injection   # REQUIRED — one of the 10 canonical categories
  scan_target: skill           # OPTIONAL — mcp | skill | skill_md | llm_io |
                               # runtime | user_input | tool_response | both | llm
```

`tags.category` is REQUIRED; `tags.scan_target` is OPTIONAL. When it is present,
conformant Engines MUST honor it: a Rule with `scan_target: skill` MUST NOT be
evaluated against an MCP AgentEvent, and vice versa. The 10 canonical categories
are enumerated in Section 8.

### 5.4 Agent Source

```yaml
agent_source:
  type: mcp_exchange         # REQUIRED — the event class this Rule inspects
  framework: [claude_code]    # OPTIONAL — narrowing hints
```

`agent_source.type` is REQUIRED. It SHOULD be one of the canonical event
classes: `llm_io`, `mcp_exchange`, `tool_call`, `multi_agent_comm`,
`agent_trace`, `skill_lifecycle`, `memory_access`, `context_window`,
`agent_behavior`. The vocabulary is intentionally open (the schema does not
close the enum) so new event classes can be registered without a breaking
change; new canonical values are introduced by Spec amendment. An Engine that
does not model a given `type` MUST skip the Rule rather than misclassify the
event.

### 5.5 Response

```yaml
response:
  actions:
    - block_request         # canonical action vocabulary; see Appendix A
    - log_alert
  user_message: "Optional analyst-facing message"
```

Engines MUST NOT execute response actions automatically without an explicit
configuration directive from the operator. The `response` field is a
recommendation expressed by the Rule author, not a directive to the Engine.

### 5.6 Test Cases

A Rule SHOULD carry a `test_cases` object with `true_positives` and
`true_negatives` arrays. Each entry pairs an `input` with an `expected` verdict
whose value MUST be `triggered` or `not_triggered`:

```yaml
test_cases:
  true_positives:
    - input: "<a sample payload of the attack class this Rule detects>"
      expected: triggered
  true_negatives:
    - input: "<a benign sample the Rule must not flag>"
      expected: not_triggered
```

At least one `true_positive` and one `true_negative` are REQUIRED for a Rule at
`maturity: experimental` or above; at least five of each are REQUIRED for
promotion to `maturity: stable` and for inclusion in the conformance Corpus
(Section 11). The legacy verdict tokens `trigger` / `no_trigger` are deprecated
and MUST NOT be used in new Rules.

## 6. Detection Semantics

### 6.1 Detection Structure

A Rule's `detection` object contains a `conditions` array (REQUIRED, ≥1 item)
and an optional `condition` combinator string. Each entry in `conditions` is
one of two forms defined by the normative schema
[`spec/schema/rule.schema.json`](spec/schema/rule.schema.json).

**Pattern condition** — matches content in a named field:

```yaml
detection:
  condition: any            # OPTIONAL combinator; default "any" (OR)
  conditions:
    - field: content        # which part of the AgentEvent to inspect
      operator: regex        # see Section 6.3
      value: "(?i)ignore\\s+(all\\s+)?previous\\s+instructions"
      description: "Instruction override attempt"   # OPTIONAL
```

**Behavioral condition** — compares a runtime metric against a threshold:

```yaml
    - metric: tool_calls_per_minute
      operator: gt
      threshold: 50
```

A pattern condition MUST contain `field`, `operator`, and `value`. A behavioral
condition MUST contain `metric`, `operator`, and `threshold`. These are the only
two condition shapes the schema defines.

### 6.2 Match Definition and Combinator

Given a Rule R and an AgentEvent I, an Engine MUST emit a Match if, and only if,
the boolean combination of R's evaluated conditions selected by
`R.detection.condition` is true.

`condition` is a string with these semantics:

| Value | Semantics |
|-------|-----------|
| `any` (default) | Match iff **at least one** condition matches (OR). |
| `all` | Match iff **every** condition matches (AND). |
| boolean expression | An expression over condition aliases using `AND`, `OR`, `NOT`, and parentheses. Used by multi-step Rules whose `conditions` are keyed by alias. |

When `condition` is absent, an Engine MUST default to `any`. `any` and `all`
MUST be supported for v1.0.0 conformance; expression support is REQUIRED only
for Rules that declare aliased conditions.

### 6.3 Operators

A pattern condition's `operator` MUST be one of the following, per the schema
enum:

| Operator | Semantics |
|----------|-----------|
| `regex` | `value` is a regular expression (Section 6.4). Used by the overwhelming majority of the Corpus. |
| `contains` | Case-sensitive substring match. |
| `equals` | Exact string equality. |
| `matches` | Glob / wildcard match, engine-defined. |
| `ml_classifier` | `value` names a classifier the Engine invokes; result is boolean. |
| `ast` | `value` is an AST query over parsed code content. |
| `bytecode` | `value` is a bytecode-level pattern. |

A behavioral condition's `operator` is a numeric comparison over `metric`
(e.g. `gt`, `lt`, `gte`, `lte`, `eq`).

Engines MUST reject a Rule whose pattern `operator` is outside the enum above,
with a clear error identifying the unknown operator — silently treating an
unknown operator as no-match would convert an authoring mistake into a silent
false negative. An Engine MAY skip `matches`, `ml_classifier`, `ast`, or
`bytecode` conditions it cannot evaluate (treating them as non-matching, not
matching), but MUST NOT report such a Rule as conformant at Level L2/L3.

### 6.4 Regular-Expression Dialect

`regex` operands are ECMAScript (`RegExp`) patterns with one required
preprocessing rule: a pattern MAY begin with an inline global-flag group
matching `^\(\?[ims]+\)` (for example `(?i)` or `(?is)`). A conforming Engine
MUST strip that leading group from the pattern and apply the corresponding
`RegExp` flags (`i`, `m`, `s`). This inline-flag form is used by a large
majority of the Corpus and is therefore normative: an Engine that compiles the
pattern literally as ECMAScript — where a leading `(?i)` raises a syntax error —
is non-conforming. Patterns are applied across the entire Input field, not
line-by-line, unless the pattern itself constrains position. Engines SHOULD
reject patterns whose worst-case matching is super-linear (ReDoS) rather than
evaluate them.

### 6.5 Determinism

For a given Engine version, a given Rule, and a given Input, the Match outcome
MUST be deterministic. Engines MUST NOT introduce non-determinism (e.g.,
randomized sampling, time-of-day branching) into Rule evaluation.

### 6.6 Extension Methods

The conditions and operators in Sections 6.1-6.4 define the default detection
method (`pattern`). A Rule MAY declare an optional `detection.method` field
to opt into an alternative method defined by a Spec extension document.
v1.0 defines `pattern` as the default; the canonical extension document
[atr-method-v1.1.md](spec/atr-method-v1.1.md) defines four additional
methods: `signature`, `semantic`, `behavioral`, and `trace`.

Engines that do not implement a given method MUST skip Rules using it
rather than fail closed on unknown method values. This permits gradual
adoption of new methods without breaking existing conformance claims.

Future extension methods MUST be introduced by Spec amendment per
GOVERNANCE.md, not by individual Rule authors.

## 7. Match Output

An Engine MUST emit Match output that includes, at minimum:

```json
{
  "rule_id": "ATR-2026-00001",
  "corpus_version": "2.2.2",
  "input_identifier": "<engine-supplied stable handle for the Input>",
  "matched_at": "2026-05-16T03:14:15Z",
  "severity": "high",
  "category": "prompt-injection",
  "matched_conditions": ["instruction_override", "credential_exfil"]
}
```

`corpus_version` is the SemVer string of the ATR corpus the engine was
loaded with at the time of the match. Individual rules carry no separate
version field; the corpus is versioned as a whole per §10.

Engines MAY emit additional fields. The output format MAY be JSON, SARIF,
STIX 2.1 (via the `x-atr-rule` extension), or any other serialization, but
the listed fields MUST be present.

## 8. Canonical Categories

The following ten categories are normative for v1.0.0. New categories MUST be
introduced only by Spec amendment per GOVERNANCE.md.

1. `prompt-injection`
2. `agent-manipulation`
3. `skill-compromise`
4. `context-exfiltration`
5. `tool-poisoning`
6. `privilege-escalation`
7. `model-abuse`
8. `excessive-autonomy`
9. `model-security`
10. `data-poisoning`

## 9. Crosswalks (Optional)

A Rule MAY include a `compliance` object mapping the detection to external
frameworks:

```yaml
compliance:
  owasp_agentic: [ASI01, ASI03]
  owasp_llm: [LLM01]
  mitre_atlas: [AML.T0051.000]
  nist_ai_rmf: [MS-2.6, MG-2.2]
  oscal_assessment_objective: [ar-objective-mcp-tool-screening-1]
  iso_iec_42001: [A.6.2.1]
  eu_ai_act: [Art.15]
  safe_mcp: [SAFE-T1101]
```

`oscal_assessment_objective` lets a Rule act as an evidence source beneath an
OSCAL-driven assessment. Engines that emit OSCAL Assessment Results (per
`spec/atr-event-v1.0.md` mapping) MAY cite the Rule's match output as evidence
for the referenced objective.

Identifiers MUST come from the authoritative source for each framework. Where
ambiguity exists, Rule authors SHOULD include a `references` entry pointing to
the source document.

## 10. Versioning

ATR follows Semantic Versioning 2.0.0 with the following project-specific
contract:

- Major (X.0.0): breaking change to wire format, identifier scheme, or
  evaluation semantics.
- Minor (X.Y.0): new categories, new operators, new optional fields, or any
  change adding capability without breaking existing conforming Engines.
- Patch (X.Y.Z): Rule corpus additions, deprecations, or editorial spec
  changes that do not require Engine updates.

A deprecated field MUST remain valid for at least one Major version after
deprecation is announced in CHANGELOG.md and in the Spec.

## 11. Conformance Levels

| Level | Requirement |
|-------|-------------|
| L1 | Engine loads the published Corpus without parse errors and emits Match output per Section 7 for at least one Rule. |
| L2 | Engine passes 100% of the Conformance Test Suite (Section 12) against the published Corpus for the declared Spec version. |
| L3 | Engine passes L2 AND emits Match output in at least two interchange formats (JSON + one of: SARIF, STIX 2.1, MISP, OpenCTI), AND publishes its results against the public benign Corpus with documented FP rate. |

An implementation MAY claim "ATR-compatible" only with a declared Conformance
Level and a reproducible test report.

## 12. Conformance Test Suite

The Conformance Test Suite is published in the `conformance/` directory of
the canonical repository under the same MIT license as the Spec.

The suite v1.0.0 ships at least 100 true-positive fixtures, at least 100
true-negative fixtures, and 20 edge-case fixtures covering catastrophic
regex inputs, malformed YAML and JSON, oversized inputs, deeply nested
structures, zero-width and RTL-override characters, null-byte injection,
and control-character payloads. Fixtures are generated deterministically
from the embedded `test_cases` blocks of the rule corpus via
`conformance/v1.0/runner/generate-fixtures.ts`, plus a curated edge set
in `conformance/v1.0/runner/generate-edge-fixtures.ts`.

An Engine claiming L2 conformance MUST pass 100% of the labeled fixtures
present in the declared suite version, MUST produce zero false positives
across the labeled true-negative fixtures of that same version, and MUST
handle every edge-case fixture by returning either no_match or a
graceful_error within the per-fixture runtime budget. An Engine MUST
publish the suite version it was tested against in any conformance claim.

## 13. Security and Privacy Considerations

### 13.1 Trust Boundary

Rules are content that an Engine evaluates against potentially untrusted
Inputs. An Engine MUST NOT permit a Rule's `description`, `references`, or
other free-form metadata fields to alter evaluation behavior. The only fields
that affect evaluation are those enumerated in Sections 5.3, 5.4, 6, 7.

### 13.2 Resource Exhaustion

A malformed `regex` selector may cause catastrophic backtracking. Engines
MUST apply a per-rule execution timeout (RECOMMENDED: 100 ms per Input per
Rule) and MUST report a timeout as a non-match rather than an error.

### 13.3 PII in Match Output

If a Rule's matched substring contains PII or sensitive credentials, Engines
SHOULD provide a redaction option that hashes or truncates the matched
substring before emitting Match output. The Rule MAY hint at this with a
`response.redact_match: true` field.

### 13.4 Reporting Vulnerabilities

Vulnerabilities in this Spec or the reference Engine implementation are
reported per SECURITY.md.

## 14. IANA Considerations

This Specification requests registration of the following media types:

- `application/vnd.atr.rule+yaml` — a single ATR Rule
- `application/vnd.atr.corpus+yaml` — a corpus manifest listing multiple Rules
- `application/vnd.atr.match+json` — Match output per Section 7

Registration templates appear in Appendix B.

## 15. References

### 15.1 Normative References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- [YAML12] Ben-Kiki, O. et al., "YAML Ain't Markup Language Version 1.2", October 2009.
- [SEMVER] Preston-Werner, T., "Semantic Versioning 2.0.0", https://semver.org/spec/v2.0.0.html.

### 15.2 Informative References

- [SIGMA] SigmaHQ, "Sigma Rule Specification", https://github.com/SigmaHQ/sigma-specification
- [STIX21] OASIS, "STIX Version 2.1", https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- [NIST-AI-RMF] NIST, "Artificial Intelligence Risk Management Framework (AI 100-1)"
- [NIST-GAI-PROFILE] NIST, "Generative AI Profile (AI 600-1)"
- [OWASP-AGENTIC] OWASP, "Agentic Security Initiative Top 10 (2026)"
- [MITRE-ATLAS] MITRE, "Adversarial Threat Landscape for AI Systems"
- [SAFE-MCP] safe-agentic-framework, "Secure AI Framework for Enterprise — MCP", https://github.com/safe-agentic-framework/safe-mcp

## Appendix A. Canonical Response Action Vocabulary

The following action identifiers are normative for v1.0.0:

`block_request`, `log_alert`, `quarantine_artifact`, `require_human_review`,
`redact_match`, `rate_limit_source`, `revoke_credential`, `notify_operator`.

## Appendix B. IANA Media Type Registration Templates

The following provisional registration templates accompany the IANA
request in §14. Final wording will be filed with IANA on advancement of
this document to Final status.

### B.1 `application/vnd.atr.rule+yaml`

```
Type name:               application
Subtype name:            vnd.atr.rule+yaml
Required parameters:     none
Optional parameters:     charset (default: utf-8)
Encoding considerations: 8bit; YAML 1.2 text document, see [YAML12]
Security considerations: SPEC §13
Interoperability:        SPEC §5–§6 define the wire format and evaluation
                         semantics; conformance is per SPEC §11.
Published specification: This Specification (SPEC.md v1.0.x at
                         https://github.com/Agent-Threat-Rule/agent-threat-rules).
Applications using:      ATR-compatible detection engines, security
                         scanners, AI agent governance tooling.
Author/Change controller: ATR Numbering Authority (BDFL, transitioning to
                         TSC per GOVERNANCE.md).
```

### B.2 `application/vnd.atr.corpus+yaml`

```
Type name:               application
Subtype name:            vnd.atr.corpus+yaml
Required parameters:     none
Optional parameters:     charset (default: utf-8)
Encoding considerations: 8bit; YAML 1.2 manifest enumerating a set of ATR
                         Rules with their version metadata.
Security considerations: SPEC §13
Interoperability:        Consumers MUST verify rule IDs against the
                         Numbering Authority registry; see §4.
Published specification: This Specification.
Applications using:      Same as B.1.
Author/Change controller: Same as B.1.
```

### B.3 `application/vnd.atr.match+json`

```
Type name:               application
Subtype name:            vnd.atr.match+json
Required parameters:     none
Optional parameters:     charset (default: utf-8)
Encoding considerations: 8bit; JSON document conforming to SPEC §7.
Security considerations: SPEC §13.3 (PII / credential redaction).
Interoperability:        SPEC §7 defines the required output fields.
Published specification: This Specification.
Applications using:      ATR-compatible engines emitting Match output for
                         downstream SIEM, SOAR, and audit tooling.
Author/Change controller: Same as B.1.
```

## Appendix C. Change Log Against Pre-1.0 Drafts

| Change | Source |
|--------|--------|
| Adopted RFC 2119 normative language | This document |
| Consolidated three pre-1.0 spec drafts (`ATR-SPEC-v1.md`, `ATR-FRAMEWORK-SPEC.md`, `docs/schema-spec.md`) | This document |
| Defined Conformance Levels L1/L2/L3 | This document |
| Required ≥5 TP + ≥5 TN per Rule (was prior community practice) | This document |
| Specified Match output schema | This document |
| Added IANA media type registration request | This document |
