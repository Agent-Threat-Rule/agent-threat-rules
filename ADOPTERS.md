# ADOPTERS

Projects and organizations that have integrated Agent Threat Rules (ATR) into
public, ongoing work. Inclusion here is self-declared by the adopter via PR
and reflects the state at the time of the merge. Entries are sorted by
adoption tier and then alphabetically. The maintainers reserve the right to
move an entry between tiers if its public status changes (e.g. a project is
archived) — entries are not removed without notice.

To add yourself, open a PR using the
[`adopter` PR template](./.github/PULL_REQUEST_TEMPLATE/adopter.md). The
maintainers do not pre-approve adoption — your PR becomes the record.

## Why this file exists

ADOPTERS.md is the **machine-readable source of truth** consumed by
`agentthreatrule.org/ecosystem` and by downstream tooling that wants to know
which projects ship ATR. The website renders this file directly; the file is
not a marketing artefact and must not contain marketing copy.

Each entry follows a fixed structure (see Schema below) so the website can
parse it without ambiguity.

---

## Schema

Each entry, regardless of tier, follows:

```markdown
### Project Name
- **Org**: organisation (or "Independent")
- **Type**: one of [engine | rule-import | category-subset | adapter | reference | sidecar-proxy | other]
- **Integration**: one-sentence description of what the integration is
- **Evidence**: link to the merged PR / public announcement / docs page
- **Since**: YYYY-MM-DD (date of public adoption)
- **Status**: one of [shipped | in-review | planning]
- **Categories** (optional): comma-separated list of ATR categories the
  project consumes (e.g. `prompt-injection`, `tool-poisoning`)
```

The website parser reads the four required fields. Optional fields may be
added but parsers ignore unknown keys.

---

## Tier S — Standards bodies & frameworks

Adopters whose adoption is itself a public-good interoperability artefact
(taxonomies, catalogues, profiles, schemas published by neutral bodies).

### MISP / CIRCL
- **Org**: CIRCL (Computer Incident Response Center Luxembourg)
- **Type**: reference
- **Integration**: ATR rule-ID taxonomy + threat-intel galaxy merged into MISP's core distribution
- **Evidence**: <https://github.com/MISP/misp-taxonomies/pull/323> and <https://github.com/MISP/misp-galaxy/pull/1207>
- **Since**: 2026-05-10
- **Status**: shipped

### OWASP Agent Security Regression Harness
- **Org**: OWASP Foundation
- **Type**: reference
- **Integration**: ATR rule corpus referenced as the canonical agent-threat detection ruleset in the project's threat catalogue
- **Evidence**: <https://github.com/OWASP/agent-security-regression-harness/pull/74>
- **Since**: 2026-05-11
- **Status**: shipped

### NIST AI RMF — OSCAL Path 1
- **Org**: NIST (informal acceptance pathway)
- **Type**: reference
- **Integration**: Community OSCAL profile cross-references ATR rule IDs to AI RMF controls
- **Evidence**: <https://github.com/Agent-Threat-Rule/ai-rmf-oscal-catalog>
- **Since**: 2026-05-10
- **Status**: shipped

### OpenTelemetry — semantic-conventions-genai
- **Org**: CNCF / OpenTelemetry GenAI SIG
- **Type**: reference
- **Integration**: Proposal for `agent.threat.detection.*` semantic-convention attributes (which ATR populates on agent spans) is in review
- **Evidence**: <https://github.com/open-telemetry/semantic-conventions-genai/pull/165>
- **Since**: 2026-05-17
- **Status**: in-review

---

## Tier 1 — Production deployments

Adopters who ship ATR in a publicly-available customer-facing product or
internal-but-public tooling. Listed when the adopter has confirmed the
deployment publicly (merged PR, public docs, conference talk, etc.).

### Cisco AI Defense
- **Org**: Cisco
- **Type**: rule-import
- **Integration**: ATR rule corpus consumed by the AI Defense skill-scanner; matches surface in the Cisco product UI as detection findings
- **Evidence**: <https://github.com/cisco-ai-defense/skill-scanner/pull/99> (and predecessor PoC #79)
- **Since**: 2026-04-22
- **Status**: shipped

### Microsoft Agent Governance Toolkit
- **Org**: Microsoft
- **Type**: rule-import
- **Integration**: 287-rule ATR expansion auto-synced weekly into the Agent Governance Toolkit detection layer
- **Evidence**: <https://github.com/microsoft/agent-governance-toolkit/pull/1277>
- **Since**: 2026-04-26
- **Status**: shipped

### Gen Digital Sage
- **Org**: Gen Digital (Norton / Avast / LifeLock parent)
- **Type**: rule-import
- **Integration**: Full ATR rule pack integrated into the Sage agentic-AI risk-scoring layer
- **Evidence**: <https://github.com/gendigitalinc/sage/pull/33>
- **Since**: 2026-05-11
- **Status**: shipped

---

## Tier 2 — Open-source tooling & SDK integrations

Open-source developer tools, frameworks, and SDKs that have integrated ATR.
Listed when the integration code has been merged or released.

### BerriAI LiteLLM
- **Org**: BerriAI
- **Type**: sidecar-proxy
- **Integration**: ATR guardrail integration as a LiteLLM proxy callback; scans LLM input + output against the rule corpus at the proxy layer
- **Evidence**: <https://github.com/BerriAI/litellm/pull/28050>
- **Since**: 2026-05-16
- **Status**: in-review

### Promptfoo
- **Org**: Promptfoo
- **Type**: rule-import
- **Integration**: MCP red-team output scanning consumes ATR rules to flag adversarial responses in evaluation runs
- **Evidence**: <https://github.com/promptfoo/promptfoo/pull/8529>
- **Since**: 2026-04-08
- **Status**: in-review

### NVIDIA garak
- **Org**: NVIDIA
- **Type**: rule-import
- **Integration**: ATR detector plugin for the garak red-teaming framework
- **Evidence**: <https://github.com/NVIDIA/garak/pull/1276>
- **Since**: 2026-05-20
- **Status**: in-review

### IBM mcp-context-forge
- **Org**: IBM
- **Type**: sidecar-proxy
- **Integration**: ATR threat-detection plugin for the MCP context-forge proxy
- **Evidence**: <https://github.com/IBM/mcp-context-forge/pull/4109>
- **Since**: 2026-05-09
- **Status**: in-review

### Portkey AI Gateway
- **Org**: Portkey AI
- **Type**: sidecar-proxy
- **Integration**: ATR detection plugin in the Portkey gateway plugin architecture
- **Evidence**: <https://github.com/Portkey-AI/gateway/pull/1652>
- **Since**: 2026-05-16
- **Status**: in-review

### Semgrep
- **Org**: Semgrep Inc. (community contribution)
- **Type**: adapter
- **Integration**: YAML rule-format adapter that translates Semgrep rule conventions to ATR conformance for skill-manifest + MCP-tool security
- **Evidence**: Semgrep upstream PR (open as of 2026-05-10)
- **Since**: 2026-05-10
- **Status**: in-review

### aaif-goose
- **Org**: AAIF (block/goose)
- **Type**: sidecar-proxy
- **Integration**: PreToolUse hook denial integrates ATR rule evaluation at the tool-call boundary
- **Evidence**: <https://github.com/aaif-goose/goose/pull/9304>
- **Since**: 2026-05-19
- **Status**: in-review

### SigmaHQ
- **Org**: SigmaHQ
- **Type**: adapter
- **Integration**: Cross-listing in the Sigma tools directory; agent-threat-rules listed as a sibling detection-rule format
- **Evidence**: <https://github.com/SigmaHQ/sigma/pull/6015>
- **Since**: 2026-05-09
- **Status**: in-review

---

## Tier 3 — Documentation references & awesome-lists

Adopters who reference ATR in public catalogues, awesome-lists, or
documentation indices. Lower-effort inclusion but useful for ecosystem
discoverability.

### ottosulin/awesome-ai-security
- **Org**: Otto Sulin (independent)
- **Type**: reference
- **Integration**: ATR listed in the MCP Security section
- **Evidence**: <https://github.com/ottosulin/awesome-ai-security/pull/192>
- **Since**: 2026-05-20
- **Status**: shipped

### e2b-dev/awesome-ai-agents
- **Org**: E2B
- **Type**: reference
- **Integration**: ATR listed in the AI agents awesome-list
- **Evidence**: <https://github.com/e2b-dev/awesome-ai-agents/pull/959>
- **Since**: 2026-05-16
- **Status**: in-review

### e2b-dev/awesome-ai-sdks
- **Org**: E2B
- **Type**: reference
- **Integration**: ATR listed in the AI SDKs awesome-list
- **Evidence**: <https://github.com/e2b-dev/awesome-ai-sdks/pull/194>
- **Since**: 2026-05-16
- **Status**: in-review

### Puliczek/awesome-mcp-security
- **Org**: Puliczek (independent)
- **Type**: reference
- **Integration**: ATR listed in MCP threat-detection tools
- **Evidence**: Puliczek/awesome-mcp-security
- **Since**: 2026-04-21
- **Status**: in-review

---

## Tier 4 — Commercial implementations

Vendors offering commercial support, hosted engines, or enterprise SLAs
around ATR. Listed when the vendor has confirmed publicly that they ship
ATR as a product feature.

### PanGuard AI
- **Org**: Panguard AI, Inc.
- **Type**: engine
- **Integration**: Hosted ATR engine + enterprise SLAs, compliance evidence module, and runtime guardrails
- **Evidence**: <https://panguard.ai>
- **Since**: 2026-04-22
- **Status**: shipped

*Vendors wishing to be listed here must contact `contact@agentthreatrule.org`
with evidence that ATR is a documented product feature in their public
docs.*

---

## Removed entries

None to date. If an adopter is moved out of an active tier due to project
archival or removal of ATR support, the entry is moved here with a
one-line note and the original "Since" date is preserved.
