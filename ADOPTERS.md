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

### NIST AI RMF — community OSCAL catalog (submission in review)
- **Org**: ATR maintainers (community contribution; NOT a NIST publication)
- **Type**: reference
- **Integration**: Community-authored OSCAL catalog covering NIST AI RMF (72 controls + 31 cross-reference links), CC0-licensed, self-published at Agent-Threat-Rule/ai-rmf-oscal-catalog. The catalog was submitted to the NIST OSCAL team; the initial PR usnistgov/oscal-content#333 was closed and reopened as a scope-aligned rework, usnistgov/oscal-content#338 (currently OPEN, in review). The ATR maintainers are awaiting NIST direction. Listed here for transparency about the submission, NOT as evidence of NIST endorsement.
- **Evidence**: <https://github.com/usnistgov/oscal-content/pull/338>
- **Since**: 2026-05-10 (community catalog published; PR opened 2026-05-21)
- **Status**: in-review

### OpenTelemetry — semantic-conventions-genai
- **Org**: CNCF / OpenTelemetry GenAI SIG
- **Type**: reference
- **Integration**: Proposal for `agent.threat.detection.*` semantic-convention attributes (which ATR populates on agent spans) is in review
- **Evidence**: <https://github.com/open-telemetry/semantic-conventions-genai/pull/165>
- **Since**: 2026-05-17
- **Status**: in-review

### OWASP AI Exchange
- **Org**: OWASP Foundation (AI Exchange / AI Security & Privacy Guide)
- **Type**: reference
- **Integration**: Proposal to add Agent Threat Rules to the OWASP AI Exchange guidance as a referenceable agent-threat detection ruleset
- **Evidence**: <https://github.com/OWASP/www-project-ai-security-and-privacy-guide/pull/181>
- **Since**: 2026-06-16
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
- **Evidence**: <https://github.com/NVIDIA/garak/pull/1676>
- **Since**: 2026-05-20
- **Status**: in-review

### SigmaHQ
- **Org**: SigmaHQ
- **Type**: adapter
- **Integration**: Cross-listing in the Sigma tools directory; agent-threat-rules listed as a sibling detection-rule format
- **Evidence**: <https://github.com/SigmaHQ/sigma/pull/6015>
- **Since**: 2026-05-09
- **Status**: shipped

### Microsoft PyRIT
- **Org**: Microsoft
- **Type**: rule-import
- **Integration**: ATR adversarial-payload dataset loader merged into PyRIT (PR #1715, merged 2026-05-27 by maintainer Roman Lutz); a follow-up AgentThreatRulesScorer (PR #1893) is in review
- **Evidence**: <https://github.com/microsoft/PyRIT/pull/1715>
- **Since**: 2026-05-27
- **Status**: shipped

### Microsoft Agent Framework
- **Org**: Microsoft
- **Type**: adapter
- **Integration**: Sample showing ATR as a deterministic action-boundary validator in the Microsoft Agent Framework
- **Evidence**: <https://github.com/microsoft/agent-framework/pull/6528>
- **Since**: 2026-06-16
- **Status**: in-review

### OpenAI Guardrails
- **Org**: OpenAI
- **Type**: adapter
- **Integration**: Optional ATR deterministic text check contributed to the OpenAI Guardrails Python SDK
- **Evidence**: <https://github.com/openai/openai-guardrails-python/pull/77>
- **Since**: 2026-06-16
- **Status**: in-review

### Cisco mcp-scanner
- **Org**: Cisco
- **Type**: rule-import
- **Integration**: ATR-derived tool_shadowing YARA rule contributed to the Cisco mcp-scanner detection set
- **Evidence**: <https://github.com/cisco-ai-defense/mcp-scanner/pull/194>
- **Since**: 2026-06-16
- **Status**: in-review

### Splunk security_content
- **Org**: Splunk
- **Type**: rule-import
- **Integration**: Three ATR-derived MCP detections contributed to the Splunk Suspicious MCP Activity analytic story
- **Evidence**: <https://github.com/splunk/security_content/pull/4128>
- **Since**: 2026-06-16
- **Status**: in-review

### Dify
- **Org**: ATR maintainers (plugin listed in the Dify plugin marketplace; NOT a Dify-core adoption or integration)
- **Type**: adapter
- **Integration**: ATR available as a reviewed plugin in the Dify plugin marketplace (146k★ platform)
- **Evidence**: <https://github.com/langgenius/dify-plugins/pull/2584>
- **Since**: 2026-06-22
- **Status**: shipped

### rulezet
- **Org**: rulezet (independent project, ~50★; PR merged by external maintainer)
- **Type**: adapter
- **Integration**: ATR rule-format adapter merged into rulezet-core, letting rulezet ingest and translate ATR-format rules
- **Evidence**: <https://github.com/rulezet/rulezet-core/pull/50>
- **Since**: 2026-06-18
- **Status**: shipped

### Tencent AI-Infra-Guard
- **Org**: Tencent
- **Type**: rule-import
- **Integration**: ATR-derived MCP threat-detection rules (tool poisoning, credential exfiltration) merged into Tencent's open-source AI-Infra-Guard scanner
- **Evidence**: <https://github.com/Tencent/AI-Infra-Guard/pull/422>
- **Since**: 2026-06-23
- **Status**: shipped

### Google ADK
- **Org**: Google
- **Type**: reference
- **Integration**: ATR guardrail plugin documented as an integration in the official Google Agent Development Kit (ADK) docs (the earlier adk-python sample PR closed unmerged; the docs integration was merged by a Google maintainer)
- **Evidence**: <https://github.com/google/adk-docs/pull/1850>
- **Since**: 2026-06-24
- **Status**: shipped

### AMD GAIA
- **Org**: AMD
- **Type**: reference
- **Integration**: ATR endpoint-guard integration pattern documented in the AMD GAIA docs
- **Evidence**: <https://github.com/amd/gaia/pull/1809>
- **Since**: 2026-06-24
- **Status**: shipped

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

### CryptoAILab/Awesome-LM-SSP
- **Org**: CryptoAILab (independent)
- **Type**: reference
- **Integration**: ATR listed in the LLM safety & security awesome-list
- **Evidence**: <https://github.com/CryptoAILab/Awesome-LM-SSP/pull/108>
- **Since**: 2026-04-02
- **Status**: shipped

### precize/Agentic-AI-Top10-Vulnerability
- **Org**: precize (third-party community repo; NOT an OWASP Foundation publication)
- **Type**: reference
- **Integration**: ATR detection mapping across the agentic-AI vulnerability categories in a third-party catalogue
- **Evidence**: <https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14>
- **Since**: 2026-03-30
- **Status**: shipped

### wearetyomsmnv/Awesome-LLM-agent-Security
- **Org**: wearetyomsmnv (independent)
- **Type**: reference
- **Integration**: ATR listed in the LLM-agent security tooling awesome-list
- **Evidence**: <https://github.com/wearetyomsmnv/Awesome-LLM-agent-Security/pull/6>
- **Since**: 2026-04-08
- **Status**: shipped

### nibzard/awesome-agentic-patterns
- **Org**: nibzard (independent)
- **Type**: reference
- **Integration**: "Deterministic Threat Rule Scanning" pattern accepted, referencing ATR
- **Evidence**: <https://github.com/nibzard/awesome-agentic-patterns/pull/58>
- **Since**: 2026-04-09
- **Status**: shipped

### TalEliyahu/Awesome-AI-Security
- **Org**: Tal Eliyahu (independent)
- **Type**: reference
- **Integration**: ATR listed in the AI security resource awesome-list
- **Evidence**: <https://github.com/TalEliyahu/Awesome-AI-Security/pull/53>
- **Since**: 2026-04-10
- **Status**: shipped

### cckuailong/awesome-gpt-security
- **Org**: cckuailong (independent)
- **Type**: reference
- **Integration**: ATR listed in the Detecting section of the awesome-gpt-security list
- **Evidence**: <https://github.com/cckuailong/awesome-gpt-security/pull/39>
- **Since**: 2026-05-11
- **Status**: shipped

### Joe-B-Security/awesome-prompt-injection
- **Org**: Joe B (independent)
- **Type**: reference
- **Integration**: ATR listed in the Tools section of the awesome-prompt-injection list
- **Evidence**: <https://github.com/Joe-B-Security/awesome-prompt-injection/pull/45>
- **Since**: 2026-06-02
- **Status**: shipped

### ProjectRecon/awesome-ai-agents-security
- **Org**: ProjectRecon (independent)
- **Type**: reference
- **Integration**: ATR listed in the Static Analysis & Linters section of the awesome-ai-agents-security list
- **Evidence**: <https://github.com/ProjectRecon/awesome-ai-agents-security/pull/17>
- **Since**: 2026-06-12
- **Status**: shipped

---

## Tier 4 — Commercial implementations

Vendors offering commercial support, hosted engines, or enterprise SLAs
around ATR. Listed when the vendor has confirmed publicly that they ship
ATR as a product feature.

*Vendors wishing to be listed here must contact `contact@agentthreatrule.org`
with evidence that ATR is a documented product feature in their public
docs.*

---

## Removed entries

If an adopter is moved out of an active tier due to project archival, removal
of ATR support, a closed/unmerged PR, or unverifiable evidence, the entry is
noted here with the reason and the original "Since" date preserved.

- **IBM mcp-context-forge** (was Tier 2 · since 2026-05-09) — evidence PR IBM/mcp-context-forge#4109 was closed without merge. Removed 2026-06-14.
- **Portkey AI Gateway** (was Tier 2 · since 2026-05-16) — evidence PR Portkey-AI/gateway#1652 was closed without merge. Removed 2026-06-14.
- **Semgrep** (was Tier 2 · since 2026-05-10) — no merged PR or verifiable evidence link could be located. Removed 2026-06-14.
- **Puliczek/awesome-mcp-security** (was Tier 3 · since 2026-04-21) — ATR is not present in the project README; listing could not be verified. Removed 2026-06-14.
- **aaif-goose (block/goose)** (was Tier 2 · since 2026-05-19) — evidence PR aaif-goose/goose#9304 is goose's generic PreToolUse denial hook; the PR body does not reference ATR, so it is not an ATR-specific integration. Removed 2026-06-16.
