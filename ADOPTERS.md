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
- **Integration**: Four ATR-derived regression scenarios contributed to the harness (goal hijack, MCP trust boundary, prompt injection, sensitive-data disclosure). The scenario files carry no ATR attribution upstream, so this is a contribution to the harness rather than a reference to ATR by it
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

### FINOS Common Cloud Controls
- **Org**: FINOS (Fintech Open Source Foundation, a Linux Foundation project)
- **Type**: reference
- **Integration**: ATR guideline-mappings merged into the Common Cloud Controls catalogue (CN01/CN02/CN04/CN06) with Gemara MappingReference entries
- **Evidence**: <https://github.com/finos/common-cloud-controls/pull/986>
- **Since**: 2026-07-02
- **Status**: shipped

---

### Gemara
- **Org**: Gemara project (OSPS / interoperability)
- **Type**: reference
- **Integration**: ATR detection categories mapped onto Gemara capability-catalog format; the example directory under `examples/ai-agent/` is the project's only worked example. Contributed by ATR, merged by Gemara maintainer jpower432
- **Evidence**: <https://github.com/gemaraproj/gemara/pull/428>
- **Since**: 2026-07-21
- **Still-present**: examples/ai-agent/atr-categories-to-capabilities-mapping.yaml contains "ATR"
- **Status**: shipped

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
- **Integration**: ATR rule pack, auto-synced weekly auto-synced weekly into the Agent Governance Toolkit detection layer
- **Evidence**: <https://github.com/microsoft/agent-governance-toolkit/pull/1277>
- **Since**: 2026-04-26
- **Status**: shipped

### Gen Digital Sage
- **Org**: Gen Digital (Norton / Avast / LifeLock parent)
- **Type**: rule-import
- **Integration**: ATR-derived agent-layer threat patterns contributed to the Sage agentic-AI risk-scoring layer
- **Evidence**: <https://github.com/gendigitalinc/sage/pull/33>
- **Since**: 2026-05-11
- **Status**: shipped

---

### NVIDIA NeMo Agent Toolkit
- **Org**: NVIDIA
- **Type**: reference
- **Integration**: NVIDIA's own README lists `NeMo-Agent-Toolkit-ATR` alongside the Tavily and Redis plugins under the Public Plugin API for Third-Party Tools. Written and merged by NVIDIA maintainer bbednarski9 — ATR did not open this PR
- **Evidence**: <https://github.com/NVIDIA/NeMo-Agent-Toolkit/pull/2039>
- **Since**: 2026-06-10
- **Still-present**: README.md contains "NeMo-Agent-Toolkit-ATR"
- **Status**: shipped

## Tier 2 — Open-source tooling & SDK integrations

Open-source developer tools, frameworks, and SDKs that have integrated ATR.
Listed when the integration code has been merged or released.

### AG2 (AutoGen)
- **Org**: AG2 (ag2ai)
- **Type**: adapter
- **Integration**: `ATRGuardrail` contrib capability that scans tool output and LLM input against the ATR ruleset via the `pyatr` engine; merged into the ag2-classic framework and since maintained by an AG2 maintainer
- **Evidence**: <https://github.com/ag2ai/ag2classic/blob/main/autogen/agentchat/contrib/capabilities/atr_guardrail.py>
- **Since**: 2026-06-28
- **Status**: shipped

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
- **Integration**: ATR adversarial-payload dataset loader merged into PyRIT (PR #1715, merged 2026-05-27 by maintainer Roman Lutz). A follow-up AgentThreatRulesScorer (PR #1893) was merged 2026-08-17 and reverted 2026-08-18 by PR #2410; only the dataset loader ships today
- **Evidence**: <https://github.com/microsoft/PyRIT/pull/1715>
- **Since**: 2026-05-27
- **Status**: shipped

### Microsoft Agent Framework
- **Org**: Microsoft
- **Type**: adapter
- **Integration**: Sample showing ATR as a deterministic action-boundary validator in the Microsoft Agent Framework
- **Evidence**: <https://github.com/microsoft/agent-framework/pull/6528>
- **Since**: 2026-06-16
- **Status**: shipped

### Cisco AI BOM
- **Org**: Cisco
- **Type**: adapter
- **Integration**: `security_enrichment.py` uses pyatr to tag detected skill, prompt, agent and MCP components with MITRE ATLAS technique IDs
- **Evidence**: <https://github.com/cisco-ai-defense/aibom/pull/53>
- **Since**: 2026-07-08
- **Still-present**: aibom/src/aibom/security_enrichment.py contains "pyatr"
- **Status**: shipped

### Google ADK
- **Org**: Google
- **Type**: adapter
- **Integration**: ATR guardrail plugin documented in Google's official ADK integration catalogue, live at adk.dev/integrations/atr-guardrail/. Contributed by ATR, merged by Google maintainer koverholt
- **Evidence**: <https://github.com/google/adk-docs/pull/1850>
- **Since**: 2026-06-24
- **Still-present**: docs/integrations/atr-guardrail.md contains "Agent Threat Rules"
- **Status**: shipped

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

### rulezet (CIRCL)
- **Org**: CIRCL (rulezet rule-management platform)
- **Type**: adapter
- **Integration**: `atr_format.py` importer/converter mirroring the existing `sigma_format` module (24 unit tests) — ATR rules are manageable as a first-class format in rulezet
- **Evidence**: <https://github.com/rulezet/rulezet-core/pull/50>
- **Since**: 2026-06-18
- **Status**: shipped

### NVIDIA NeMo Guardrails
- **Org**: NVIDIA
- **Type**: rule-import
- **Integration**: Agent Threat Rules detection rail for the NeMo Guardrails library
- **Evidence**: <https://github.com/NVIDIA-NeMo/Guardrails/pull/2251>
- **Since**: 2026-06-04
- **Status**: in-review

### Cisco a2a-scanner
- **Org**: Cisco
- **Type**: rule-import
- **Integration**: ATR detection pack for scanning agent-to-agent (A2A) protocol traffic
- **Evidence**: <https://github.com/cisco-ai-defense/a2a-scanner/pull/14>
- **Since**: 2026-06-26
- **Status**: in-review

---

## Tier 3 — Documentation references & awesome-lists

Adopters who reference ATR in public catalogues, awesome-lists, or
documentation indices. Lower-effort inclusion but useful for ecosystem
discoverability.

### killertcell428/aigis
- **Org**: Aigis (independent)
- **Type**: reference
- **Integration**: Aigis↔ATR crosswalk — maps Aigis detection patterns to ATR rule IDs through the shared MITRE ATLAS technique axis, with a two-direction ATLAS coverage-gap analysis; merged into the Aigis repo
- **Evidence**: <https://github.com/killertcell428/aigis/pull/154>
- **Since**: 2026-07-07
- **Still-present**: docs/compliance/ATR_CROSSWALK.md contains "agent-threat-rules"
- **Status**: shipped

### ottosulin/awesome-ai-security
- **Org**: Otto Sulin (independent)
- **Type**: reference
- **Integration**: ATR listed in the MCP Security section
- **Evidence**: <https://github.com/ottosulin/awesome-ai-security/pull/192>
- **Since**: 2026-05-20
- **Still-present**: README.md contains "agent-threat-rules"
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
- **Still-present**: collection/toolkit.md contains "agent-threat-rules"
- **Status**: shipped

### precize/Agentic-AI-Top10-Vulnerability
- **Org**: precize (third-party community repo; NOT an OWASP Foundation publication)
- **Type**: reference
- **Integration**: ATR detection mapping across the agentic-AI vulnerability categories in a third-party catalogue
- **Evidence**: <https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14>
- **Since**: 2026-03-30
- **Still-present**: ATR-DETECTION-MAPPING.md contains "agent-threat-rules"
- **Status**: shipped

### wearetyomsmnv/Awesome-LLM-agent-Security
- **Org**: wearetyomsmnv (independent)
- **Type**: reference
- **Integration**: ATR listed in the LLM-agent security tooling awesome-list
- **Evidence**: <https://github.com/wearetyomsmnv/Awesome-LLM-agent-Security/pull/6>
- **Since**: 2026-04-08
- **Still-present**: README.md contains "agent-threat-rules"
- **Status**: shipped

### nibzard/awesome-agentic-patterns
- **Org**: nibzard (independent)
- **Type**: reference
- **Integration**: "Deterministic Threat Rule Scanning" pattern accepted, referencing ATR
- **Evidence**: <https://github.com/nibzard/awesome-agentic-patterns/pull/58>
- **Since**: 2026-04-09
- **Still-present**: patterns/deterministic-threat-rule-scanning.md contains "agent-threat-rules"
- **Status**: shipped

### OWASP Agentic Skills Top 10
- **Org**: OWASP
- **Type**: reference
- **Integration**: ATR-to-AST crosswalk and the wild-scan dataset accepted as external references; both PRs merged by project lead kenhuangus
- **Evidence**: <https://github.com/OWASP/www-project-agentic-skills-top-10/pull/48>
- **Since**: 2026-07-09
- **Status**: shipped

### xlabs-club/awesome-x-ops
- **Org**: xlabs-club
- **Type**: reference
- **Integration**: ATR added to the English and Simplified-Chinese lists by maintainer l10178 — ATR did not open this PR
- **Evidence**: <https://github.com/xlabs-club/awesome-x-ops/pull/220>
- **Since**: 2026-08-17
- **Still-present**: README.md contains "agent-threat-rules"
- **Status**: shipped

### AMD GAIA
- **Org**: AMD
- **Type**: reference
- **Integration**: Official GAIA integrations doc — guarding the Lemonade model endpoint with an offline ATR input/output guard (prompt-injection detection pattern)
- **Evidence**: <https://github.com/amd/gaia/pull/1809>
- **Since**: 2026-06-24
- **Status**: shipped

### ProjectRecon/awesome-ai-agents-security
- **Org**: ProjectRecon (independent)
- **Type**: reference
- **Integration**: ATR listed in the Static Analysis & Linters section
- **Evidence**: <https://github.com/ProjectRecon/awesome-ai-agents-security/pull/17>
- **Since**: 2026-06-12
- **Still-present**: README.md contains "agent-threat-rules"
- **Status**: shipped

### raphabot/awesome-cybersecurity-agentic-ai
- **Org**: raphabot (independent)
- **Type**: reference
- **Integration**: ATR listed in the Tools section
- **Evidence**: <https://github.com/raphabot/awesome-cybersecurity-agentic-ai/pull/24>
- **Since**: 2026-06-28
- **Still-present**: README.md contains "agent-threat-rules"
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
- **Google ADK** (was Tier 2 · since 2026-06-16) — the samples PR google/adk-python#6130 was closed without merge, so this entry was removed 2026-07-05. The docs integration landed separately in google/adk-docs#1850 and Google ADK is listed again under Tier 2 from that evidence.
- **NVIDIA garak** (was Tier 2 · since 2026-05-20) — evidence PR NVIDIA/garak#1676 was closed without merge on 2026-08-04, withdrawn by its author after four months in changes-requested. Removed 2026-08-23.
- **OpenAI Guardrails** (was Tier 2 · since 2026-06-16) — evidence PR openai/openai-guardrails-python#77 was closed without merge by an OpenAI maintainer on 2026-08-18, who recommended a separately maintained integration instead. Removed 2026-08-23.
- **TalEliyahu/Awesome-AI-Security** (was Tier 3 · since 2026-04-10) — the listing was merged but is no longer present in the project README; it was removed upstream some time before 2026-05-09. Removed 2026-08-23.
