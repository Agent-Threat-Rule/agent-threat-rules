# ATR → ETSI TS 104 223 / UK AI Cyber Security Code of Practice Mapping

Version: 0.1.0 (INTERNAL DRAFT — not published)
Status: Draft alignment mapping for ETSI TS 104 223 V1.1.1 and the UK NCSC/DSIT AI Cyber Security Code of Practice
Date: 2026-06-12
Editor: Adam Lin (林冠辛) <adam@agentthreatrule.org>
Mapped corpus: Agent Threat Rules v3.5.8 (793 rules / 10 categories; disk == data/stats.json on 2026-07-12)
Reference frameworks:
  - ETSI TS 104 223 V1.1.1 (2025-04) "Securing Artificial Intelligence (SAI); Baseline Cyber Security Requirements for AI Models and Systems"
  - UK AI Cyber Security Code of Practice (DSIT / NCSC), "Code of practice for the cyber security of AI"

---

## 1. Purpose

This document maps the Agent Threat Rules (ATR) detection corpus to the principle
structure shared by ETSI TS 104 223 and the UK AI Cyber Security Code of Practice.
The two documents share the same 13 core principles; ETSI TS 104 223 expands them
into 72 trackable provisions (per ETSI's own press/ecosystem material — the
13 principles and clause numbering (5.x.y) confirmed via reader proxy 2026-06-13; provision total (~60-72) not finally confirmed against the paywalled official PDF; see §5.3)
across 5 AI-lifecycle phases. The UK Code of Practice presents the same 13
principles with its own numbered provisions.

This is an **alignment / informative-reference mapping**. It demonstrates where ATR
detection rules supply runtime evidence for provisions in these frameworks. It is
**NOT** a claim that ETSI or the UK government (DSIT/NCSC) has adopted, endorsed,
reviewed, or certified ATR. No participation or submission channel is asserted.

For each relevant principle, this mapping cites ≥1 real ATR rule by its public
`ATR-YYYY-NNNNN` identifier. Every cited rule ID and title was read from the rule
YAML on disk on 2026-06-12.

## 2. Background

### 2.1 The shared 13 principles and 5 lifecycle phases

ETSI TS 104 223 and the UK Code of Practice organize requirements under 13 core
principles, grouped into 5 AI-lifecycle phases:

| Phase | Principles |
|-------|------------|
| Secure Design | 1 Awareness · 2 Secure design · 3 Threat evaluation · 4 Human responsibility |
| Secure Development | 5 Asset protection · 6 Infrastructure security · 7 Supply chain security · 8 Documentation · 9 Testing and evaluation |
| Secure Deployment | 10 Communication and processes with end-users and affected entities |
| Secure Maintenance | 11 Updates, patches and mitigations · 12 Monitor system behaviour |
| Secure End of Life | 13 Data and model disposal |

(ETSI principle titles per ETSI press material; ETSI per-provision clause numbering
and verbatim provision text in §4 are from the ETSI TS 104 223 PDF, retrieved
2026-06-12 via reader proxy — see §5.3 for the count-reconciliation caveat. UK
provision wording per the UK Code of Practice text.)

### 2.2 Where ATR fits

ATR is a runtime detection-rule corpus for AI-agent attacks. Its evidence is
strongest for the provisions of these frameworks that concern:

- **Secure design (Principle 2)** — withstanding adversarial inputs / prompt
  injection / unexpected inputs.
- **Supply chain security (Principle 7)** — malicious skills / poisoned tool
  packages / known-vulnerable agent components.
- **Testing and evaluation (Principle 9)** — security-assessment evidence, here
  expressed as machine-checkable rules with bundled true-positive / true-negative
  test cases.
- **Monitor system behaviour (Principle 12)** — logging system/user actions and
  detecting anomalies in model inputs and outputs at runtime.

ATR does NOT supply evidence for governance-only, organisational, or physical
provisions (e.g. awareness training programmes, end-of-life data disposal, human-
accountability policy). Those are out of scope for a runtime detection corpus and
are marked accordingly in §5 (Open Items).

## 3. Claim Boundary

- "Alignment" and "mapping" only. No adoption / endorsement / certification by
  ETSI, DSIT, or NCSC is claimed or implied.
- ETSI TS 104 223 is a published Technical Specification; ATR is an independent
  open-source project. Citing the standard here is a public-document cross-
  reference, not a relationship.
- Where a provision is only partially addressed by runtime detection (e.g. the
  framework asks for an end-to-end testing *process*; ATR supplies one machine-
  checkable *input* to that process), this is stated explicitly.

## 4. Principle-to-Rule Mapping

Each row cites real ATR rules that supply runtime evidence for the named provision.
"ATR contribution" describes what the rule actually detects; it does not restate the
provision as if ATR fulfils it end to end.

### 4.1 Principle 2 — Secure design (Secure Design phase)

ETSI numbering (verified via primary PDF text, retrieved 2026-06-12 via reader
proxy): Principle 2's provisions are clause **5.1.2-1 … 5.1.2-7**. The most
mapping-relevant is **ETSI 5.1.2-2** (verbatim, abridged): "Developers and System
Operators shall ensure AI systems are designed to withstand adversarial attacks,
unexpected inputs and failure" — the ETSI analogue of UK Code of Practice 2.2
("Developers and System Operators shall ensure that AI systems are designed and
implemented to withstand adversarial AI attacks, unexpected inputs and AI system
failure"). ETSI 5.1.2-3 (audit trail of system operation) and 5.1.2-6 (minimal,
risk-assessed permissions on other systems) are also relevant. Related data/input
sanitisation sits under the Secure Development clauses.

| Provision focus | ATR contribution | Cited rules (verified on disk 2026-06-12) |
|-----------------|------------------|--------------------------------------------|
| Withstand adversarial inputs / prompt injection | Pattern detection of direct and indirect prompt injection and system-prompt override at the LLM I/O boundary | ATR-2026-00001 "Direct Prompt Injection via User Input" (high); ATR-2026-00002 "Indirect Prompt Injection via External Content" (high); ATR-2026-00004 "System Prompt Override Attempt" (critical) |
| Withstand unexpected / encoded evasion inputs | Detection of encoding-evasion and visual-spoofing payloads that bypass naive input filters | ATR-2026-00080 "Encoding-Based Prompt Injection Evasion" (prompt-injection); ATR-2026-00086 "Visual Spoofing via RTL Override, Punycode, and Homoglyph Injection" (high) |
| Sanitise data/inputs against poisoning at design time | Detection of RAG / knowledge-base contamination feeding the model | ATR-2026-00070 "Data Poisoning via RAG and Knowledge Base Contamination" (data-poisoning) |

### 4.2 Principle 4 — Enable human responsibility (Secure Design phase)

The framework requires that humans remain responsible and that AI systems support
meaningful human oversight of autonomous behaviour. ATR contributes runtime signals
where an agent acts without the human-approval step the operator's policy requires.

| Provision focus | ATR contribution | Cited rules (verified on disk) |
|-----------------|------------------|---------------------------------|
| Human oversight of destructive autonomous action | Trace-method rule surfaces destructive tool invocation lacking a prior human-approval span | ATR-2026-00549 "Destructive tool invocation without prior human approval" (critical) |
| Human confirmation before high-risk tool use | Detection of high-risk tool invocation without human confirmation; unauthorized financial action | ATR-2026-00099 "High-Risk Tool Invocation Without Human Confirmation" (low); ATR-2026-00098 "Unauthorized Financial Action by AI Agent" (critical) |
| Bounding autonomous runaway behaviour | Detection of runaway agent loops / single-session tool-call loops | ATR-2026-00050 "Runaway Agent Loop Detection"; ATR-2026-00553 "Runaway tool-call loop within a single session" |

### 4.3 Principle 7 — Secure your supply chain (Secure Development phase)

ETSI numbering (primary PDF, retrieved 2026-06-12): Principle 7's provisions are
clause **5.2.3-1 … 5.2.3-4** (with sub-provisions 5.2.3-2.1 / 5.2.3-2.2). Most
relevant: **ETSI 5.2.3-1** "Developers and System Operators shall follow secure
software supply chain processes for model development"; **5.2.3-2 / 5.2.3-2.1**
(justify + risk-assess use of undocumented/unsecured models or components);
**5.2.3-3** (re-run evaluations on released models before deployment).

The framework requires securing the AI supply chain — components, models, and
(for agents) skills and tools obtained from third parties.

| Provision focus | ATR contribution | Cited rules (verified on disk) |
|-----------------|------------------|---------------------------------|
| Malicious / impersonating skill packages | Detection of skill impersonation and supply-chain attacks; skill squatting/typosquatting | ATR-2026-00060 "MCP Skill Impersonation and Supply Chain Attack"; ATR-2026-00124 "Skill Squatting / Typosquatting" |
| Hidden behaviour in third-party skills | Detection of description-behaviour mismatch and hidden capability in skills | ATR-2026-00061 "Skill Description-Behavior Mismatch"; ATR-2026-00062 "Hidden Capability in MCP Skill" |
| Poisoned tool distribution channels | Detection of MCP tool supply-chain poisoning and compromised tool distribution | ATR-2026-00095 "MCP Tool Supply Chain Poisoning"; ATR-2026-00096 "Skill Registry Poisoning and Compromised Tool Distribution" |
| Known-vulnerable agent components (CVE-mapped) | Runtime detection for disclosed CVEs in agent/LLM infrastructure | ATR-2026-00529 "LiteLLM Proxy SQL Injection (CVE-2026-42208, CISA KEV)" (critical); ATR-2026-00538 "LangChain-ChatChat Unauthenticated MCP STDIO RCE (CVE-2026-30617)" (critical) |

### 4.4 Principle 9 — Conduct appropriate testing and evaluation (Secure Development phase)

ETSI numbering (primary PDF, retrieved 2026-06-12): Principle 9's provisions are
clause **5.2.5-1 … 5.2.5-4** (with sub-provisions 5.2.5-2.1 / 5.2.5-4.1). Most
relevant: **ETSI 5.2.5-1** "Developers shall ensure all released models,
applications and systems undergo security assessment testing" (the ETSI analogue of
UK Code of Practice 9.1, which requires that releases "have been tested as part of a
security assessment process"); **5.2.5-2** (pre-deployment testing) and **5.2.5-2.1**
(independent testers with AI-relevant skills should conduct it).

| Provision focus | ATR contribution | Cited rules / mechanism |
|-----------------|------------------|--------------------------|
| Security-assessment test artefacts | Every conforming ATR rule bundles `test_cases.true_positives` and `test_cases.true_negatives` (ATR-SPEC-v1 §; ≥1 each at experimental maturity, ≥5 each at stable). A rule corpus is therefore a reusable, machine-runnable security-test input to a broader assessment process. | Corpus-wide property; see e.g. ATR-2026-00001, ATR-2026-00549 test blocks |
| Adversarial-input test coverage | The prompt-injection, model-abuse, and tool-poisoning categories double as an adversarial test battery for an agent under evaluation | Categories: prompt-injection (177), model-abuse (10), tool-poisoning (47) — counts per data/stats.json 2026-06-12 |

Note: ATR supplies a machine-checkable *input* to a security-assessment process. It
does not by itself constitute the full testing-and-evaluation programme the
provision requires.

### 4.5 Principle 12 — Monitor your system's behaviour (Secure Maintenance phase)

ETSI numbering (primary PDF, retrieved 2026-06-12): Principle 12's provisions are
clause **5.4.2-1 … 5.4.2-4**. Verbatim (abridged): **ETSI 5.4.2-1** "System
Operators shall log system and user actions supporting compliance, investigation,
remediation"; **ETSI 5.4.2-2** "System Operators should analyse logs detecting
anomalies, breaches, unexpected behavior over time"; 5.4.2-3 (monitor internal
states); 5.4.2-4 (monitor performance for gradual behaviour changes). These map
1:1 onto the UK Code of Practice 12.1 (log system/user actions) and 12.2 (analyse
logs to detect anomalies).

| Provision focus | ATR contribution | Cited rules (verified on disk) |
|-----------------|------------------|---------------------------------|
| Monitor model inputs/outputs for adverse events | Continuous pattern + trace detection across LLM I/O and tool-call boundaries; each match emits a structured event (rule_id, severity, matched selectors) suitable for SIEM ingestion | ATR-2026-00001, ATR-2026-00002 (input side); ATR-2026-00011 "Instruction Injection via Tool Output" (output/tool side) |
| Detect anomalies in agent behaviour over time | Trace/behavioural rules detect goal drift and cross-session/cross-agent leakage anomalies | ATR-2026-00552 "Agent goal drift after environmental pressure injection" (high); ATR-2026-00548 "Cross-agent session context leak across delegation chain" (high) |
| Detect sensitive-data exposure in outputs | Detection of system-prompt / credential / token leakage in agent output | ATR-2026-00020 "System Prompt and Internal Instruction Leakage"; ATR-2026-00021 "Credential and Secret Exposure in Agent Output" |
| Support incident investigation / remediation (logging) | Match output is a structured, attributable record (rule_id + severity + category + matched selectors) consumable by downstream log/SIEM/SOAR pipelines | Corpus-wide property |

### 4.6 Principle 6 — Secure your infrastructure (Secure Development phase) — partial

ETSI numbering (primary PDF, retrieved 2026-06-12): Principle 6's provisions are
clause **5.2.2-1 … 5.2.2-6**. Most relevant: **ETSI 5.2.2-1** (evaluate access
control frameworks for APIs, models, data, and pipelines); **5.2.2-2** (API
controls including rate limiting); **5.2.2-3** (dedicated dev environments with
separation and least-privilege controls).

The framework requires securing the infrastructure hosting AI systems, including
access control and isolation. ATR contributes where an agent attempts to escalate
privilege or escape its execution boundary at runtime.

| Provision focus | ATR contribution | Cited rules (verified on disk) |
|-----------------|------------------|---------------------------------|
| Privilege boundary enforcement | Detection of privilege escalation / admin-function access and agent scope creep | ATR-2026-00040 "Privilege Escalation and Admin Function Access"; ATR-2026-00041 "Agent Scope Creep Detection" |
| Sandbox / isolation escape (CVE-mapped) | Runtime detection for disclosed sandbox-escape and code-execution CVEs in agent infrastructure | ATR-2026-00436 "Enclave VM Sandbox Escape RCE (CVE-2026-27597)"; ATR-2026-00441 "Microsoft Semantic Kernel SessionsPythonPlugin Arbitrary File Write + Startup Persistence (CVE-2026-25592)" |
| Cross-tenant memory-boundary escape | Trace-method rule blocks cross-conversation memory writes that escape tenant scope | ATR-2026-00551 "Cross-conversation memory write (scope-escape via memory store)" (critical) |

Marked partial: ATR addresses the agent-runtime slice of infrastructure security
(privilege, isolation escape at the agent layer). Host/network/cloud infrastructure
hardening is out of scope.

## 5. Coverage Summary and Open Items

### 5.1 Principles with ATR runtime evidence

| Principle | Coverage | Primary ATR categories |
|-----------|----------|------------------------|
| 2 Secure design | Strong | prompt-injection, data-poisoning |
| 4 Human responsibility | Partial | excessive-autonomy, privilege-escalation (trace) |
| 6 Infrastructure security | Partial (agent-layer only) | privilege-escalation |
| 7 Supply chain security | Strong | skill-compromise, tool-poisoning |
| 9 Testing and evaluation | Indirect (supplies test inputs) | all attack categories |
| 12 Monitor system behaviour | Strong | all categories (detection + structured output) |

### 5.2 Principles out of scope for a runtime detection corpus (no claim of coverage)

- Principle 1 (Awareness) — organisational training, not runtime detectable.
- Principle 3 (Threat evaluation) — process/governance; ATR's THREAT-MODEL.md is an
  input but ATR does not perform the operator's risk assessment.
- Principle 5 (Asset protection), Principle 8 (Documentation) — governance/inventory
  provisions; not runtime detection.
- Principle 10 (Communication with end-users) — disclosure/UX provision.
- Principle 11 (Updates, patches and mitigations) — ATR ships CVE-mapped detection
  rules quickly, but patching the underlying component is the operator's action.
- Principle 13 (Data and model disposal) — end-of-life process; out of scope.

### 5.3 Open Items

- ETSI TS 104 223 V1.1.1 per-provision numbering is now POPULATED from the primary
  PDF (etsi.org returns HTTP 403 to direct automated fetch; the PDF body text was
  retrieved 2026-06-12 via the r.jina.ai reader proxy). The clause scheme is clause
  5 = requirements, with phase/principle sub-clauses: Secure Design 5.1 (Principle 2
  = 5.1.2-x), Secure Development 5.2 (Principle 6 = 5.2.2-x, Principle 7 = 5.2.3-x,
  Principle 9 = 5.2.5-x), Secure Maintenance 5.4 (Principle 12 = 5.4.2-x). The
  provision IDs and verbatim text in §4 are from that extraction.
- COUNT RECONCILIATION NEEDED (do before external use): ETSI's own press/ecosystem
  material consistently states **72 provisions**, and this document uses 72. The
  proxy extraction enumerated provisions only up to ~51 distinct `5.x.y-N` IDs —
  almost certainly because the extraction was partial (it captured the five
  principles queried plus context, not all 13). Treat 72 as the published figure and
  the proxy enumeration as incomplete. A human should open the ETSI PDF in a browser
  to (a) confirm the 72 total, (b) confirm the exact provision IDs/text quoted in §4
  render identically, and (c) capture any provisions for principles not queried here.
- Provision wording in §4 is now from the ETSI PDF where quoted as "ETSI 5.x.y-N";
  the parallel UK Code of Practice wording is retained where it aids the reader. The
  two frameworks share the 13 principles but number provisions differently.
- This mapping cites provisions where ATR supplies evidence; it does not claim
  full provision coverage of either framework.
- Rule counts move daily via auto-crystallize and ecosystem PRs. The counts here
  (462 total / category counts in §4.4) were `find rules -name "*.yaml" | wc -l` and
  data/stats.json on 2026-06-12. Re-verify before any external citation.

## 6. References

### 6.1 Frameworks

- ETSI TS 104 223 V1.1.1 (2025-04), Securing Artificial Intelligence (SAI);
  Baseline Cyber Security Requirements for AI Models and Systems.
  https://www.etsi.org/deliver/etsi_ts/104200_104299/104223/01.01.01_60/ts_104223v010101p.pdf
  (full PDF returns HTTP 403 to direct automated fetch on 2026-06-12; the PDF body
  text — used for the §4 provision IDs/wording — was retrieved via the r.jina.ai
  reader proxy over the same URL. The 13-principle / 72-provision / 5-phase summary
  is also corroborated by the ETSI press release
  https://www.etsi.org/newsroom/press-releases/2627-etsi-releases-world-leading-standard-for-securing-ai/
  Note the standard is also published in EN form as ETSI EN 304 223; the TS and EN
  share the principle/provision structure.)
- UK AI Cyber Security Code of Practice (DSIT / NCSC), Code of practice for the
  cyber security of AI.
  https://www.gov.uk/government/publications/ai-cyber-security-code-of-practice/code-of-practice-for-the-cyber-security-of-ai

### 6.2 ATR

- ATR-SPEC-v1.md — rule format, identifier scheme, evaluation semantics, test-case
  requirements.
- data/stats.json — canonical rule-count record.
- spec/mappings/atr-to-nist-csf-2.0.md — companion mapping (same informative-
  reference convention).
