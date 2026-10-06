# ATR → NIST Cybersecurity Framework 2.0 Mapping

Version: 1.1.0
Status: Draft for NIST IR 8596 Informative Reference submission
Date: 2026-06-14
Editor: Adam Lin (林冠辛) <adam@agentthreatrule.org>
Mapped corpus: Agent Threat Rules v3.5.0 (652 rules / 10 categories; per data/stats.json 2026-06-16)
Reference framework: NIST CSF 2.0 (NIST CSWP 29, February 2024)

---

## 1. Purpose

This document maps the Agent Threat Rules (ATR) detection corpus to the NIST
Cybersecurity Framework 2.0 subcategory taxonomy. It is intended as an
Informative Reference submission per [NIST IR 8596 Cyber AI Profile][nist-ir-8596].

For each of the 10 ATR attack-class categories and each of the 5 detection
methods (atr-method-v1.1.md §4), this mapping enumerates the CSF 2.0
subcategories whose implementation guidance can cite ATR Rules as runtime
evidence.

## 2. Background

NIST CSF 2.0 organizes cybersecurity outcomes under six Functions:

| Function | Code | Scope |
|----------|------|-------|
| GOVERN | GV | Cybersecurity governance, risk management strategy, policy |
| IDENTIFY | ID | Asset inventory, risk assessment, supply chain |
| PROTECT | PR | Access control, awareness training, data security |
| DETECT | DE | Continuous monitoring, adverse event detection |
| RESPOND | RS | Incident response, communications, mitigation |
| RECOVER | RC | Recovery planning, communications |

ATR Rules supply primarily **DETECT** outcomes (continuous monitoring of AI
agent runtime events) with secondary contributions to **PROTECT** (preventive
controls expressed as block actions in `detection.response`) and **GOVERN**
(governance over agent autonomy and human-in-the-loop policy).

## 3. Method-to-Function Mapping

Each ATR detection method contributes primarily to one or two CSF Functions:

| ATR Method (atr-method-v1.1.md §4) | Primary Function | Secondary | Rationale |
|------------------------------------|------------------|-----------|-----------|
| `pattern` (regex match) | DETECT | PROTECT | Match-and-block at input boundary; analyst-tractable signatures |
| `signature` (hash / name / URL exact match) | DETECT | PROTECT | Known-bad blocking; sub-millisecond hot-path enforcement |
| `semantic` (LLM-as-judge) | DETECT | — | Intent classification beyond regex; produces analyst-reviewable verdicts |
| `behavioral` (metric threshold) | DETECT | — | Statistical anomaly over time windows |
| `trace` (declarative assertion over span DAG) | DETECT | GOVERN | Silent-failure / scope-drift detection; surfaces policy violations for human review |

## 4. Category-to-Subcategory Mapping

For each of the 10 ATR attack-class categories (SPEC.md §8), the table lists
the CSF 2.0 subcategories the rule corpus supplies evidence for.

### 4.1 prompt-injection (223 rules)

| CSF 2.0 Subcategory | Outcome | ATR Evidence | Rules (examples) |
|---------------------|---------|--------------|------------------|
| DE.CM-09 | Computing hardware and software, runtime environments, and their data are monitored for adverse events | Pattern + trace rules detect direct & indirect prompt injection at LLM I/O boundary and across retrieved-content-to-tool causal chains | ATR-2026-00001 (direct PI), ATR-2026-00550 (untrusted retrieval → privileged tool, trace) |
| DE.AE-02 | Potentially adverse events are analyzed to better understand associated activities | Each Rule's `detection.condition` produces a structured Match output (SPEC.md §7) with rule_id, severity, matched_selectors | All prompt-injection rules |
| PR.IR-01 | Networks and environments are protected from unauthorized logical access and usage | `response.actions: [block_input]` enforces preventive control when Pattern matches | ATR-2026-00001, -00440, -00441 |

### 4.2 tool-poisoning (65 rules)

| CSF 2.0 Subcategory | Outcome | ATR Evidence | Rules (examples) |
|---------------------|---------|--------------|------------------|
| DE.CM-09 | Computing hardware and software monitored | MCP tool description and tool-call argument inspection | ATR-2026-00415, -00529 |
| ID.RA-08 | Processes for receiving, analyzing, and responding to vulnerabilities disclosed are established | CVE-mapped rules (CVE-2026-26030, CVE-2026-2275, CVE-2026-30617, ...) provide runtime detection for known tool-poisoning CVEs | ATR-2026-00529 (litellm SQL), -00538 (langchain-chatchat), -00543 (litellm MCP argv) |
| PR.IR-01 | Networks/environments protected from unauthorized access | `block_tool` action prevents tool execution when poisoned MCP message detected | All tool-poisoning rules with `block_tool` |

### 4.3 context-exfiltration (103 rules)

| CSF 2.0 Subcategory | Outcome | ATR Evidence | Rules (examples) |
|---------------------|---------|--------------|------------------|
| DE.CM-09 | Continuous monitoring for adverse events | Pattern rules detect credential / API key / system prompt leakage attempts | ATR-2026-00076, -00086 |
| DE.CM-01 | Networks and network services are monitored | Trace rule 00548 detects cross-agent session leakage across delegation chains | ATR-2026-00548 (cross-agent context leak, trace) |
| PR.DS-01 | The confidentiality, integrity, and availability of data-at-rest are protected | Block actions prevent exfiltration when triggered | All context-exfil rules with `block_*` |

### 4.4 agent-manipulation (106 rules)

| CSF 2.0 Subcategory | Outcome | ATR Evidence | Rules (examples) |
|---------------------|---------|--------------|------------------|
| DE.AE-02 | Adverse events analyzed | Goal drift, persona switching, role-impersonation pattern detection | ATR-2026-00032, -00074, -00552 (trace) |
| DE.AE-03 | Information is correlated from multiple sources | Trace rule 00552 correlates RETRIEVER / TOOL_RESPONSE pressure spans with AGENT goal-change spans | ATR-2026-00552 (goal drift, composite trace) |
| GV.RM-01 | Cybersecurity risk management strategy is established | Authorization for autonomous goal changes requires policy; trace rules surface deviations | ATR-2026-00552 |

### 4.5 privilege-escalation (35 rules)

| CSF 2.0 Subcategory | Outcome | ATR Evidence | Rules (examples) |
|---------------------|---------|--------------|------------------|
| PR.AA-05 | Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties | Require-primitive trace rule 00549 enforces human-approval predecessor for destructive tools | ATR-2026-00549 (require, trace) |
| PR.IR-01 | Unauthorized access protection | Cross-conversation memory write rule blocks tenant-boundary escapes | ATR-2026-00551 (forbid + cross-attribute, trace) |
| GV.PO-01 | Policy for managing cybersecurity risks is established | Rules surface destructive autonomy that policy did not authorize | ATR-2026-00549, -00551 |

### 4.6 excessive-autonomy (29 rules)

| CSF 2.0 Subcategory | Outcome | ATR Evidence | Rules (examples) |
|---------------------|---------|--------------|------------------|
| GV.PO-01 | Policy for cybersecurity risks established | Rules detect runaway loops, resource exhaustion patterns | ATR-2026-00050, -00051 |
| DE.AE-02 | Adverse events analyzed | Behavioral-method rules (placeholder in v1.1) will use metric thresholds over windows | (behavioral plane, §7 placeholder) |

### 4.7 skill-compromise (45 rules)

| CSF 2.0 Subcategory | Outcome | ATR Evidence | Rules (examples) |
|---------------------|---------|--------------|------------------|
| GV.SC-04 | Suppliers are known and prioritized by criticality | Signature-method rules block known-malicious skill packages by hash / registry URL / package name | ATR-2026-DRAFT-skill-malware (template example in atr-method-v1.1.md §5.5) |
| ID.AM-08 | Systems, hardware, software, services, and data are managed throughout their life cycle | Signature rules supply skill provenance binding | All signature-method rules in skill-compromise |
| DE.CM-09 | Computing software monitored | Static skill scan (`scan_target: skill`) on every SKILL.md ingest | ATR-2026-00451, -00452 |

### 4.8 model-abuse (37 rules)

| CSF 2.0 Subcategory | Outcome | ATR Evidence | Rules (examples) |
|---------------------|---------|--------------|------------------|
| DE.CM-09 | Computing software monitored | Detection of model extraction, fine-tuning abuse | ATR-2026-00072, -00073 |
| ID.RA-01 | Vulnerabilities in assets are identified, validated, and recorded | Known model-abuse CVEs covered | (subset of model-abuse rules) |

### 4.9 model-security (3 rules)

| CSF 2.0 Subcategory | Outcome | ATR Evidence | Rules (examples) |
|---------------------|---------|--------------|------------------|
| PR.PS-04 | Log records are generated and made available for continuous monitoring | Model-security rules emit Match output for downstream SIEM consumption | ATR-2026-00433 (modelcache deserialization RCE) |
| ID.RA-08 | Vulnerability disclosure processes | CVE-mapped model-security rules | ATR-2026-00433 |

### 4.10 data-poisoning (5 rules)

| CSF 2.0 Subcategory | Outcome | ATR Evidence | Rules (examples) |
|---------------------|---------|--------------|------------------|
| GV.SC-08 | Relevant suppliers and other third parties are included in incident planning, response, and recovery activities | Data-poisoning detection feeds supplier-incident coordination | ATR-2026-00073 |
| DE.CM-09 | Continuous monitoring | Training-data corruption pattern detection | (data-poisoning rules) |

## 5. Detect-Plane Coverage Summary

Aggregating across all 10 categories, the ATR corpus contributes to the
following CSF 2.0 DETECT subcategories (the primary contribution area):

| DETECT Subcategory | Coverage | Notes |
|--------------------|----------|-------|
| DE.AE-02 (events analyzed) | Universal | Every Match output is a structured analyzed event |
| DE.AE-03 (info correlated) | High | Composite trace rules correlate multi-span signals |
| DE.AE-04 (events characterized) | High | severity + category + confidence on each Match |
| DE.AE-06 (impact and scope estimated) | Medium | severity rubric per SPEC.md §4; scope inferred from trace |
| DE.AE-08 (incidents declared) | Medium | response.actions includes `escalate` |
| DE.CM-01 (networks monitored) | Partial | OpenInference trace ingest provides network-adjacent view |
| DE.CM-03 (personnel activity monitored) | Partial | Human-approval signals tracked in trace rules |
| DE.CM-06 (external service providers monitored) | High | MCP server monitoring covers external services |
| DE.CM-09 (computing hardware/software monitored) | Universal | Core ATR scope |

## 6. PROTECT-Plane Contribution

The `response.actions` vocabulary (SPEC.md Appendix A) maps onto CSF PROTECT
preventive controls:

| ATR Action | CSF 2.0 Subcategory |
|------------|---------------------|
| `block_input` / `block_output` / `block_request` | PR.IR-01 (unauthorized access protection) |
| `block_tool` | PR.IR-01 + PR.AA-05 (access permissions) |
| `quarantine_session` / `quarantine_artifact` | PR.IR-04 (asset segregation) |
| `redact_match` | PR.DS-02 (data-in-transit protected) |
| `revoke_credential` | PR.AA-02 (credentials issued, managed, revoked) |
| `rate_limit_source` | PR.IR-03 (mechanisms to achieve resilience) |

## 7. GOVERN-Plane Contribution

Trace-method rules surface policy violations that require GOVERN-Function
attention:

| ATR Trace Rule Pattern | CSF 2.0 Subcategory |
|------------------------|---------------------|
| Missing human-approval predecessor (require primitive) | GV.PO-01 (policy established), PR.AA-05 |
| Cross-tenant scope drift (invariant primitive) | GV.SC-04 (supplier criticality), GV.OC-04 (legal/regulatory requirements understood) |
| Goal drift / autonomy escape (composite) | GV.RM-01 (risk management strategy), GV.SC-07 (risks from suppliers monitored) |

## 8. Implementation Guidance (for NIST IR 8596 reviewers)

An organization seeking to use ATR as an Informative Reference for CSF 2.0
implementation:

1. **Deploy an ATR-conformant engine.** Reference TypeScript engine at
   `npm:agent-threat-rules`. Engines declare conformance per SPEC.md §11
   (L1 = parses corpus; L2 = passes conformance test suite; L3 = emits
   match output in 2+ interchange formats).

2. **Select a Runtime Profile** (atr-method-v1.1.md §4.1):
   - `deterministic` (pattern + signature only) for in-line hot path.
   - `assisted` (semantic + behavioral + trace) for async sidecar.
   - Both for full coverage.

3. **Configure response actions** per organizational risk tolerance. The
   `response.actions` field is a RECOMMENDATION; engines do NOT execute
   automatically without explicit operator policy (SPEC.md §5.5).

4. **Emit Match output to existing SIEM / SOAR / OSCAL pipelines.** The
   `compliance.oscal_assessment_objective` field (atr-method-v1.1.md §9.1)
   lets each Match attach as observation evidence beneath an OSCAL
   Assessment Plan / Result.

5. **Measure coverage** via the conformance test suite (
   `conformance/v1.0/`) and report the suite version in any conformance
   claim (SPEC.md §12).

## 9. Open Items

- Behavioral-method (CSF DE.CM continuous monitoring) is a normative
  placeholder in atr-method-v1.1.md §7. Full specification pending v1.2.
- The mapping above lists subcategories where ATR Rules supply evidence;
  it does NOT claim full CSF subcategory coverage. CSF subcategories not
  listed are not in scope for AI agent runtime detection.
- ATR currently maps to CSF 2.0 (Feb 2024 baseline). When NIST IR 8596
  publishes the Cyber AI Profile with AI-specific subcategory guidance,
  this document will be updated to align.

## 10. References

### 10.1 Normative

- [NIST CSF 2.0 / NIST CSWP 29][nist-csf-2] (Feb 2024)
- [NIST IR 8596: Cyber AI Profile Concept Paper][nist-ir-8596]
- [SPEC.md][atr-spec] — ATR Core Specification v1.0.0
- [atr-method-v1.1.md][atr-method] — ATR Method Extensions v1.1.0

### 10.2 Cross-references

- ATR rules referencing this mapping carry the field
  `references.nist_csf: [<subcategory-id>...]` per atr-method-v1.1.md §9.3.
- The STIX 2.1 x-atr-rule extension v1.1 carries the same data under
  `compliance_refs.nist_csf` (spec/stix-extension/x-atr-rule-schema.json).

[nist-csf-2]: https://www.nist.gov/cyberframework
[nist-ir-8596]: https://csrc.nist.gov/pubs/ir/8596/ipd
[atr-spec]: ../../SPEC.md
[atr-method]: ../atr-method-v1.1.md
