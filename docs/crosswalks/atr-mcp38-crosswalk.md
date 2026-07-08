# ATR -> MCP-38 Threat Taxonomy Crosswalk (OWASP-axis join)

This document maps the **MCP-38 threat taxonomy** to Agent Threat Rules (ATR)
detection content, so an operator working from the MCP-38 paper can see which
MCP threats already have executable ATR coverage and which are gaps.

Source taxonomy: **MCP-38: A Comprehensive Threat Taxonomy for Model Context Protocol Systems (v1.0)**,
Yi Ting Shen, Kentaroh Toyoda, Alex Leung, arXiv:2603.18063 (CC BY 4.0).
38 protocol-specific threats (MCP-01 ... MCP-38).

## Methodology -- read this first (it is a 2-hop approximation)

**This is NOT a direct MCP-id-to-ATR-id mapping.** ATR rules do not carry
MCP-38 ids. The crosswalk is a **2-hop join through the OWASP axis**:

    MCP-38 threat  --[paper Table 4]-->  OWASP code  --[ATR rule metadata]-->  ATR rules

- **Hop 1 (MCP-38 -> OWASP).** The paper's Table 4 assigns each MCP threat one
  or more OWASP LLM Top 10 (2025) and OWASP Agentic (2026) codes. Those
  assignments are extracted verbatim into `data/mcp38-mappings.json` and have
  primary-source backing in the paper.
- **Hop 2 (OWASP -> ATR).** Every ATR rule tags `references.owasp_llm` and
  `references.owasp_agentic`. The generator reads those tags and joins on the
  **bare code prefix only** (`LLM01`..`LLM10`, `ASI01`..`ASI10`). The
  descriptive name after the code drifts across the ATR corpus and between ATR
  and the paper, so it is deliberately ignored for joining.

Consequences to keep in mind when reading the tables below:

- A threat shown as **covered** means ATR has rules tagged with an OWASP code
  the paper assigns to that threat -- it is *topical* coverage, not a proof that
  a specific rule fires on that specific MCP mechanism. OWASP buckets are broad
  (e.g. LLM01 Prompt Injection maps to five different MCP threats), so a single
  rule set is credited to several MCP threats it is only loosely related to.
- A threat shown as an **OWASP-axis gap** (no rules via its OWASP codes) is a
  strong signal of missing coverage, but a rule using different terminology
  could still be adjacent. Treat gaps as an authoring roadmap, not proven
  absence.
- For a hand-verified, rule-id-level MCP-38 mapping that names specific rules
  per threat, see [`docs/MCP-38-MAPPING.md`](../MCP-38-MAPPING.md). This
  generated document is the *reproducible, corpus-wide* companion to it.

All ATR-side numbers below are computed at build time from the rule YAML; none
are hard-coded. Regenerate with `python3 scripts/generate-mcp-crosswalk.py`.

## Coverage summary

- ATR rules total (join surface): 708
- MCP-38 threats total: 38
- MCP-38 threats with >=1 ATR rule via the OWASP axis: 38 (100%)
- MCP-38 threats with no ATR rule via the OWASP axis: 0

By MCP-38 tactic category (paper section 4 grouping):

| Tactic category | Label | Threats | Covered (OWASP-axis) |
|---|---|---|---|
| I | Semantic Manipulation & Poisoning | 6 | 6 |
| II | Prompt Injection & Boundary Breaking / Code Execution | 7 | 7 |
| III | Identity, Trust, Transport & Supply Chain | 11 | 11 |
| IV | Access Control & Agent Logic Drift | 8 | 8 |
| V | Data Exfiltration & Resource Abuse | 6 | 6 |

## Per-threat crosswalk

`ATR rules` counts distinct rule ids reachable from the threat's OWASP codes
(union across all its LLM and ASI codes). `ATR categories` are the ATR rule
directories those rules fall in. STRIDE codes are the paper's (S/T/R/I/D/E).

| MCP-38 | Threat | STRIDE | OWASP LLM | OWASP Agentic | ATR rules | ATR categories |
|---|---|---|---|---|---|---|
| MCP-01 | Identity Spoofing / Improper Authentication | S | LLM02, LLM06 | ASI03 | 327 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-02 | Credential Theft / Token Theft | S/I | LLM02 | ASI03 | 216 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-03 | Replay Attacks / Session Hijacking | S/R | LLM05 | ASI07, ASI09 | 101 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-04 | Privilege Escalation & Confused Deputy | T/E | LLM06 | ASI02, ASI03 | 236 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-05 | Excessive Permissions / Overexposure | E | LLM06 | ASI02 | 168 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-06 | Improper Multitenancy & Isolation Failure | I/E | LLM08 | ASI08 | 69 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-07 | Command Injection | T/E | LLM05 | ASI05 | 102 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-08 | File System Exposure / Path Traversal | I | LLM05 | ASI05 | 102 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-09 | Traditional Web Vulnerabilities (SSRF, XSS) | T/I/D | LLM01 | ASI01, ASI05 | 577 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-10 | Tool Description Poisoning | T | LLM03 | ASI04 | 84 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-11 | Full Schema Poisoning (FSP) | T | LLM04 | ASI06 | 88 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-12 | Resource Content Poisoning | T | LLM04 | ASI01, ASI06 | 538 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-13 | Tool Shadowing / Name Spoofing | S/E | LLM03 | ASI04 | 84 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-14 | Cross-Server Tool Shadowing | S/E | LLM03 | ASI04 | 84 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-15 | Preference Manipulation Attack (MPMA) | T | LLM01, LLM03 | ASI01, ASI04 | 568 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-16 | Rug Pull / Dynamic Behavior Change | T/R | LLM03 | ASI04 | 84 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-17 | Parasitic Toolchain / Connector Chaining | T/D | LLM05, LLM06 | ASI02 | 205 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-18 | Shadow MCP Servers | S/I | LLM03 | ASI04 | 84 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-19 | Prompt Injection (Direct) | I | LLM01 | ASI01 | 524 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-20 | Prompt Injection (Indirect via Data) | I | LLM01, LLM04 | ASI01, ASI06 | 583 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-21 | Overreliance on LLM Safeguards | E | LLM09 | ASI09 | 33 | agent-manipulation, context-exfiltration, excessive-autonomy, prompt-injection, skill-compromise, tool-poisoning |
| MCP-22 | Insecure Human-in-the-Loop Bypass | E | LLM06 | ASI09 | 160 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-23 | Consent / Approval Fatigue | E | LLM06 | ASI09 | 160 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-24 | Data Exfiltration via Tool Output | I | LLM02 | ASI02 | 178 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-25 | Privacy Inversion / Data Aggregation Leakage | I | LLM02 | ASI06 | 216 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-26 | Supply Chain Compromise | T/S | LLM03 | ASI04 | 84 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-27 | Missing Integrity Verification | T | LLM03 | ASI04 | 84 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-28 | Man-in-the-Middle / Transport Tampering | T/I | LLM02, LLM07 | ASI07 | 176 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-29 | Protocol Gaps / Weak Transport Security | S/T/D | LLM02, LLM07 | ASI07 | 176 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-30 | Insecure stdio Descriptor Handling | T | LLM05 | ASI05 | 102 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-31 | MCP Endpoint / DNS Rebinding | S | LLM03 | ASI04 | 84 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-32 | Unrestricted Network Access & Lateral Movement | I/E | LLM06 | ASI08 | 191 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-33 | Resource Exhaustion / Denial of Wallet | D | LLM10 | ASI08 | 59 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-34 | Tool Manifest Reconnaissance | I | LLM03 | ASI04 | 84 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-35 | Planning / Agent Logic Drift | T | LLM09 | ASI01, ASI10 | 476 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-36 | Multi-Agent Context Hijacking | T | LLM01 | ASI07 | 489 | agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-37 | Sandbox Escape | E | LLM05 | ASI05 | 102 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| MCP-38 | Invisible Agent Activity / No Observability | R | LLM06 | ASI10 | 153 | agent-manipulation, context-exfiltration, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |

## OWASP-code join table (the actual key)

The bare OWASP codes each side carries, and how many ATR rules tag each. This
is the literal join surface; the per-threat table above is derived from it via
Table 4.

| OWASP code | Name (paper) | ATR rules tagging it | MCP-38 threats using it |
|---|---|---|---|
| LLM01 | Prompt Injection | 482 | MCP-09, MCP-15, MCP-19, MCP-20, MCP-36 |
| LLM02 | Sensitive Information Disclosure | 149 | MCP-01, MCP-02, MCP-24, MCP-25, MCP-28, MCP-29 |
| LLM03 | Supply Chain Vulnerabilities | 22 | MCP-10, MCP-13, MCP-14, MCP-15, MCP-16, MCP-18, MCP-26, MCP-27, MCP-31, MCP-34 |
| LLM04 | Data & Model Poisoning | 6 | MCP-11, MCP-12, MCP-20 |
| LLM05 | Improper Output Handling | 70 | MCP-03, MCP-07, MCP-08, MCP-17, MCP-30, MCP-37 |
| LLM06 | Excessive Agency | 149 | MCP-01, MCP-04, MCP-05, MCP-17, MCP-22, MCP-23, MCP-32, MCP-38 |
| LLM07 | System Prompt Leakage | 20 | MCP-28, MCP-29 |
| LLM08 | Vector & Embedding Weaknesses | 21 | MCP-06 |
| LLM09 | Misinformation | 17 | MCP-21, MCP-35 |
| LLM10 | Unbounded Consumption | 11 | MCP-33 |
| ASI01 | Agent Goal Hijack | 467 | MCP-09, MCP-12, MCP-15, MCP-19, MCP-20, MCP-35 |
| ASI02 | Tool Misuse & Exploitation | 32 | MCP-04, MCP-05, MCP-17, MCP-24 |
| ASI03 | Identity & Privilege Abuse | 113 | MCP-01, MCP-02, MCP-04 |
| ASI04 | Agentic Supply Chain Vulnerabilities | 74 | MCP-10, MCP-13, MCP-14, MCP-15, MCP-16, MCP-18, MCP-26, MCP-27, MCP-31, MCP-34 |
| ASI05 | Unexpected Code Execution (RCE) | 69 | MCP-07, MCP-08, MCP-09, MCP-30, MCP-37 |
| ASI06 | Memory & Context Poisoning | 83 | MCP-11, MCP-12, MCP-20, MCP-25 |
| ASI07 | Insecure Inter-Agent Communication | 21 | MCP-03, MCP-28, MCP-29, MCP-36 |
| ASI08 | Cascading Failures | 48 | MCP-06, MCP-32, MCP-33 |
| ASI09 | Human-Agent Trust Exploitation | 18 | MCP-03, MCP-21, MCP-22, MCP-23 |
| ASI10 | Rogue Agents | 7 | MCP-35, MCP-38 |

## Provenance

- MCP-38 side: Threat names, STRIDE codes and tactic categories are read verbatim from Table 3 (full threat definitions). The owasp_llm / owasp_agentic code lists per threat are the INVERSE of the paper's Table 4 (MCP-38 framework cross-walk against OWASP LLM Top 10 2025 and OWASP Agentic 2026), which the authors publish as OWASP-code -> [MCP threats]; we invert it to MCP-threat -> [OWASP codes]. Every OWASP code here therefore has primary-source backing in the paper. Descriptive OWASP names use the paper's wording; ATR rule metadata sometimes labels the same code differently, so the crosswalk joins on the code prefix only.
- ATR side: rule YAML under `rules/` (708 files at build time),
  fields `references.owasp_llm` and `references.owasp_agentic`, joined on the
  bare code prefix.
- Extracted: 2026-07-08. arXiv:2603.18063 is CC BY 4.0; ATR is MIT.
- Regenerate: `python3 scripts/generate-mcp-crosswalk.py`. Verify freshness in
  CI: `python3 scripts/generate-mcp-crosswalk.py --check`.

