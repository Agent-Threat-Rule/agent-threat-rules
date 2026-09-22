# ATR → OWASP Agentic Top 10 Mapping

Last updated: 2026-03-26
ATR version: v1.0.0+ (108 rules)
OWASP framework: Top 10 for Agentic Applications 2026

## Coverage Summary

| OWASP Category | Rules | Status |
|---|---|---|
| ASI01: Agent Goal Hijack | 13 rules | STRONG |
| ASI02: Tool Misuse & Exploitation | 11 rules | STRONG |
| ASI03: Identity & Privilege Abuse | 9 rules | STRONG |
| ASI04: Agentic Supply Chain | 8 rules | STRONG |
| ASI05: Unexpected Code Execution (RCE) | 8 rules | STRONG |
| ASI06: Memory & Context Poisoning | 8 rules | STRONG |
| ASI07: Insecure Inter-Agent Communication | 5 rules | MODERATE |
| ASI08: Cascading Failures | 4 rules | MODERATE |
| ASI09: Human-Agent Trust Exploitation | 5 rules | MODERATE |
| ASI10: Rogue Agents | 7 rules | MODERATE |

**Overall: 10/10 categories covered. 71 unique ATR rules. No PARTIAL categories.**

Note: Some rules appear in multiple categories (e.g., ATR-2026-00117 maps to both ASI07 and ASI10). Total rule-category mappings: 77.

---

## Detailed Mapping

### ASI01: Agent Goal Hijack (13 rules) — STRONG

Hidden prompts and injection attacks that redirect agent behavior away from its intended goal.

| ATR Rule | Title | Severity |
|---|---|---|
| ATR-2026-00001 | Direct Prompt Injection | CRITICAL |
| ATR-2026-00002 | Indirect Prompt Injection | CRITICAL |
| ATR-2026-00003 | Jailbreak Attempt | HIGH |
| ATR-2026-00004 | System Prompt Override | CRITICAL |
| ATR-2026-00005 | Multi-Turn Injection | HIGH |
| ATR-2026-00080 | Encoding Evasion | MEDIUM |
| ATR-2026-00081 | Semantic Multi-Turn | HIGH |
| ATR-2026-00084 | Structured Data Injection | MEDIUM |
| ATR-2026-00086 | Visual Spoofing | MEDIUM |
| ATR-2026-00091 | Nested Payload | HIGH |
| ATR-2026-00093 | Gradual Escalation | HIGH |
| ATR-2026-00097 | CJK Injection Patterns | MEDIUM |
| ATR-2026-00104 | Persona Hijacking | HIGH |

### ASI02: Tool Misuse & Exploitation (11 rules) — STRONG

Agents bending legitimate tools into destructive outputs or using tools beyond their intended scope.

| ATR Rule | Title | Severity |
|---|---|---|
| ATR-2026-00010 | MCP Malicious Response | CRITICAL |
| ATR-2026-00011 | Tool Output Injection | HIGH |
| ATR-2026-00012 | Unauthorized Tool Call | HIGH |
| ATR-2026-00013 | Tool SSRF | CRITICAL |
| ATR-2026-00095 | Supply Chain Poisoning | CRITICAL |
| ATR-2026-00096 | Registry Poisoning | HIGH |
| ATR-2026-00100 | Consent Bypass Instruction | HIGH |
| ATR-2026-00101 | Trust Escalation Override | HIGH |
| ATR-2026-00103 | Hidden Safety Bypass Instruction | CRITICAL |
| ATR-2026-00105 | Silent Action Concealment | HIGH |
| ATR-2026-00106 | Schema-Description Contradiction | MEDIUM |

### ASI03: Identity & Privilege Abuse (9 rules) — STRONG

Leaked credentials or escalated privileges allowing agents to operate beyond intended scope.

| ATR Rule | Title | Severity |
|---|---|---|
| ATR-2026-00021 | API Key Exposure | CRITICAL |
| ATR-2026-00040 | Privilege Escalation | CRITICAL |
| ATR-2026-00041 | Scope Creep | HIGH |
| ATR-2026-00064 | Over-Permissioned Skill | MEDIUM |
| ATR-2026-00107 | Delayed Execution Bypass | HIGH |
| ATR-2026-00113 | Credential Theft | CRITICAL |
| ATR-2026-00114 | OAuth Token Abuse | HIGH |
| ATR-2026-00115 | Env Var Harvesting | CRITICAL |
| ATR-2026-00102 | Disguised Analytics Exfiltration | HIGH |

### ASI04: Agentic Supply Chain Vulnerabilities (8 rules) — STRONG

Dynamic MCP and A2A ecosystems where runtime components can be poisoned.

| ATR Rule | Title | Severity |
|---|---|---|
| ATR-2026-00060 | Skill Impersonation | CRITICAL |
| ATR-2026-00061 | Description-Behavior Mismatch | HIGH |
| ATR-2026-00062 | Hidden Capability | HIGH |
| ATR-2026-00063 | Skill Chain Attack | HIGH |
| ATR-2026-00065 | Skill Update Attack | HIGH |
| ATR-2026-00066 | Parameter Injection | HIGH |
| ATR-2026-00089 | Polymorphic Skill | HIGH |
| ATR-2026-00095 | Supply Chain Poisoning | CRITICAL |

### ASI05: Unexpected Code Execution / RCE (8 rules) — STRONG

Natural-language execution paths that unlock dangerous avenues for remote code execution.

| ATR Rule | Title | Severity |
|---|---|---|
| ATR-2026-00012 | Unauthorized Tool Call | HIGH |
| ATR-2026-00083 | Indirect Tool Injection | HIGH |
| ATR-2026-00110 | Eval Injection | CRITICAL |
| ATR-2026-00111 | Shell Escape | CRITICAL |
| ATR-2026-00112 | Dynamic Import Exploitation | HIGH |
| ATR-2026-00088 | Adaptive Countermeasure | HIGH |
| ATR-2026-00082 | Fingerprint Evasion | MEDIUM |
| ATR-2026-00087 | Rule Probing | MEDIUM |

### ASI06: Memory & Context Poisoning (8 rules) — STRONG

Memory poisoning that reshapes agent behavior long after the initial interaction.

| ATR Rule | Title | Severity |
|---|---|---|
| ATR-2026-00020 | System Prompt Leak | HIGH |
| ATR-2026-00070 | Data Poisoning | HIGH |
| ATR-2026-00075 | Agent Memory Manipulation | HIGH |
| ATR-2026-00085 | Audit Evasion | HIGH |
| ATR-2026-00090 | Threat Intel Exfil | HIGH |
| ATR-2026-00092 | Consensus Poisoning | HIGH |
| ATR-2026-00094 | Audit Bypass | HIGH |
| ATR-2026-00073 | Malicious Finetuning Data | HIGH |

### ASI07: Insecure Inter-Agent Communication (5 rules) — MODERATE

Spoofed inter-agent messages that misdirect entire clusters.

| ATR Rule | Title | Severity |
|---|---|---|
| ATR-2026-00076 | Inter-Agent Message Spoofing | HIGH |
| ATR-2026-00108 | Consensus Sybil Attack | HIGH |
| ATR-2026-00116 | A2A Message Validation | HIGH |
| ATR-2026-00117 | Agent Identity Spoofing | CRITICAL |
| ATR-2026-00030 | Cross-Agent Attack | HIGH |

### ASI08: Cascading Failures (4 rules) — MODERATE

False signals cascading through automated pipelines with escalating impact.

| ATR Rule | Title | Severity |
|---|---|---|
| ATR-2026-00050 | Runaway Agent Loop | HIGH |
| ATR-2026-00051 | Resource Exhaustion | HIGH |
| ATR-2026-00052 | Cascading Failure | CRITICAL |
| ATR-2026-00072 | Model Behavior Extraction | HIGH |

### ASI09: Human-Agent Trust Exploitation (5 rules) — MODERATE

Exploiting the trust relationship between humans and AI agents.

| ATR Rule | Title | Severity |
|---|---|---|
| ATR-2026-00077 | Human Trust Exploitation | HIGH |
| ATR-2026-00098 | Unauthorized Financial Action | CRITICAL |
| ATR-2026-00099 | High-Risk Tool Gate | MEDIUM |
| ATR-2026-00118 | Approval Fatigue Exploitation | MEDIUM |
| ATR-2026-00119 | Social Engineering via Agent | HIGH |

### ASI10: Rogue Agents (7 rules) — MODERATE

Agents operating outside their intended boundaries or becoming autonomous threats.

| ATR Rule | Title | Severity |
|---|---|---|
| ATR-2026-00032 | Goal Hijacking | CRITICAL |
| ATR-2026-00074 | Cross-Agent Privilege Escalation | CRITICAL |
| ATR-2026-00117 | Agent Identity Spoofing | CRITICAL |
| ATR-2026-00050 | Runaway Agent Loop | HIGH |
| ATR-2026-00041 | Scope Creep | HIGH |
| ATR-2026-00107 | Delayed Execution Bypass | HIGH |
| ATR-2026-00089 | Polymorphic Skill | HIGH |

---

## Version History

| Date | ATR Version | Rules | OWASP Coverage |
|---|---|---|---|
| 2026-03-26 | v0.3.1 | 61 | 8/10 (4 PARTIAL) |
| 2026-03-26 | v0.4.0 | 71 | 10/10 (0 PARTIAL) |
