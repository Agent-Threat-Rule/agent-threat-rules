# ATR → SAFE-MCP Technique Mapping

Last updated: 2026-07-12 (corpus re-stamp v3.5.2->v3.5.8)
ATR corpus: v3.5.8, 793 rules (10 categories)
SAFE-MCP version: latest (85 techniques, 47 mitigations)

> Coverage note: the per-technique ATR rule citations in this document were last
> fully enumerated against the 108-rule v1.0.0 corpus (rule IDs below use the old
> short form, e.g. ATR-010). Technique coverage is monotonic — adding rules can
> only maintain or increase it — so the current 462-rule corpus covers at least
> the 78/85 techniques shown below; treat 78/85 as a conservative lower bound.
> A full re-enumeration against the current corpus is pending.

## Coverage Summary

| SAFE-MCP Tactic | Techniques | ATR Covered | Coverage |
|---|---|---|---|
| Initial Access (TA0001) | 9 | 9 | FULL |
| Execution (TA0002) | 9 | 8 | STRONG |
| Persistence (TA0003) | 8 | 8 | FULL |
| Privilege Escalation (TA0004) | 9 | 8 | STRONG |
| Defense Evasion (TA0005) | 8 | 7 | STRONG |
| Credential Access (TA0006) | 7 | 7 | FULL |
| Discovery (TA0007) | 6 | 5 | STRONG |
| Lateral Movement (TA0008) | 7 | 7 | FULL |
| Collection (TA0009) | 5 | 5 | FULL |
| Command and Control (TA0011) | 4 | 4 | FULL |
| Exfiltration (TA0010) | 6 | 5 | STRONG |
| Impact (TA0040) | 6 | 6 | FULL |
| Resource Development (TA0042) | 1 | 1 | FULL |
| **Total** | **85** | **78** | **91.8%** |

**Overall: 78/85 SAFE-MCP techniques covered by at least one ATR rule.**

---

## Detailed Mapping

### Initial Access — 9/9 covered (FULL)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1001 | Tool Poisoning Attack (TPA) | ATR-010, ATR-011, ATR-100, ATR-101, ATR-103, ATR-105 | Strong — 6 rules cover hidden instructions, safety bypass, silent concealment in tool descriptions |
| SAFE-T1002 | Supply Chain Compromise | ATR-060, ATR-095, ATR-096 | Typosquatting, poisoned packages, registry manipulation |
| SAFE-T1003 | Malicious MCP-Server Distribution | ATR-095, ATR-096 | Trojanized packages and compromised registries |
| SAFE-T1004 | Server Impersonation / Name-Collision | ATR-060, ATR-117 | Impersonation via namespace collision and identity spoofing |
| SAFE-T1005 | Exposed Endpoint Exploit | ATR-012, ATR-013 | Partial — unauthorized tool calls and SSRF cover exploitation vectors |
| SAFE-T1006 | User-Social-Engineering Install | ATR-119 | Social engineering via agent output |
| SAFE-T1007 | OAuth Authorization Phishing | ATR-114 | OAuth and API token interception |
| SAFE-T1008 | Tool Shadowing Attack | ATR-089, ATR-106 | Polymorphic aliasing and schema-description contradiction |
| SAFE-T1009 | Authorization Server Mix-up | ATR-114 | OAuth token interception covers mix-up scenarios |

### Execution — 8/9 covered (STRONG)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1101 | Command Injection | ATR-066, ATR-110, ATR-111 | Parameter injection, eval/dynamic code, shell metacharacters |
| SAFE-T1102 | Prompt Injection (Multiple Vectors) | ATR-001, ATR-002, ATR-003, ATR-004, ATR-005, ATR-080, ATR-081, ATR-083, ATR-084, ATR-091, ATR-097, ATR-104 | **Strongest coverage** — 12 rules across direct, indirect, jailbreak, encoding, CJK, multi-turn, structured data |
| SAFE-T1103 | Fake Tool Invocation (Function Spoofing) | ATR-012 | Unauthorized tool call detection |
| SAFE-T1104 | Over-Privileged Tool Abuse | ATR-040, ATR-064 | Privilege escalation and over-permissioned skill detection |
| SAFE-T1105 | Path Traversal via File Tool | ATR-113 | Credential file theft from agent environment |
| SAFE-T1106 | Autonomous Loop Exploit | ATR-050, ATR-051 | Runaway loops and resource exhaustion |
| SAFE-T1109 | Debugging Tool Exploitation | — | **GAP**: CVE-2025-49596 specific, no ATR rule yet |
| SAFE-T1110 | Multimodal Prompt Injection via Images/Audio | — | **GAP**: ATR currently focuses on text-based detection |
| SAFE-T1111 | AI Agent CLI Weaponization | ATR-110, ATR-111 | RCE via eval and shell injection covers CLI weaponization |

### Persistence — 8/8 covered (FULL)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1201 | MCP Rug Pull Attack | ATR-065, ATR-089 | Malicious updates and polymorphic capability changes |
| SAFE-T1202 | OAuth Token Persistence | ATR-114 | OAuth token interception and reuse |
| SAFE-T1203 | Backdoored Server Binary | ATR-095 | Supply chain poisoning covers backdoored binaries |
| SAFE-T1204 | Context Memory Implant | ATR-075 | Agent memory manipulation |
| SAFE-T1205 | Persistent Tool Redefinition | ATR-065 | Malicious skill update or mutation |
| SAFE-T1206 | Credential Implant in Config | ATR-113 | Credential file access in agent environment |
| SAFE-T1207 | Hijack Update Mechanism | ATR-095, ATR-096 | Supply chain and registry poisoning |
| SAFE-T2106 | Vector Store Contamination | ATR-070, ATR-075 | RAG poisoning and memory manipulation |

### Privilege Escalation — 8/9 covered (STRONG)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1301 | Cross-Server Tool Shadowing | ATR-074, ATR-089 | Cross-agent escalation and polymorphic aliasing |
| SAFE-T1302 | High-Privilege Tool Abuse | ATR-040, ATR-012 | Admin function access and unauthorized tool calls |
| SAFE-T1303 | Sandbox Escape via Server Exec | — | **GAP**: Container-level escape is infrastructure-specific |
| SAFE-T1304 | Credential Relay Chain | ATR-074, ATR-114 | Cross-agent privilege escalation and token interception |
| SAFE-T1305 | Host OS Priv-Esc (RCE) | ATR-040, ATR-110 | Privilege escalation and RCE via eval |
| SAFE-T1306 | Rogue Authorization Server | ATR-114 | OAuth token interception covers rogue AS |
| SAFE-T1307 | Confused Deputy Attack | ATR-074, ATR-117 | Cross-agent escalation and identity spoofing |
| SAFE-T1308 | Token Scope Substitution | ATR-114 | OAuth token interception |
| SAFE-T1309 | Privileged Tool Invocation via Prompt | ATR-001, ATR-004, ATR-040 | Prompt injection + privilege escalation |

### Defense Evasion — 7/8 covered (STRONG)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1401 | Line Jumping | ATR-094 | Multi-layer audit system bypass |
| SAFE-T1402 | Instruction Steganography | ATR-002, ATR-080, ATR-086 | Indirect injection (zero-width chars, HTML comments), encoding evasion, visual spoofing |
| SAFE-T1403 | Consent-Fatigue Exploit | ATR-118 | Human approval fatigue exploitation |
| SAFE-T1404 | Response Tampering | ATR-088, ATR-105 | Behavioral monitoring evasion and silent concealment |
| SAFE-T1405 | Tool Obfuscation/Renaming | ATR-061 | Description-behavior mismatch |
| SAFE-T1406 | Metadata Manipulation | ATR-082 | Behavioral fingerprint detection evasion |
| SAFE-T1407 | Server Proxy Masquerade | — | **GAP**: Network-level masquerade is infrastructure-specific |
| SAFE-T1408 | OAuth Protocol Downgrade | ATR-114 | OAuth token interception covers protocol-level attacks |

### Credential Access — 7/7 covered (FULL)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1501 | Full-Schema Poisoning (FSP) | ATR-100, ATR-103 | Hidden instructions and safety bypass in tool descriptions |
| SAFE-T1502 | File-Based Credential Harvest | ATR-113 | Credential file theft from agent environment |
| SAFE-T1503 | Env-Var Scraping | ATR-115 | Bulk environment variable harvesting |
| SAFE-T1504 | Token Theft via API Response | ATR-021, ATR-114 | Credential exposure in output + OAuth interception |
| SAFE-T1505 | In-Memory Secret Extraction | ATR-021 | Credential and secret exposure detection |
| SAFE-T1506 | Infrastructure Token Theft | ATR-114 | OAuth and API token interception |
| SAFE-T1507 | Authorization Code Interception | ATR-114 | OAuth token interception |

### Discovery — 5/6 covered (STRONG)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1601 | MCP Server Enumeration | ATR-087, ATR-090 | Rule probing and threat intelligence exfiltration |
| SAFE-T1602 | Tool Enumeration | ATR-087 | Detection rule probing covers enumeration behavior |
| SAFE-T1603 | System Prompt Disclosure | ATR-020 | System prompt and internal instruction leakage |
| SAFE-T1604 | Server Version Enumeration | — | **GAP**: Infrastructure-level version fingerprinting |
| SAFE-T1605 | Capability Mapping | ATR-087, ATR-090 | Rule probing and intelligence exfiltration |
| SAFE-T1606 | Directory Listing via File Tool | ATR-113 | Credential file access covers directory traversal |

### Lateral Movement — 7/7 covered (FULL)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1701 | Cross-Tool Contamination | ATR-063, ATR-074 | Multi-skill chain attack and cross-agent escalation |
| SAFE-T1702 | Shared-Memory Poisoning | ATR-070, ATR-092 | RAG contamination and multi-agent consensus poisoning |
| SAFE-T1703 | Tool-Chaining Pivot | ATR-063 | Multi-skill chain attack |
| SAFE-T1704 | Compromised-Server Pivot | ATR-074 | Cross-agent privilege escalation |
| SAFE-T1705 | Cross-Agent Instruction Injection | ATR-030, ATR-116 | Cross-agent attack and malicious A2A message injection |
| SAFE-T1706 | OAuth Token Pivot Replay | ATR-114 | OAuth token interception and reuse |
| SAFE-T1707 | CSRF Token Relay | ATR-114 | OAuth token interception |

### Collection — 5/5 covered (FULL)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1801 | Automated Data Harvesting | ATR-102 | Disguised analytics collection |
| SAFE-T1802 | File Collection | ATR-113 | Credential file theft (file access patterns) |
| SAFE-T1803 | Database Dump | ATR-013 | SSRF covers unauthorized data access via tools |
| SAFE-T1804 | API Data Harvest | ATR-102 | Disguised analytics collection |
| SAFE-T1805 | Context Snapshot Capture | ATR-075, ATR-090 | Memory manipulation and intelligence exfiltration |

### Command and Control — 4/4 covered (FULL)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1901 | Outbound Webhook C2 | ATR-010, ATR-013 | Malicious tool response (curl/wget) + SSRF |
| SAFE-T1902 | Covert Channel in Responses | ATR-080, ATR-086 | Encoding evasion and visual spoofing |
| SAFE-T1903 | Malicious Server Control Channel | ATR-095 | Supply chain poisoning covers rogue servers |
| SAFE-T1904 | Chat-Based Backchannel | ATR-080 | Encoding-based evasion (base64, hex) |

### Exfiltration — 5/6 covered (STRONG)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T1910 | Covert Channel Exfiltration | ATR-080, ATR-102 | Encoding evasion and disguised analytics |
| SAFE-T1911 | Parameter Exfiltration | ATR-084 | Structured data injection via JSON/CSV |
| SAFE-T1912 | Stego Response Exfil | ATR-086 | Visual spoofing and steganography detection |
| SAFE-T1913 | HTTP POST Exfil | ATR-010, ATR-013 | Malicious tool response + SSRF |
| SAFE-T1914 | Tool-to-Tool Exfil | ATR-063 | Multi-skill chain attack |
| SAFE-T1915 | Cross-Chain Laundering via Bridges/DEXs | — | **GAP**: Blockchain/DeFi-specific, out of ATR's current scope |

### Impact — 6/6 covered (FULL)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T2101 | Data Destruction | ATR-012, ATR-098 | Unauthorized tool calls and unauthorized financial actions |
| SAFE-T2102 | Service Disruption | ATR-051, ATR-052 | Resource exhaustion and cascading failures |
| SAFE-T2103 | Code Sabotage | ATR-062 | Hidden capability in MCP skill |
| SAFE-T2104 | Fraudulent Transactions | ATR-098 | Unauthorized financial action by AI agent |
| SAFE-T2105 | Disinformation Output | ATR-032, ATR-119 | Goal hijacking and social engineering via agent output |
| SAFE-T3001 | RAG Backdoor Attack | ATR-070 | RAG and knowledge base contamination |

### Resource Development — 1/1 covered (FULL)

| SAFE-MCP ID | SAFE-MCP Technique | ATR Rules | Notes |
|---|---|---|---|
| SAFE-T2107 | AI Model Poisoning via Training Data | ATR-073 | Malicious fine-tuning data detection |

---

## Gap Analysis

7 SAFE-MCP techniques have no direct ATR rule coverage:

| SAFE-MCP ID | Technique | Gap Reason | Priority |
|---|---|---|---|
| SAFE-T1109 | Debugging Tool Exploitation | CVE-specific (MCP Inspector), needs targeted rule | MEDIUM |
| SAFE-T1110 | Multimodal Prompt Injection | ATR is text-based; image/audio injection requires different detection | HIGH |
| SAFE-T1303 | Sandbox Escape via Server Exec | Infrastructure-level, outside agent interaction layer | LOW |
| SAFE-T1407 | Server Proxy Masquerade | Network-level masquerade, outside agent interaction layer | LOW |
| SAFE-T1604 | Server Version Enumeration | Infrastructure fingerprinting, outside agent interaction layer | LOW |
| SAFE-T1915 | Cross-Chain Laundering | Blockchain/DeFi-specific, outside current scope | LOW |
| — | *(No additional gaps)* | — | — |

**Key insight**: 3 of 7 gaps are infrastructure-level threats outside ATR's agent interaction focus. The 2 actionable gaps are:
1. **SAFE-T1110 Multimodal Injection** — high priority as multimodal agents grow
2. **SAFE-T1109 Debugging Tool Exploitation** — medium priority, CVE-specific

---

## Complementary Relationship

| Dimension | SAFE-MCP | ATR |
|---|---|---|
| **Type** | Threat knowledge base (like MITRE ATT&CK) | Detection ruleset (like Sigma/YARA) |
| **Output** | "These attacks exist and here's how they work" | "Here's how to detect these attacks in real MCP traffic" |
| **Format** | Markdown technique descriptions with mitigations | Machine-readable YAML rules with regex patterns |
| **Data** | Theoretical framework with example scenarios | 36,394 real-world skills scanned, empirical findings |
| **Benchmark** | No benchmark | PINT-format corpus (self-built): 63.6% recall, 99.7% precision |
| **OWASP** | Not mapped | 10/10 OWASP Agentic Top 10 coverage |

**ATR provides the detection layer that operationalizes SAFE-MCP's threat taxonomy.** SAFE-MCP tells you what to look for; ATR tells you how to find it.

---

## Cross-Reference: ATR Rule → SAFE-MCP Technique

For completeness, here is the reverse mapping — each ATR rule and which SAFE-MCP techniques it helps detect:

| ATR Rule | Title | SAFE-MCP Techniques |
|---|---|---|
| ATR-001 | Direct Prompt Injection | T1102, T1309 |
| ATR-002 | Indirect Prompt Injection | T1102, T1402 |
| ATR-003 | Jailbreak Attempt | T1102 |
| ATR-004 | System Prompt Override | T1102, T1309 |
| ATR-005 | Multi-Turn Injection | T1102 |
| ATR-010 | Malicious MCP Tool Response | T1001, T1901, T1913 |
| ATR-011 | Instruction Injection via Tool Output | T1001 |
| ATR-012 | Unauthorized Tool Call | T1005, T1103, T1302, T2101 |
| ATR-013 | SSRF via Agent Tool Calls | T1005, T1803, T1901, T1913 |
| ATR-020 | System Prompt Leakage | T1603 |
| ATR-021 | Credential Exposure in Output | T1504, T1505 |
| ATR-030 | Cross-Agent Attack | T1705 |
| ATR-032 | Agent Goal Hijacking | T2105 |
| ATR-040 | Privilege Escalation | T1104, T1302, T1305, T1309 |
| ATR-050 | Runaway Agent Loop | T1106 |
| ATR-051 | Resource Exhaustion | T1106, T2102 |
| ATR-052 | Cascading Failure | T2102 |
| ATR-060 | Skill Impersonation / Supply Chain | T1002, T1004 |
| ATR-061 | Description-Behavior Mismatch | T1405 |
| ATR-062 | Hidden Capability in MCP Skill | T2103 |
| ATR-063 | Multi-Skill Chain Attack | T1701, T1703, T1914 |
| ATR-064 | Over-Permissioned MCP Skill | T1104 |
| ATR-065 | Malicious Skill Update | T1201, T1205 |
| ATR-066 | Parameter Injection | T1101 |
| ATR-070 | RAG/Knowledge Base Contamination | T2106, T1702, T3001 |
| ATR-072 | Model Behavior Extraction | — (Discovery, not in SAFE-MCP) |
| ATR-073 | Malicious Fine-tuning Data | T2107 |
| ATR-074 | Cross-Agent Privilege Escalation | T1301, T1304, T1307, T1701, T1704 |
| ATR-075 | Agent Memory Manipulation | T1204, T2106, T1805 |
| ATR-076 | Insecure Inter-Agent Communication | — (Generic A2A, maps broadly) |
| ATR-077 | Human-Agent Trust Exploitation | — (Maps to consent-fatigue adjacent) |
| ATR-080 | Encoding-Based Evasion | T1102, T1402, T1902, T1904, T1910 |
| ATR-081 | Semantic Multi-Turn Evasion | T1102 |
| ATR-082 | Behavioral Fingerprint Evasion | T1406 |
| ATR-083 | Indirect Injection via Tool Responses | T1102 |
| ATR-084 | Structured Data Injection | T1102, T1911 |
| ATR-085 | Multi-Layer Audit Evasion | T1102 |
| ATR-086 | Visual Spoofing (RTL/Punycode) | T1402, T1902, T1912 |
| ATR-087 | Detection Rule Probing | T1601, T1602, T1605 |
| ATR-088 | Adaptive Behavioral Evasion | T1404 |
| ATR-089 | Polymorphic Skill Aliasing | T1008, T1201, T1301 |
| ATR-090 | Threat Intel Exfiltration | T1601, T1605, T1805 |
| ATR-091 | Advanced Nested Payloads | T1102 |
| ATR-092 | Multi-Agent Consensus Poisoning | T1702 |
| ATR-093 | Gradual Capability Escalation | T1102 |
| ATR-094 | Multi-Layer Audit Bypass | T1401 |
| ATR-095 | MCP Supply Chain Poisoning | T1002, T1003, T1203, T1207, T1903 |
| ATR-096 | Skill Registry Poisoning | T1002, T1003, T1207 |
| ATR-097 | CJK Prompt Injection | T1102 |
| ATR-098 | Unauthorized Financial Action | T2101, T2104 |
| ATR-099 | High-Risk Tool Without Confirmation | — (Process control, not attack technique) |
| ATR-100 | Consent Bypass via Hidden Instructions | T1001, T1501 |
| ATR-101 | Trust Escalation via Authority Override | T1001 |
| ATR-102 | Disguised Analytics Exfiltration | T1801, T1804, T1910 |
| ATR-103 | Hidden Safety Bypass Instructions | T1001, T1501 |
| ATR-104 | Persona Hijacking | T1102 |
| ATR-105 | Silent Action Concealment | T1001, T1404 |
| ATR-106 | Schema-Description Contradiction | T1008 |
| ATR-107 | Delayed Task Execution Bypass | — (Timing-based, no direct SAFE-MCP match) |
| ATR-108 | Multi-Agent Consensus Sybil | — (Covered by T1702 Shared-Memory Poisoning) |
| ATR-110 | RCE via eval() / Dynamic Code | T1101, T1111, T1305 |
| ATR-111 | Shell Metacharacter Injection | T1101, T1111 |
| ATR-112 | Dynamic Module Loading | T1101 |
| ATR-113 | Credential File Theft | T1105, T1206, T1502, T1606, T1802 |
| ATR-114 | OAuth/API Token Interception | T1007, T1009, T1202, T1304, T1306, T1308, T1408, T1504, T1506, T1507, T1706, T1707 |
| ATR-115 | Env Variable Harvesting | T1503 |
| ATR-116 | Malicious A2A Message Injection | T1705 |
| ATR-117 | Agent Identity Spoofing | T1004, T1307 |
| ATR-118 | Approval Fatigue Exploitation | T1403 |
| ATR-119 | Social Engineering via Agent Output | T1006, T2105 |

---

## How to Use This Mapping

**For SAFE-MCP contributors**: ATR provides ready-made detection signatures for 78 of 85 SAFE-MCP techniques. Each ATR rule is a YAML file with regex patterns, severity levels, and test cases that can be integrated into any MCP security scanner.

**For ATR users**: SAFE-MCP provides the threat taxonomy context for understanding *why* each ATR rule exists and how attacks chain together across tactics.

**For security teams**: Use SAFE-MCP to understand your threat landscape, then deploy ATR rules to detect those threats in your MCP infrastructure.

---

## References

- ATR Repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
- ATR Paper: https://doi.org/10.5281/zenodo.19178002
- SAFE-MCP Repository: https://github.com/safe-agentic-framework/safe-mcp
- SAFE-MCP Website: https://safemcp.org
- ATR OWASP Mapping: [OWASP-MAPPING.md](./OWASP-MAPPING.md)
