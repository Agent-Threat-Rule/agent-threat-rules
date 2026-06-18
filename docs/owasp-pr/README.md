# ATR Contributions to OWASP Agentic AI Top 10

## What This PR Contains

This PR adds real-world attack examples, prevention strategies, and detection references to all 10 ASI categories in the OWASP Agentic AI Top 10. Content is based on:

- **76 open-source detection rules** from [ATR (Agent Threat Rules)](https://github.com/Agent-Threat-Rule/agent-threat-rules), MIT licensed
- **36,394 MCP skills scanned** on ClawHub (182 CRITICAL, 1,124 HIGH findings)
- **PINT-format corpus** (850 samples from deepset + Lakera Gandalf, not Lakera's official PINT benchmark): 63.6% recall, 99.7% precision
- **Real CVEs**: CVE-2026-28363 (CVSS 9.9), CVE-2026-25253 (CVSS 8.8), CVE-2025-59536 (CVSS 8.7), CVE-2025-49150, CVE-2025-53773, and others
- **Real attack campaigns**: ClawHavoc (1,184 malicious skills), AMOS infostealer (314 skills), Snyk ToxicSkills (76 confirmed malicious)

## Coverage Summary

| ASI Category | ATR Rules | Real CVEs | Attack Campaigns |
|---|---|---|---|
| ASI01: Agent Behaviour Hijack | 13 | CVE-2024-5184, CVE-2025-53773 | PINT-format eval |
| ASI02: Tool Misuse & Exploitation | 11 | CVE-2025-59536, CVE-2025-49150 | MCP server compromises |
| ASI03: Identity & Privilege Abuse | 9 | CVE-2025-59536 | Snyk 280+ leaky skills |
| ASI04: Supply Chain Vulnerabilities | 8 | CVE-2026-28363 (9.9), CVE-2026-25253 (8.8) | ClawHavoc, AMOS, ToxicSkills |
| ASI05: Unexpected Code Execution | 8 | CVE-2025-49150, CVE-2025-53773 | Cato MedusaLocker PoC |
| ASI06: Memory & Context Poisoning | 8 | — | RAG poisoning campaigns |
| ASI07: Inter-Agent Communication | 5 | — | Multi-agent consensus attacks |
| ASI08: Cascading Failures | 4 | — | Auto-deploy incidents |
| ASI09: Human-Agent Trust | 5 | — | Approval fatigue exploits |
| ASI10: Rogue Agents | 7 | — | Polymorphic skill campaigns |

## Files

Each file follows the OWASP template structure (Description, Common Examples, Prevention Strategies, Attack Scenarios, Reference Links):

- `ASI01_Agent_Behaviour_Hijack.md`
- `ASI02_Tool_Misuse_and_Exploitation.md`
- `ASI03_Identity_and_Privilege_Abuse.md`
- `ASI04_Agentic_Supply_Chain_Vulnerabilities.md`
- `ASI05_Unexpected_Code_Execution_RCE.md`
- `ASI06_Memory_and_Context_Poisoning.md`
- `ASI07_Insecure_Inter_Agent_Communication.md`
- `ASI08_Cascading_Failures.md`
- `ASI09_Human_Agent_Trust_Exploitation.md`
- `ASI10_Rogue_Agents.md`

## About ATR

ATR (Agent Threat Rules) is an open-source, MIT-licensed detection ruleset for agentic AI security threats. It provides executable YAML-based rules that can be integrated into any MCP/A2A pipeline for real-time threat detection.

- Repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
- Rules: 76 (71 MCP + 5 skill-level)
- Eval: PINT-format corpus, self-built from public datasets (63.6% recall, 99.7% precision)
- License: MIT
