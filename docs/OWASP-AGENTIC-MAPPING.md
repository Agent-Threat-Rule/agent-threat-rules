# ATR -> OWASP Agentic Top 10 (2026) Mapping

Last updated: 2026-07-12
ATR version: v3.5.8 (793 rules with OWASP Agentic tags)
OWASP framework: Agentic Top 10 v1.0 (December 2025)

## Summary

- Categories covered: **10/10**
- Total rule -> category mappings: **976**
- Tagged ATR rules: **747** of 747 total rules in repo
- ATR version: `v3.5.8` -- OWASP Agentic Top 10: `v1.0 (December 2025)`

Strength tiers: **STRONG** >= 8 rules · **MODERATE** 4-7 rules · **LIMITED** 1-3 rules.

## Coverage by ASI category

| ASI | Title | Rule count | Strength | Reference attack |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | 480 | STRONG | EchoLeak |
| ASI02 | Tool Misuse and Exploitation | 48 | STRONG | Amazon Q |
| ASI03 | Identity and Privilege Abuse | 115 | STRONG | n/a |
| ASI04 | Agentic Supply Chain Vulnerabilities | 75 | STRONG | GitHub MCP exploit |
| ASI05 | Unexpected Code Execution (RCE) | 76 | STRONG | AutoGPT RCE |
| ASI06 | Memory & Context Poisoning | 87 | STRONG | Gemini Memory Attack |
| ASI07 | Insecure Inter-Agent Communication | 21 | STRONG | n/a |
| ASI08 | Cascading Failures | 48 | STRONG | n/a |
| ASI09 | Human-Agent Trust Exploitation | 18 | STRONG | n/a |
| ASI10 | Rogue Agents | 8 | STRONG | Replit meltdown |

---

## Per-category detail

### ASI01: Agent Goal Hijack (480 rules) -- STRONG

**OWASP description.** Attackers manipulate the agent's decision pathways or objectives so it pursues an adversary-controlled goal instead of its assigned task. Canonical instance: EchoLeak.

**ATR coverage shape.** Direct + indirect prompt injection, persona hijack, encoding evasion, jailbreak chains, multi-turn assembly, multilingual paraphrase.

**Reference attack (EchoLeak).** Covered by the rules below; ATR's general-purpose detection layers match the technique signature without needing an attack-specific rule.

Top rules by severity:

| Rule ID | Title | Severity | Description |
|---|---|---|---|
| ATR-2026-00004 | System Prompt Override Attempt | critical | Detects attempts to override, replace, or redefine the agent's system prompt. Attackers c… |
| ATR-2026-00030 | Cross-Agent Attack Detection | critical | Consolidated detection for cross-agent attacks in multi-agent systems, covering both impe… |
| ATR-2026-00081 | Semantic Evasion via Multi-Turn Prompt Injection | critical | Detects multi-turn prompt injection attacks that use semantic manipulation to bypass rege… |
| ATR-2026-00091 | Advanced Structured Data Injection with Nested Payloads | critical | Detects advanced structured data injection where malicious prompts are deeply nested with… |
| ATR-2026-00092 | Multi-Agent Consensus Poisoning and Sybil Attack | critical | Detects attacks targeting multi-agent consensus systems through coordinated fake proposal… |

Plus 475 additional rules tagged ASI01 -- see `docs/owasp-agentic-mapping.json` for the complete list.

### ASI02: Tool Misuse and Exploitation (48 rules) -- STRONG

**OWASP description.** Legitimate tools are used unsafely because the agent acts on ambiguous instructions or has over-privileged access. Canonical instance: Amazon Q assistant tool-misuse incident.

**ATR coverage shape.** Unauthorized tool calls, SSRF via tool, MCP malicious response, schema-description contradiction, consent bypass.

**Reference attack (Amazon Q).** Covered by the rules below; ATR's general-purpose detection layers match the technique signature without needing an attack-specific rule.

Top rules by severity:

| Rule ID | Title | Severity | Description |
|---|---|---|---|
| ATR-2026-00010 | Malicious Content in MCP Tool Response | critical | Detects malicious content embedded in MCP (Model Context Protocol) tool responses. Attack… |
| ATR-2026-00013 | SSRF via Agent Tool Calls | critical | Detects high-confidence Server-Side Request Forgery (SSRF) that targets cloud CREDENTIAL… |
| ATR-2026-00062 | Hidden Capability in MCP Skill | critical | Detects MCP skills that expose hidden or undocumented capabilities beyond their declared… |
| ATR-2026-00063 | Multi-Skill Chain Attack | critical | Detects attack sequences where multiple MCP skills are chained together to achieve a mali… |
| ATR-2026-00066 | Parameter Injection via Tool Arguments | critical | Detects injection attacks delivered through MCP tool arguments. An attacker crafts tool a… |

Plus 43 additional rules tagged ASI02 -- see `docs/owasp-agentic-mapping.json` for the complete list.

### ASI03: Identity and Privilege Abuse (115 rules) -- STRONG

**OWASP description.** Agents operate in an attribution gap; leaked credentials or escalated privileges let them act beyond intended scope.

**ATR coverage shape.** API key exposure, OAuth token abuse, env var harvesting, scope creep, credential file theft, privilege escalation.

Top rules by severity:

| Rule ID | Title | Severity | Description |
|---|---|---|---|
| ATR-2026-00021 | Credential and Secret Exposure in Agent Output | critical | Detects when an AI agent exposes API keys, secret tokens, private keys, database connecti… |
| ATR-2026-00040 | Privilege Escalation and Admin Function Access | critical | Consolidated detection for privilege escalation attempts, covering both tool permission e… |
| ATR-2026-00074 | Cross-Agent Privilege Escalation | critical | Detects agents using inter-agent communication channels to escalate privileges beyond the… |
| ATR-2026-00113 | Credential File Theft from Agent Environment | critical | Detects tools or agent instructions that access well-known credential files from the host… |
| ATR-2026-00115 | Bulk Environment Variable Harvesting and Exfiltration | critical | Detects tools or agent instructions that perform bulk extraction of environment variables… |

Plus 110 additional rules tagged ASI03 -- see `docs/owasp-agentic-mapping.json` for the complete list.

### ASI04: Agentic Supply Chain Vulnerabilities (75 rules) -- STRONG

**OWASP description.** Runtime composition of third-party capabilities (MCP servers, plugins, skills, A2A endpoints) lets adversaries poison the call graph after deployment. Canonical instance: GitHub MCP exploit.

**ATR coverage shape.** Skill impersonation, hidden capability, polymorphic skill, registry poisoning, malicious skill code, parameter injection.

**Reference attack (GitHub MCP exploit).** Covered by the rules below; ATR's general-purpose detection layers match the technique signature without needing an attack-specific rule.

Top rules by severity:

| Rule ID | Title | Severity | Description |
|---|---|---|---|
| ATR-2026-00072 | Model Behavior Extraction | critical | Detects systematic probing attempts to extract model behavior, decision boundaries, syste… |
| ATR-2026-00073 | Malicious Fine-tuning Data | critical | Detects poisoned fine-tuning datasets that contain instruction-following backdoors, trigg… |
| ATR-2026-00121 | Malicious Code in Skill Package | critical | Detects malicious code patterns in SKILL.md files and associated scripts. 100% of confirm… |
| ATR-2026-00149 | Skill Data Exfiltration via Compound Patterns | critical | Detects compound exfiltration patterns in SKILL.md files where sensitive data (credential… |
| ATR-2026-00200 | Agent Memory and Configuration File Tampering | critical | Detects attempts to write, append, or modify agent memory files (MEMORY.md, SOUL.md, CLAU… |

Plus 70 additional rules tagged ASI04 -- see `docs/owasp-agentic-mapping.json` for the complete list.

### ASI05: Unexpected Code Execution (RCE) (76 rules) -- STRONG

**OWASP description.** Agents generate and execute code ("vibe coding"), opening RCE paths through natural-language instructions. Canonical instance: AutoGPT RCE.

**ATR coverage shape.** eval injection, shell metacharacter escape, dynamic import exploitation, indirect tool injection leading to code exec.

**Reference attack (AutoGPT RCE).** Covered by the rules below; ATR's general-purpose detection layers match the technique signature without needing an attack-specific rule.

Top rules by severity:

| Rule ID | Title | Severity | Description |
|---|---|---|---|
| ATR-2026-00010 | Malicious Content in MCP Tool Response | critical | Detects malicious content embedded in MCP (Model Context Protocol) tool responses. Attack… |
| ATR-2026-00062 | Hidden Capability in MCP Skill | critical | Detects MCP skills that expose hidden or undocumented capabilities beyond their declared… |
| ATR-2026-00095 | MCP Tool Supply Chain Poisoning | critical | Detects tool poisoning attacks targeting the MCP (Model Context Protocol) skill/tool supp… |
| ATR-2026-00096 | Skill Registry Poisoning and Compromised Tool Distribution | critical | Detects supply chain attacks that target skill/tool registries and distribution channels.… |
| ATR-2026-00110 | Remote Code Execution via eval() and Dynamic Code Injection | critical | Detects tools or agent instructions that invoke eval(), Function(), vm.runInNewContext(),… |

Plus 71 additional rules tagged ASI05 -- see `docs/owasp-agentic-mapping.json` for the complete list.

### ASI06: Memory & Context Poisoning (87 rules) -- STRONG

**OWASP description.** Long-term memory, RAG stores, or shared context are corrupted so the agent's future behavior is shaped by attacker payloads. Canonical instance: Gemini Memory Attack.

**ATR coverage shape.** Agent memory manipulation, RAG poisoning, audit evasion, malicious finetuning data, consensus poisoning, persistent context drift.

**Reference attack (Gemini Memory Attack).** Covered by the rules below; ATR's general-purpose detection layers match the technique signature without needing an attack-specific rule.

Top rules by severity:

| Rule ID | Title | Severity | Description |
|---|---|---|---|
| ATR-2026-00004 | System Prompt Override Attempt | critical | Detects attempts to override, replace, or redefine the agent's system prompt. Attackers c… |
| ATR-2026-00136 | Tool Response Data Piggybacking | critical | Detects malicious tool responses that embed sensitive data extraction within legitimate-l… |
| ATR-2026-00139 | Casual Authority Data Redirect | critical | Detects social engineering claiming authority to redirect agent output to attacker-contro… |
| ATR-2026-00201 | Credential Exfiltration via Shell Pipe | critical | Detects credential theft patterns where environment variables containing API keys, secret… |
| ATR-2026-00212 | mcp-atlassian Credential Leak via Hint Parameter Injection (CVE-2026-27825/27826) | critical | Detects the mcp-atlassian credential-leak attack pattern (CVE-2026-27825 and CVE-2026-278… |

Plus 82 additional rules tagged ASI06 -- see `docs/owasp-agentic-mapping.json` for the complete list.

### ASI07: Insecure Inter-Agent Communication (21 rules) -- STRONG

**OWASP description.** Multi-agent systems exchange messages without authentication or integrity guarantees, letting adversaries spoof or replay messages between agents.

**ATR coverage shape.** A2A message spoofing, agent identity spoofing, consensus sybil attack, cross-agent attack vectors.

Top rules by severity:

| Rule ID | Title | Severity | Description |
|---|---|---|---|
| ATR-2026-00030 | Cross-Agent Attack Detection | critical | Consolidated detection for cross-agent attacks in multi-agent systems, covering both impe… |
| ATR-2026-00108 | Multi-Agent Consensus Sybil Attack | critical | Detects attempts to manipulate multi-agent consensus or voting systems through Sybil-styl… |
| ATR-2026-00117 | Agent Identity Spoofing and Authority Impersonation | critical | Detects agents or messages that impersonate other agents, system components, or superviso… |
| ATR-2026-00161 | MCP Tool Description — IMPORTANT Tag Cross-Tool Shadowing Attack | critical | Detects MCP tool poisoning attacks that embed hidden instructions inside an <IMPORTANT> X… |
| ATR-2026-00162 | Credential Access with Exfiltration in Skill Instructions | critical | Detects SKILL.md files that combine credential file access (SSH keys, AWS credentials, AP… |

Plus 16 additional rules tagged ASI07 -- see `docs/owasp-agentic-mapping.json` for the complete list.

### ASI08: Cascading Failures (48 rules) -- STRONG

**OWASP description.** A single fault in one agent, tool, or signal propagates system-wide because automated downstream consumers act on it without independent validation.

**ATR coverage shape.** Runaway agent loop, resource exhaustion, cascading failure detection, model behavior extraction triggering downstream cascade.

Top rules by severity:

| Rule ID | Title | Severity | Description |
|---|---|---|---|
| ATR-2026-00097 | CJK Prompt Injection - Expanded Chinese/Japanese/Korean Patterns | critical | Expanded CJK-language prompt injection patterns targeting the gap where attackers use nat… |
| ATR-2026-00098 | Unauthorized Financial Action by AI Agent | critical | Detects when an AI agent attempts to execute financial operations (payments, transfers, r… |
| ATR-2026-00136 | Tool Response Data Piggybacking | critical | Detects malicious tool responses that embed sensitive data extraction within legitimate-l… |
| ATR-2026-00141 | API Key Leakage via Example Format | critical | Detects attempts to leak API keys by providing example formats with real key prefixes, ho… |
| ATR-2026-00142 | Data Piggybacking via Casual Transition Words | critical | Detects tool response piggybacking using casual transition words (oh and, P.S., BTW, inte… |

Plus 43 additional rules tagged ASI08 -- see `docs/owasp-agentic-mapping.json` for the complete list.

### ASI09: Human-Agent Trust Exploitation (18 rules) -- STRONG

**OWASP description.** Adversaries exploit anthropomorphism and authority bias so humans approve harmful agent actions they would otherwise reject.

**ATR coverage shape.** Human trust exploitation, approval fatigue, social engineering via agent, unauthorized financial action, high-risk tool gate bypass.

Top rules by severity:

| Rule ID | Title | Severity | Description |
|---|---|---|---|
| ATR-2026-00098 | Unauthorized Financial Action by AI Agent | critical | Detects when an AI agent attempts to execute financial operations (payments, transfers, r… |
| ATR-2026-00419 | Cursor MCP JSON Zero-Click Configuration RCE (CVE-2025-54136) | critical | Detects exploitation of CVE-2025-54136 in Cursor and the same-class issue surfaced by the… |
| ATR-2026-00523 | Claude Code Hooks SessionStart Pre-Trust RCE (CVE-2025-59536) | critical | Detects exploitation of CVE-2025-59536 (Critical), pre-trust remote code execution in Cla… |
| ATR-2026-00524 | Claude Code ANTHROPIC_BASE_URL Credential Exfiltration (CVE-2026-21852) | critical | Detects exploitation of CVE-2026-21852 (Moderate, CVSS 5.3), credential exfiltration in C… |
| ATR-2026-00858 | Indirect PI — Data Exfiltration with Evidence Destruction (Exfil-and-Delete) | critical | Detects indirect prompt injection payloads instructing an agent to exfiltrate sensitive d… |

Plus 13 additional rules tagged ASI09 -- see `docs/owasp-agentic-mapping.json` for the complete list.

### ASI10: Rogue Agents (8 rules) -- STRONG

**OWASP description.** Agents deviate from their intended function, optionally collude with other agents, and operate as autonomous threats. Canonical instance: Replit meltdown.

**ATR coverage shape.** Goal hijacking, cross-agent privilege escalation, runaway loop, scope creep, delayed execution bypass, polymorphic behavior.

**Reference attack (Replit meltdown).** Covered by the rules below; ATR's general-purpose detection layers match the technique signature without needing an attack-specific rule.

Top rules by severity:

| Rule ID | Title | Severity | Description |
|---|---|---|---|
| ATR-2026-00030 | Cross-Agent Attack Detection | critical | Consolidated detection for cross-agent attacks in multi-agent systems, covering both impe… |
| ATR-2026-00074 | Cross-Agent Privilege Escalation | critical | Detects agents using inter-agent communication channels to escalate privileges beyond the… |
| ATR-2026-00104 | Persona Hijacking via Mandatory System Prompt Override | critical | Detects MCP tools that attempt to override system prompts or behavioral guidelines by ins… |
| ATR-2026-00108 | Multi-Agent Consensus Sybil Attack | critical | Detects attempts to manipulate multi-agent consensus or voting systems through Sybil-styl… |
| ATR-2026-00117 | Agent Identity Spoofing and Authority Impersonation | critical | Detects agents or messages that impersonate other agents, system components, or superviso… |

Plus 3 additional rules tagged ASI10 -- see `docs/owasp-agentic-mapping.json` for the complete list.

---

## Methodology

Each YAML file under `rules/` is scanned for OWASP Agentic Top 10 tags in two locations:

1. `references.owasp_agentic` -- string list (e.g. `"ASI01:2026"`)
2. `compliance.owasp_agentic[].id` -- structured form (e.g. `id: ASI01:2026`)

Bucketing is done on the `ASI[0-9]{2}` prefix to absorb legacy taxonomy suffixes. A rule mapping to multiple ASI categories counts in each. Strength tiers: **STRONG** >= 8 · **MODERATE** 4-7 · **LIMITED** 1-3.

Regenerate with:

```bash
npx tsx scripts/generate-owasp-mapping.ts
```

Outputs `docs/OWASP-AGENTIC-MAPPING.md` (this file) and `docs/owasp-agentic-mapping.json` (programmatic consumption).

## Reciprocal mappings

- MITRE ATLAS -- see per-rule `mitre_atlas` field plus aggregate coverage in [COVERAGE.md](../COVERAGE.md)
- NIST AI RMF -- see per-rule `compliance.nist_ai_rmf[]` plus the [AI RMF OSCAL catalog](https://github.com/Agent-Threat-Rule/ai-rmf-oscal-catalog)
- EU AI Act -- per-rule `compliance.eu_ai_act[]` (Article 9, Article 15)
- ISO/IEC 42001 -- per-rule `compliance.iso_42001[]`
- OWASP LLM Top 10 (2025) -- per-rule `compliance.owasp_llm[]`
- SAFE-MCP -- see [SAFE-MCP-MAPPING.md](SAFE-MCP-MAPPING.md) (78/85 techniques, 91.8%)
- OWASP Agentic Skills Top 10 (AST) -- see [OWASP-AST10-MAPPING.md](OWASP-AST10-MAPPING.md) (skill supply chain framework)
- OWASP Agentic AI Maturity Model -- see [OWASP-AGENTIC-MATURITY-MAPPING.md](OWASP-AGENTIC-MATURITY-MAPPING.md) (which ASI detections substantiate governance maturity)

## Contributing

To propose a new mapping or correct an existing one:

1. Open a PR editing the relevant rule under `rules/<category>/ATR-2026-NNNNN-*.yaml`
2. Add or update the `references.owasp_agentic` and/or `compliance.owasp_agentic` block
3. Run `npx tsx scripts/generate-owasp-mapping.ts` to regenerate this file
4. Include the regenerated `docs/OWASP-AGENTIC-MAPPING.md` and `docs/owasp-agentic-mapping.json` in the PR

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full contribution flow.

## References

- OWASP Agentic Top 10 (2026) -- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP GenAI Security Project -- https://genai.owasp.org/
- Project Chair: John Sotiropoulos -- ASI Co-lead
- Agentic Top 10 Co-leads: Keren Katz, Ron F. Del Rosario
- Project contact: https://genai.owasp.org/contact/
- ATR repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
- ATR npm package: https://www.npmjs.com/package/agent-threat-rules
