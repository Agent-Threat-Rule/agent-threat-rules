# ATR → MCP-38 Threat Taxonomy Mapping

Last updated: 2026-07-12 (corpus re-stamp to v3.5.8; cited rule IDs
spot-checked as still resolving; the 7-gap authoring roadmap is carried forward
and re-validated as those dedicated rules are written)
ATR corpus: v3.5.8, 793 rules (10 categories)
Source taxonomy: **MCP-38 — A Comprehensive Threat Taxonomy for Model Context
Protocol Systems (v1.0)**, Shen, Toyoda & Leung, arXiv:2603.18063. 38 protocol-
specific threat categories (MCP-01 … MCP-38) grouped into 5 tactic categories
(I–V), cross-referenced by the authors to OWASP LLM Top 10, OWASP Agentic
(ASI01–ASI10), and MITRE ATLAS.

> **Methodology & caveat.** This first-pass mapping was produced by keyword-
> matching each MCP-38 technique against the full ATR rule corpus, then
> classifying coverage as **Covered** (multiple dedicated rules), **Partial**
> (1–2 related rules / adjacent coverage), or **Candidate gap** (no keyword
> match). Keyword scans are approximate: broad techniques (e.g. MCP-07 Command
> Injection, MCP-19 Direct Prompt Injection) match a large fraction of the
> corpus and are unambiguously covered, while a "candidate gap" may still be
> partially covered by a rule using different terminology. The 7 candidate gaps
> below should therefore be read as a **verification + authoring roadmap**, not
> a definitive absence. Example rule IDs are illustrative, not exhaustive.

## Coverage summary

| MCP-38 tactic category | Techniques | Covered | Partial | Candidate gap |
|---|---|---|---|---|
| I — Semantic Manipulation & Poisoning | 6 | 3 | 0 | 3 |
| II — Prompt Injection & Boundary Breaking | 7 | 6 | 0 | 1 |
| III — Identity, Trust & Supply Chain | 11 | 8 | 2 | 1 |
| IV — Access Control & Logic Drift | 8 | 6 | 1 | 1 |
| V — Data Exfiltration & Resource Abuse | 6 | 5 | 0 | 1 |
| **Total** | **38** | **28** | **3** | **7** |

**31 / 38 MCP-38 techniques map to at least one ATR rule (81.6%); 28 have
substantive multi-rule coverage. 7 candidate gaps form the roadmap below.**

---

## Detailed mapping

### Category I — Semantic Manipulation & Poisoning (3/6 covered)
| MCP-38 | Technique | Status | Example ATR rules / notes |
|---|---|---|---|
| MCP-10 | Tool Description Poisoning | Covered | ATR-2026-00212, ATR-2026-00421 (tool-poisoning) |
| MCP-11 | Full Schema Poisoning | **Candidate gap** | extension of MCP-10 into parameter/schema fields — author a dedicated full-schema-poisoning rule |
| MCP-12 | Resource Content Injection | Covered | ATR-2026-00852, ATR-2026-00856 |
| MCP-13 | Tool Shadowing / Name Collision | Covered | ATR-2026-00579 + name-collision rules |
| MCP-14 | Cross-Server Tool Shadowing | **Candidate gap** | MCP-13 across server boundaries — author cross-server variant |
| MCP-15 | Preference Manipulation | **Candidate gap** | tool-selection preference steering — author dedicated rule |

### Category II — Prompt Injection & Boundary Breaking (6/7 covered)
| MCP-38 | Technique | Status | Example ATR rules / notes |
|---|---|---|---|
| MCP-07 | Command Injection | Covered | ATR-2026-00418, ATR-2026-00537, **ATR-2026-01931** (gemini-mcp-tool CVE-2026-0755) |
| MCP-08 | File System Exposure / Path Traversal | Covered | ATR-2026-00569, ATR-2026-00578, **ATR-2026-01931** (@file exfil) |
| MCP-09 | Web Vulns (SSRF / SQLi) | Covered | ATR-2026-01605–01608 (SSRF), ATR-2026-00522 (SQLi) |
| MCP-17 | Parasitic Toolchain | **Candidate gap** | benign-tools-composed-into-attack chains — author dedicated rule |
| MCP-19 | Prompt Injection (Direct) | Covered | core prompt-injection category (491 keyword hits) |
| MCP-20 | Prompt Injection (Indirect) | Covered | ATR-2026-00405, ATR-2026-00702, **ATR-2026-01930** (MCP sampling injection) |
| MCP-37 | Sandbox Escape | Covered | ATR-2026-00432, ATR-2026-00440 |

### Category III — Identity, Trust & Supply Chain (8/11 covered)
| MCP-38 | Technique | Status | Example ATR rules / notes |
|---|---|---|---|
| MCP-01 | Identity Spoofing | Covered | ATR-2026-00117, ATR-2026-00076 |
| MCP-02 | Credential Theft | Covered | ATR-2026-00113, ATR-2026-00576 |
| MCP-03 | Replay Attacks | Partial | ATR-2026-00076, ATR-2026-00275 — no nonce/replay-specific rule |
| MCP-16 | Rug Pull / Dynamic Behavior Change | Covered | ATR-2026-00581 (post-approval redefinition), ATR-2026-00329 |
| MCP-18 | Shadow MCP Servers | **Candidate gap** | rogue/unregistered server detection — author dedicated rule |
| MCP-26 | Supply Chain (malicious packages) | Covered | ATR-2026-00416, ATR-2026-00575 (npm worm), skill-compromise category |
| MCP-27 | Missing Integrity Verification | Covered | ATR-2026-00418, ATR-2026-00076 |
| MCP-28 | Man-in-the-Middle | Partial | ATR-2026-00256 — no TLS-strip / cert-pinning rule |
| MCP-29 | Protocol Gaps / Weak Auth | Covered | ATR-2026-00108, ATR-2026-00531 (unauthenticated API) |
| MCP-30 | Insecure stdio | Covered | ATR-2026-00416, ATR-2026-00538 |
| MCP-31 | MCP Endpoint / DNS Rebinding | Covered | ATR-2026-00524, ATR-2026-01605 |

### Category IV — Access Control & Logic Drift (6/8 covered)
| MCP-38 | Technique | Status | Example ATR rules / notes |
|---|---|---|---|
| MCP-04 | Privilege Escalation | Covered | ATR-2026-00074, ATR-2026-00117 (privilege-escalation category) |
| MCP-05 | Excessive Permissions | Covered | ATR-2026-00420, ATR-2026-00441 |
| MCP-06 | Improper Multitenancy | Covered | ATR-2026-00418, ATR-2026-00449 |
| MCP-21 | Overreliance on LLM | Covered | ATR-2026-00573, ATR-2026-00574 |
| MCP-22 | Insecure Approval Dialogs | **Candidate gap** | low-context approval prompt detection — author dedicated rule |
| MCP-23 | Consent / Approval Fatigue | Partial | ATR-2026-00118 (approval-fatigue) — single rule |
| MCP-35 | Planning / Agent Logic Manipulation | Covered | ATR-2026-00032 (goal hijacking) + agent-manipulation category |
| MCP-36 | Multi-Agent Context Injection | Covered | ATR-2026-00030 (cross-agent), ATR-2026-00076 (inter-agent spoofing) |

### Category V — Data Exfiltration & Resource Abuse (5/6 covered)
| MCP-38 | Technique | Status | Example ATR rules / notes |
|---|---|---|---|
| MCP-24 | Data Exfiltration via Aggregation | Covered | context-exfiltration category (139 keyword hits) |
| MCP-25 | Privacy Inversion / Correlation | **Candidate gap** | cross-tool correlation / de-anonymization — author dedicated rule |
| MCP-32 | Unrestricted Network Access | Covered | ATR-2026-00021, ATR-2026-00568 (cloud-metadata) |
| MCP-33 | Resource Exhaustion / DoS | Covered | ATR-2026-00050 + unbounded-consumption rules |
| MCP-34 | Tool Manifest Disclosure | Covered | ATR-2026-00161, ATR-2026-01303 |
| MCP-38 | Invisible Agent Activity / No Audit Trail | Covered | ATR-2026-00113 + covert-action coverage (incl. ATR-2026-01930 hide-from-user clause) |

---

## Roadmap — 7 candidate gaps (authoring priority)

| # | MCP-38 | Technique | Why it is a distinct gap |
|---|---|---|---|
| 1 | MCP-11 | Full Schema Poisoning | poisoning moves from the tool *description* into parameter/enum/`required` schema fields — distinct detectable surface from MCP-10 |
| 2 | MCP-14 | Cross-Server Tool Shadowing | a server overrides another server's tool name across boundaries — needs multi-server context, not single-manifest matching |
| 3 | MCP-15 | Preference Manipulation | content that biases the agent's tool *selection* toward an attacker tool without overt injection |
| 4 | MCP-17 | Parasitic Toolchain | each tool is individually benign; the attack is the *composition* — requires sequence/graph reasoning |
| 5 | MCP-18 | Shadow MCP Servers | detection of unregistered / rogue servers joining the session |
| 6 | MCP-22 | Insecure Approval Dialogs | approval prompts that hide the consequential action behind insufficient context |
| 7 | MCP-25 | Privacy Inversion | individually non-sensitive outputs correlated into sensitive inference |

These 7 are the recommended next authoring batch for full MCP-38 coverage.
Partials MCP-03 (replay), MCP-23 (consent fatigue), MCP-28 (MitM) would each
benefit from a second dedicated rule.

## Related ATR mappings
ATR also publishes mappings to [MITRE ATLAS](MITRE-ATLAS-MAPPING.md),
[SAFE-MCP](SAFE-MCP-MAPPING.md), [OWASP Agentic](OWASP-AGENTIC-MAPPING.md),
[OWASP LLM](OWASP-MAPPING.md), and [OWASP AISVS](OWASP-AISVS-MAPPING.md).
MCP-38 cross-references those same frameworks, so the per-rule reference blocks
(`owasp_llm`, `owasp_agentic`, `mitre_atlas`) already carry most of the
provenance needed to maintain this mapping as the corpus grows.
