# ATR → NSA "Model Context Protocol (MCP): Security Design Considerations" Mapping

- **ATR corpus version:** v3.5.2 HEAD, 655 rules across 10 detection-rule categories. Headline benchmarks below were measured at v3.5.0 (2026-06-16).
- **NSA guidance:** *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*, Cybersecurity Information Sheet (CSI), **NSA Artificial Intelligence Security**, **May 2026 Ver. 1.0** (U/OO/6030316-26 | PP-26-1834), posted 2026-06-02 on media.defense.gov; developed with the Carnegie Mellon University Software Engineering Institute.
- **Document date:** 2026-06-28
- **Maintainer:** Adam Lin (adam@agentthreatrule.org)
- **License:** MIT
- **Relationship to the Five Eyes mapping:** the NSA CSI explicitly cites *"Careful Adoption of Agentic AI Services"* (its reference [3]) as the general agentic-AI guidance and positions itself as the **MCP-specific technical companion**. ATR maps that Five Eyes guidance in [FIVE-EYES-MAPPING.md](./FIVE-EYES-MAPPING.md); this document maps the MCP CSI's verbatim section structure.

## Source verification

> **Primary-verified.** Unlike a first draft sourced from secondary analyses, the section headings and recommendations below are extracted **verbatim from the primary CSI PDF** (17 pages, May 2026 Ver. 1.0). The CSI organizes content into **8 named security concerns**, a set of real-world examples, and **9 named recommendations** — reproduced here exactly. (The defense.gov/nsa.gov PDF endpoints return HTTP 403 to automated fetch; the document was retrieved through a browser and read locally.)

## Executive summary

The NSA MCP CSI ships authoritative risk framing and **9 named recommendations**, and — like all government guidance — **zero executable detection rules**. Its thesis is that *"MCP's rapid proliferation has outpaced the development of its security model"* and that secure-by-default behavior *"must be enforced through implementation rigor, proper coding practices, clearer protocol specifications, and robust validation tools."* ATR is one such validation-tool layer.

Three of the CSI's recommendations point **directly** at ATR's role:

- **"Scan local network for open or vulnerable MCP servers"** — the CSI names MCP Scanner, Ramparts, CyberMCP, and Proximity as the tools for this. ATR's 655 rules are the machine-readable scan content those tools consume (ATR already ships in Cisco AI Defense's skill-scanner).
- **"Track and patch MCP related vulnerabilities"** — the CSI recommends a *"formal process for monitoring MCP related vulnerabilities ... through CVEs, vendor advisories, or open source issue trackers ... subscribing to relevant security feeds."* That is precisely ATR's CVE flywheel (2,262 CVEs tracked across 15 feeds → 594 detection-ready signatures).
- **"Instrument for logging and detection"** — the CSI wants *"all tool and model invocations ... logged"* with a way to *"identify suspicious patterns ... while minimizing false positives."* ATR's per-rule event taxonomy + 0-FP-gated rules are that detection layer.

This document does **not** claim NSA endorsement (the CSI carries an explicit non-endorsement disclaimer). It is a community detection-rule starter set for operators implementing the CSI.

---

## Part A — the CSI's 8 "Security concerns in MCP design, implementation, and practices" → ATR

| # | NSA security concern (verbatim) | ATR rule clusters (verified IDs) | Strength |
|---|---|---|---|
| A1 | **Access control** — no protocol-level identity binding; missing RBAC/CRUD; *"unverified task propagation"* between servers | `privilege-escalation/` 00040 priv-esc; `context-exfiltration/` 00114 oauth-token-abuse; `agent-manipulation/` 00030 cross-agent-attack, 00074 cross-agent-priv-esc | STRONG (abuse-side; identity issuance is infra) |
| A2 | **Insecure context or data serialization** — serialized content with comments/prompts opens injection / embedded code | `model-security/` 00433 torch-load-deser-rce; `prompt-injection/` 00084 structured-data-injection | MODERATE |
| A3 | **Poor approval workflows** — capability/data-access changes to a trusted server made without re-approval | `excessive-autonomy/` 00099 high-risk-tool-gate, 00098 unauthorized-financial-action; `agent-manipulation/` 00118 approval-fatigue | STRONG (signal-side) |
| A4 | **Token or session security** — optional OAuth bearer tokens, no lifecycle/replay control | `context-exfiltration/` 00114 oauth-token-abuse | MODERATE (lifecycle mgmt is infra) |
| A5 | **Misconfigurations and poor implementation** — trivial servers repurposed; no task/data isolation | `skill-compromise/` 00095 supply-chain-poisoning, 00065 skill-update-attack; `tool-poisoning/` 00419 cursor-mcp-zero-click-config | STRONG |
| A6 | **Inconsistent behaviors** — non-deterministic interpretation an attacker can precondition | `prompt-injection/` 00005 multi-turn, 00081 semantic-multi-turn; `agent-manipulation/` 00032 goal-hijacking | MODERATE |
| A7 | **Poor or missing audit logs** — logging left to implementers; needs traceable sequence + anomaly detection | `prompt-injection/` 00085 audit-evasion, 00094 audit-bypass; `tool-poisoning/` 00105 silent-action-concealment; + every rule's stable `id`/`severity`/`category`/`response` taxonomy | MODERATE |
| A8 | **Denial of service and fatigue-based techniques** — prompt storms, recursive tasks, "lethargy" resource exhaustion | `excessive-autonomy/` 00050 runaway-loop, 00051 resource-exhaustion, 00052 cascading-failure | STRONG |

The CSI's real-world examples section maps cleanly onto existing ATR coverage too: *Tool parameter injection* → 00066/00277; *Tool invocation path confusion / naming collisions* → 00089 polymorphic-aliasing, 00106 schema-description-contradiction; *Unrestricted GitHub repo access* → 00064 over-permissioned-skill; *WhatsApp MCP rug-pull* → 00065 skill-update-attack; *Poisoning output for downstream automation* → 00083 indirect-tool-injection, 00063 multi-skill-chain; *CVE-2025-49596 MCP-Inspector RCE* → **known gap** (tracked as SAFE-T1109 in [SAFE-MCP-MAPPING.md](./SAFE-MCP-MAPPING.md)).

---

## Part B — the CSI's 9 "Recommendations" → how ATR operationalizes each

| # | NSA recommendation (verbatim) | ATR contribution | Coverage |
|---|---|---|---|
| R1 | **Choose supported MCP projects when possible** | `skill-compromise/` 00060 impersonation, 00062 hidden-capability flag unmaintained / trojanized projects | COMPLEMENTARY |
| R2 | **Design for boundaries** (trust zones, data-classification zones, prefer local server, filtering outgoing proxy / DLP) | `context-exfiltration/` (104 rules) incl. 00500 ssrf, 00102 disguised-analytics, 00261 markdown-image-exfil detect the cross-zone leakage the proxy/DLP must block | STRONG signal (zone architecture is operator-side) |
| R3 | **Validate parameters** (against schemas, ranges, intended context; block ambiguous-source forwarding) | `prompt-injection/` input rules + 00084 structured-data-injection, 00066 parameter-injection | STRONG |
| R4 | **Constrain and sandbox tool execution** (AppContainers/seccomp/AppArmor/SELinux; least privilege; deny at runtime) | architectural; ATR detects escape *attempts*: 00110 eval, 00111 shell-escape, 00436 enclave-sandbox-escape | COMPLEMENTARY |
| R5 | **Sign and verify MCP messages** (crypto signatures in payload, time-bound, replay metadata; OWASP ASVS V7) | `agent-manipulation/` 00116 a2a-message-validation, 00076 inter-agent-message-spoofing detect unsigned/spoofed message abuse | MODERATE (signing is infra) |
| R6 | **Filter and monitor output pipelines and chained execution** (treat each output as untrusted; detect indirect injection / toolchain pivot) | **ATR core:** `prompt-injection/` 00002 indirect, 00083 indirect-tool-injection, 00080 encoding-evasion; `tool-poisoning/` 00010 malicious-response; 00063 multi-skill-chain | DIRECT |
| R7 | **Instrument for logging and detection** (log all invocations w/ params + identities + hashes; SIEM; minimize FP) | per-rule event taxonomy (`id`/`severity`/`category`/`response`) + audit-evasion detection (00085/00094/00105); ATR rules are 0-FP-gated, matching the CSI's "minimize false positives" | STRONG |
| R8 | **Track and patch MCP related vulnerabilities** (CVE / advisory / OSS-tracker monitoring; security-feed subscription; versioned inventory) | **ATR CVE flywheel:** 2,262 CVEs tracked across 15 feeds → 88 active rules + 594 detection-ready proposals. Proof: 00451 litellm-admin-sqli (CISA KEV), 00534 alibaba-rds-mcp (Akamai 2026-06), Semantic Kernel MSRC → rule in ~2h | DIRECT |
| R9 | **Scan local network for open or vulnerable MCP servers** (CSI names MCP Scanner, Ramparts, CyberMCP, Proximity) | **ATR is the scan content** those tools consume — 655 machine-readable rules, already integrated in Cisco AI Defense's skill-scanner | DIRECT |

**The headline:** R6–R9 are ATR's exact wheelhouse, and R8/R9 read almost as a specification of what ATR already does — a CVE-fed, continuously-updated, machine-executable rule corpus that local scanners consume.

---

## Part C — the OSCAL / NIST tie-in

R7 (logging/observability) and the CSI's audit-log concern (A7) are what NIST's **SP 800-53 Control Overlays for Securing AI Systems (COSAiS)** and the **OSCAL** assessment layer formalize. ATR already maintains:

- [`ai-rmf-oscal-catalog`](https://github.com/Agent-Threat-Rule/ai-rmf-oscal-catalog) (CC0) — ATR rules as an OSCAL-consumable AI-RMF control profile.
- An in-progress NIST OSCAL community contribution (AI-RMF profile examples, PR #338).

This NSA MCP mapping is the **MCP-specific evidence exhibit** for that NIST track and the artifact to bring to the COSAiS community channel (`overlays-securing-ai@list.nist.gov` / the #NIST-Overlays-Securing-AI Slack).

---

## What ATR does NOT cover (be honest)

- **Cryptographic agent identity / message signing** (A1, R5) — detection-side, not identity/PKI-side.
- **The human-approval UX** for high-impact actions (A3) — ATR raises the signal; the operator builds the gate.
- **Sandbox / network isolation, secure defaults, log retention & tamper-resistance** (R4, A7) — architectural; ATR detects precursors and evasion, not infrastructure posture.
- **CVE-2025-49596 (MCP-Inspector RCE)** — a named CSI example with no ATR rule yet (tracked gap SAFE-T1109).
- **Paraphrase bypass, multimodal (image/audio) injection, non-English coverage** — partial; one defense layer, not the only one.

---

## References

- NSA CSI, *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*, May 2026 Ver. 1.0 (U/OO/6030316-26 | PP-26-1834). Primary PDF: https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF · Press release: https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/
- The CSI's own references include the Five Eyes *Careful Adoption of Agentic AI Services* [3], OWASP ASVS V7, OASIS CoSAI [25], and Docker's MCP security analysis [24].
- CISA AI Cybersecurity Collaboration Playbook (JCDC): https://www.cisa.gov/resources-tools/resources/ai-cybersecurity-collaboration-playbook
- ATR corpus: https://github.com/Agent-Threat-Rule/agent-threat-rules
- Sibling mappings: [FIVE-EYES-MAPPING.md](./FIVE-EYES-MAPPING.md) · [SAFE-MCP-MAPPING.md](./SAFE-MCP-MAPPING.md) · [MITRE-ATLAS-MAPPING.md](./MITRE-ATLAS-MAPPING.md) · [OWASP-AGENTIC-MAPPING.md](./OWASP-AGENTIC-MAPPING.md)
- ATR OSCAL AI-RMF catalogue (CC0): https://github.com/Agent-Threat-Rule/ai-rmf-oscal-catalog

## Verification status

- [x] **Primary CSI PDF extracted verbatim** (17 pages, May 2026 Ver. 1.0) — 8 security concerns + 9 recommendations reproduced exactly.
- [x] All cited ATR rule IDs verified to exist at v3.5.2 HEAD (2026-06-28).
- [x] Per-category counts pinned to disk truth (655 total).
- [x] CSI cross-references confirmed: Five Eyes guidance [3], OWASP ASVS V7, OASIS CoSAI [25], CVE-2025-49596.
- [ ] Second-reviewer sanity-check of STRONG / MODERATE / COMPLEMENTARY strength ratings.
- [ ] Add reverse index (ATR rule → CSI concern/recommendation), matching the SAFE-MCP mapping's cross-reference table.
