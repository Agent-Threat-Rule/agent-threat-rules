# ATR → NSA "Model Context Protocol (MCP): Security Design Considerations" Mapping

- **ATR corpus version:** v3.5.2 HEAD, 655 rules on disk across 10 detection-rule categories (`data/stats.json` reports 652 pending a reconcile; headline benchmarks below were measured at v3.5.0).
- **NSA guidance:** *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*, Cybersecurity Information Sheet (CSI), NSA Artificial Intelligence Security Center (AISC), dated May 2026, posted 2026-06-02 on media.defense.gov (U/OO/6030316-26 | PP-26-1834 | Ver. 1.0).
- **Document date:** 2026-06-28
- **Maintainer:** Adam Lin (adam@agentthreatrule.org)
- **License:** MIT
- **Relationship to the Five Eyes mapping:** the April-2026 Five Eyes *"Careful Adoption of Agentic AI Services"* (mapped in [FIVE-EYES-MAPPING.md](./FIVE-EYES-MAPPING.md)) is the cross-government strategic guidance; this NSA CSI is the **MCP-specific technical companion**. This document maps the MCP CSI's risk areas and recommended mitigations to specific ATR rule clusters.

## Source verification

> **Honesty note (read first).** The named risk areas and mitigations below are corroborated across the NSA press release (Article 4496698) and four independent secondary analyses (Adversa AI, GetAIGovernance, Reed Smith, Cybersecurity Dive — see References). The **primary CSI PDF on media.defense.gov returns HTTP 403 to automated fetch**, so — unlike the Five Eyes mapping, whose quotes were extracted verbatim from the primary PDF via browser — the NSA section headings here are **reconstructed from corroborated secondary sources, not yet pinned to verbatim primary text**. A primary-PDF extraction pass (via authenticated browser) is tracked in the Verification status checklist. No claim in this document depends on a heading we could not corroborate from at least two independent sources.

## Executive summary

The NSA MCP CSI ships authoritative **risk areas and mitigation recommendations** and, like every government guidance document, **zero executable detection rules**. Its core framing — that "MCP's rapid proliferation has outpaced the development of its security model, [...] released with a flexible and underspecified design" — is precisely the gap ATR's corpus exists to close at the runtime detection layer.

Two recommendations in the CSI point **directly** at ATR's role:

1. **"Perform local MCP scans."** ATR's 655 MIT-licensed rules *are* local-MCP-scan content — machine-readable YAML signatures with regex patterns, severity, framework metadata, and test cases, already consumed by Cisco AI Defense skill-scanner, Microsoft PyRIT, and the MISP galaxy.
2. **"Adopt a collaborative security approach, such as CISA's AI Cybersecurity Collaboration Playbook"** (the JCDC Playbook the companion Five Eyes guidance also cites). ATR is exactly the open, agentic-specific detection corpus that a JCDC-style contributor brings to the table.

This document does **not** claim NSA endorsement of ATR. It is a community detection-rule starter set for operators implementing the CSI.

---

## Part A — NSA MCP risk areas → ATR rule clusters

### A1. Arbitrary code execution

**NSA concern (paraphrased):** MCP's inverted client-server pattern plus dynamic tool invocation exposes hosts to arbitrary-code-execution paths, including via crafted tool inputs and unverified task propagation between servers.

**Why this needs detection rules:** sandboxing and least-privilege are architectural controls, but the concrete RCE *attempt* is observable at runtime — `eval`/dynamic-code primitives, shell-metacharacter injection, deserialization payloads.

**ATR clusters:**
- `privilege-escalation/` (35 rules) — `ATR-2026-00110` eval-injection, `ATR-2026-00111` shell-escape, `ATR-2026-00112` dynamic-import-exploitation, `ATR-2026-00436` enclave-vm-sandbox-escape-rce
- `tool-poisoning/` (68 rules) — `ATR-2026-00277` echo-template-command-injection, `ATR-2026-00415` flowise-custom-mcp-stdio-rce
- `model-security/` (3 rules) — `ATR-2026-00433` modelcache-torch-load-deserialization-rce

**Strength:** STRONG — concrete CVE-class RCE flaws ship as rules within hours of disclosure (Semantic Kernel MSRC → npm-published in 2h16m, 2026-05-11).

### A2. Authentication & authorization weaknesses

**NSA concern:** many MCP servers expose tools with weak or no authentication; credentials and tokens are mishandled across the trust boundary.

**ATR clusters:**
- `privilege-escalation/` — `ATR-2026-00040` privilege-escalation, `ATR-2026-00451` litellm-admin-sqli (CISA KEV CVE-2026-42208)
- `context-exfiltration/` (104 rules) — `ATR-2026-00021` api-key-exposure, `ATR-2026-00114` oauth-token-abuse, `ATR-2026-00115` env-var-harvesting, `ATR-2026-00534` alibaba-rds-mcp-unauthenticated-metadata-exfil (Akamai 2026-06 disclosure)

**Strength:** STRONG for runtime credential/token abuse. **Honest limit:** ATR detects *abuse* of credentials; it does not *issue or attest* agent identity (W3C DID / agent-attestation territory).

### A3. Insecure context handling & serialization

**NSA concern:** unsafe deserialization and context handling across MCP messages create injection and code-execution surfaces.

**ATR clusters:**
- `model-security/` — `ATR-2026-00433` torch-load deserialization RCE
- `tool-poisoning/` — `ATR-2026-00106` schema-description-contradiction, `ATR-2026-00270` xss-in-tool-response
- `prompt-injection/` — `ATR-2026-00084` structured-data-injection (injection through structured input fields / serialized payloads)

**Strength:** MODERATE — deserialization-RCE precedents covered; generic serialization-format hardening is architectural.

### A4. Trust boundaries, implicit trust & tool poisoning

**NSA concern:** agentic systems introduce dynamic tool invocation and *implicit* trust relationships; one server can propagate unverified tasks into another, and poisoned tool descriptions cross trust boundaries.

**ATR clusters:**
- `tool-poisoning/` — `ATR-2026-00010` mcp-malicious-response, `ATR-2026-00106` schema-description-contradiction, `ATR-2026-00161` important-tag-cross-tool-shadowing
- `agent-manipulation/` (106 rules) — `ATR-2026-00030` cross-agent-attack, `ATR-2026-00074` cross-agent-privilege-escalation, `ATR-2026-00116` a2a-message-validation, `ATR-2026-00117` agent-identity-spoofing

**Strength:** STRONG — tool-poisoning and cross-agent propagation are core ATR coverage (this maps closely to ATR's SAFE-MCP Initial Access / Lateral Movement coverage; see [SAFE-MCP-MAPPING.md](./SAFE-MCP-MAPPING.md)).

### A5. Approval & human-oversight gaps

**NSA concern:** agents take high-impact actions without adequate human-in-the-loop checkpoints; consent flows are weak or fatigued.

**ATR clusters:**
- `excessive-autonomy/` (29 rules) — `ATR-2026-00098` unauthorized-financial-action, `ATR-2026-00099` high-risk-tool-gate (forces an `ask` verdict on financial/destructive/communication/permission/system tool categories), `ATR-2026-00428` nl-unauthorized-shell-execution
- `agent-manipulation/` — `ATR-2026-00118` approval-fatigue

**Strength:** STRONG at raising the signal. **Honest limit:** ATR flags the high-impact call (`response.actions: require_auth_challenge`); the operator-side approval UX is implementation-defined.

### A6. Logging, monitoring & visibility deficiencies

**NSA concern:** insufficient observability — tool and model invocations are not logged with parameters and identities, and audit trails can be evaded.

**ATR contribution (two layers):**
- **Structured event taxonomy** — every ATR rule emits a stable `id`, `severity`, `category`, and `response.actions`; these are the audit-log primitives the CSI's observability recommendation depends on.
- **Audit-evasion detection** — `ATR-2026-00085` audit-evasion, `ATR-2026-00094` audit-bypass, `ATR-2026-00105` silent-action-concealment.

**Strength:** LIMITED-to-MODERATE — ATR supplies the event taxonomy and catches evasion attempts; log retention, tamper-resistance, and signed audit storage are operator-side (this is where the [ai-rmf-oscal-catalog](https://github.com/Agent-Threat-Rule/ai-rmf-oscal-catalog) OSCAL evidence layer connects — see Part C).

### A7. Configuration & deployment pitfalls

**NSA concern:** insecure defaults, unvetted third-party servers, and supply-chain exposure at deploy time.

**ATR clusters:**
- `skill-compromise/` (45 rules) — `ATR-2026-00060` skill-impersonation, `ATR-2026-00062` hidden-capability, `ATR-2026-00065` skill-update-attack (rug-pull), `ATR-2026-00095` mcp-supply-chain-poisoning, `ATR-2026-00419` cursor-mcp-zero-click-config
- `excessive-autonomy/` — `ATR-2026-00500` ssrf-via-agent-url-fetch-instruction

**Strength:** STRONG for supply-chain and skill-integrity precursors; secure-default *enforcement* is operator policy.

---

## Part B — NSA recommended mitigations → how ATR operationalizes each

| NSA recommended mitigation | ATR contribution | Coverage |
|---|---|---|
| **Perform local MCP scans** | The 655-rule corpus **is** local-scan content (YAML signatures, already in Cisco skill-scanner, PyRIT, MISP galaxy) | DIRECT |
| **Input validation against schemas / ranges / context** | `prompt-injection/` input rules + `ATR-2026-00084` structured-data-injection flag malformed / injected inputs at the agent boundary | STRONG |
| **Observability — log all tool/model invocations with params + identities** | Stable per-rule event taxonomy (`id`/`severity`/`category`/`response`) + audit-evasion detection (00085/00094/00105) | PARTIAL (taxonomy + evasion; retention is operator-side) |
| **Outgoing proxy controls / DLP / output filtering** | `context-exfiltration/` (104 rules) + `ATR-2026-00500` ssrf + `ATR-2026-00102` disguised-analytics-exfiltration detect the exfil the proxy/DLP must block | STRONG signal layer |
| **Deny-by-default allowlists / least privilege** | `ATR-2026-00099` high-risk-tool-gate enforces an explicit `ask` on high-risk tool categories | DIRECT |
| **Sandboxing** | Architectural; ATR detects escape *attempts* (00110 eval, 00111 shell, 00436 enclave-escape) | COMPLEMENTARY |
| **Message integrity (inter-server)** | `agent-manipulation/` A2A rules (00116 a2a-message-validation, 00076 inter-agent-message-spoofing) | MODERATE |
| **Data classification zones** | Architectural; ATR detects cross-zone exfil via `context-exfiltration/` | COMPLEMENTARY |

---

## Part C — The OSCAL / NIST tie-in (why this mapping matters beyond NSA)

The NSA CSI's observability and accountability recommendations are exactly what NIST's **SP 800-53 Control Overlays for Securing AI Systems (COSAiS)** and the **OSCAL** assessment layer formalize. ATR already maintains:

- [`ai-rmf-oscal-catalog`](https://github.com/Agent-Threat-Rule/ai-rmf-oscal-catalog) (CC0) — ATR's detection rules expressed as an OSCAL-consumable AI-RMF control profile.
- An in-progress NIST OSCAL community contribution (AI-RMF profile examples, PR #338).

This NSA MCP mapping is the **MCP-specific evidence exhibit** for that NIST track: it shows, control-area by control-area, that ATR's rules are the machine-executable enforcement layer beneath the controls NSA recommends and NIST is overlaying. It is the artifact to bring to the COSAiS community channel (`overlays-securing-ai@list.nist.gov` / the #NIST-Overlays-Securing-AI Slack).

---

## What ATR does NOT cover (be honest)

- **Cryptographic agent identity / attestation.** Detection-side, not identity-side (W3C DID / agent-attestation frameworks).
- **The human-approval UX** for high-impact actions. ATR raises the signal; the operator builds the gate.
- **Sandbox / network isolation, secure defaults, log retention & tamper-resistance.** Architectural and operator-side; ATR detects precursors and evasion, not infrastructure posture.
- **Paraphrase bypass of canonical payloads.** Regex-and-pattern detection is one layer, not the only layer.
- **Multimodal (image/audio) injection** and **non-English coverage** remain partial (Japanese/German extension in progress).
- **Primary-PDF verbatim pinning** of NSA headings is pending (see Source verification).

---

## References

- NSA CSI, *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation* (primary PDF, defense.gov media library, 2026-06-02): https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF
- NSA press release (Article 4496698): https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/
- Secondary corroboration: Adversa AI (Top MCP security resources, 2026-06), GetAIGovernance, Reed Smith Viewpoints, Cybersecurity Dive (NIST control-overlays coverage).
- CISA AI Cybersecurity Collaboration Playbook (JCDC): https://www.cisa.gov/resources-tools/resources/ai-cybersecurity-collaboration-playbook
- ATR rule corpus: https://github.com/Agent-Threat-Rule/agent-threat-rules
- Sibling mappings: [FIVE-EYES-MAPPING.md](./FIVE-EYES-MAPPING.md) · [SAFE-MCP-MAPPING.md](./SAFE-MCP-MAPPING.md) · [MITRE-ATLAS-MAPPING.md](./MITRE-ATLAS-MAPPING.md) · [OWASP-AGENTIC-MAPPING.md](./OWASP-AGENTIC-MAPPING.md)
- ATR OSCAL AI-RMF catalogue (CC0): https://github.com/Agent-Threat-Rule/ai-rmf-oscal-catalog

## Verification status

- [x] NSA CSI risk areas corroborated across ≥2 independent secondary sources each.
- [x] Recommended-mitigation list corroborated (local MCP scans, input validation, observability, outgoing proxy/DLP, deny-by-default, sandboxing, message integrity, data classification).
- [x] All 16 cited ATR rule IDs verified to exist at v3.5.2 HEAD (2026-06-28).
- [x] Per-category counts pinned to disk truth at HEAD (655 total; prompt-injection 223, agent-manipulation 106, context-exfiltration 104, tool-poisoning 68, skill-compromise 45, model-abuse 37, privilege-escalation 35, excessive-autonomy 29, data-poisoning 5, model-security 3).
- [ ] **Primary-PDF verbatim extraction** of NSA section headings (defense.gov 403s automated fetch; pending authenticated-browser pass).
- [ ] Reconcile `data/stats.json` 652 vs disk 655 before external citation of a single headline number.
- [ ] Second-reviewer sanity-check of STRONG / MODERATE / LIMITED strength ratings.
