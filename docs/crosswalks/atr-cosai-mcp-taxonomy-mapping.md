# ATR -> CoSAI MCP Security taxonomy: threat-to-detection mapping

This document maps the twelve threat categories in the Coalition for Secure AI
(CoSAI) **"Model Context Protocol (MCP) Security"** taxonomy to Agent Threat
Rules (ATR) detection content, and -- just as importantly -- says clearly which
CoSAI threat categories ATR **does not** cover because they are architectural,
cryptographic, identity, or infrastructure controls rather than detection.

- **Source document:** *Model Context Protocol (MCP) Security*, Coalition for
  Secure AI (an OASIS Open Project), Workstream 4: Secure Design Patterns for
  Agentic Systems, published 2026-01-27. Threat taxonomy IDs `MCP-T1`..`MCP-T12`
  are taken from Appendix 6.2 of that whitepaper.
- **This mapping:** hand-authored, 2026-07-10. Class sizes are read from the
  ATR rule directories on `main` at authoring time. Verify counts against
  `data/stats.json` before external citation.
- **Companion documents:** [`atr-nsa-mcp-csi-mapping.md`](atr-nsa-mcp-csi-mapping.md)
  maps the NSA/CISA MCP CSI controls; [`atr-attack-crosswalk.md`](atr-attack-crosswalk.md)
  and [`atr-ast-crosswalk.md`](atr-ast-crosswalk.md) map MITRE ATT&CK and OWASP
  respectively. CoSAI's taxonomy does not itself carry ATLAS/ATT&CK or OWASP
  identifiers, so this crosswalk is the bridge: a CoSAI threat resolves through
  ATR's rule metadata to the ATLAS and OWASP codes those companion files map.

## Scope discipline (read first)

**ATR is detection content, not infrastructure.** It is a corpus of
machine-readable rules that flag attack *patterns* in agent/tool inputs,
outputs, descriptions, and call sequences. It is **not** an identity provider,
an authorization engine, a TLS terminator, a rate limiter, or a logging
pipeline. Where a CoSAI threat category is fundamentally an architectural or
cryptographic control, ATR's honest coverage is "out of scope for detection" --
and this document says so rather than claiming a mapping that does not exist.

Coverage labels used below:
- **Detection** -- ATR carries dedicated rules for the attack patterns in this
  category; this is a genuine runtime-detection contribution.
- **Partial** -- ATR detects some observable manifestations of the category, but
  the primary control is architectural; detection is a complement, not the fix.
- **Out of scope** -- the category is an identity, transport, resource, or
  observability control with no runtime attack *pattern* for ATR to match.

## Mapping

| CoSAI threat | Category | ATR coverage | Mapping ATR rule classes |
| :--- | :--- | :--- | :--- |
| MCP-T1 | Improper Authentication and Identity Management | Out of scope (thin detection edge) | Credential/token *exfiltration attempts* surface in `context-exfiltration`; identity issuance and verification are architectural. |
| MCP-T2 | Missing or Improper Access Control | Partial | `privilege-escalation` (42), `excessive-autonomy` (32) detect escalation and over-permissioned actions; access-control *enforcement* is architectural. |
| MCP-T3 | Input Validation/Sanitization Failures | Detection | Command injection and path-traversal patterns in `tool-poisoning` (90) and `privilege-escalation` (42). |
| MCP-T4 | Data/Control Boundary Distinction Failure | Detection (ATR core) | Tool poisoning, full schema poisoning, resource-content poisoning, and prompt injection: `prompt-injection` (242) + `tool-poisoning` (90). |
| MCP-T5 | Inadequate Data Protection and Confidentiality | Detection | Data exfiltration and context leakage: `context-exfiltration` (111). |
| MCP-T6 | Missing Integrity/Verification Controls | Partial | Resource-content poisoning, typosquatting, and shadow-server *patterns* in `skill-compromise` (45) and `tool-poisoning`; cryptographic integrity and remote attestation are architectural. |
| MCP-T7 | Session and Transport Security Failures | Out of scope | MITM, TLS, certificate validation, CSRF, CORS -- transport/crypto controls, no runtime pattern. |
| MCP-T8 | Network Binding/Isolation Failures | Partial (thin) | Malicious-command-execution patterns are detectable (`tool-poisoning`, `privilege-escalation`); network binding and isolation are architectural. |
| MCP-T9 | Trust Boundary and Privilege Design Failures | Partial | Overreliance-on-LLM and manipulation patterns: `agent-manipulation` (106), `excessive-autonomy` (32); consent-model design is architectural. |
| MCP-T10 | Resource Management/Rate Limiting Absence | Out of scope | Resource exhaustion / denial-of-wallet is a rate-limiting control. |
| MCP-T11 | Supply Chain and Lifecycle Security Failures | Partial | Malicious-skill and supply-chain patterns: `skill-compromise` (45); lifecycle governance and signing are architectural. |
| MCP-T12 | Insufficient Logging, Monitoring, and Auditability | Out of scope | ATR *emits* detections that feed a monitoring pipeline, but is not itself a logging or observability system. |

## Coverage summary

Of CoSAI's twelve MCP threat categories, ATR provides:

- **Detection for 3** -- MCP-T3 (input validation), MCP-T4 (data/control boundary,
  ATR's strongest lane), MCP-T5 (data confidentiality).
- **Partial detection for 5** -- MCP-T2, MCP-T6, MCP-T8, MCP-T9, MCP-T11, where a
  runtime detection layer complements an architectural control.
- **Out of scope for 4** -- MCP-T1 (identity), MCP-T7 (transport/crypto), MCP-T10
  (rate limiting), MCP-T12 (logging/observability).

This is the expected shape for a detection standard: ATR is strongest exactly
where MCP's novel risk lives -- the collapse of the data/instruction boundary
across tool descriptions, schemas, and resource content (MCP-T4) -- and it is
honestly out of scope for the identity, transport, and infrastructure controls
that CoSAI's own "Controls and Mitigations" section assigns to the deployment
architecture, not to a detector.

## Coverage beyond CoSAI's MCP scope

CoSAI's taxonomy is deliberately scoped to the MCP protocol surface. ATR also
carries rule classes for model-level threats outside that scope --
`model-abuse` (37), `data-poisoning` (5), `model-security` (3) -- which map to
OWASP LLM Top 10 and MITRE ATLAS entries rather than to an MCP-T category. They
are noted here only so the mapping is not mistaken for the full ATR corpus.
