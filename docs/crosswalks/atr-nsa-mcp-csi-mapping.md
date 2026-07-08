# ATR -> NSA/CISA MCP Security CSI: control-to-detection mapping

This document maps the enumerable controls in the NSA/CISA Cybersecurity
Information Sheet **"Model Context Protocol (MCP): Security Design
Considerations"** to Agent Threat Rules (ATR) detection content, and -- just as
importantly -- says clearly which CSI controls ATR **does not** cover because
they are architectural, cryptographic, or infrastructure controls rather than
detection.

- **Source document:** *Model Context Protocol (MCP): Security Design
  Considerations*, Cybersecurity Information Sheet, **NSA Artificial Intelligence
  Security**, May 2026 Ver. 1.0 (U/OO/6030316-26 | PP-26-1834), posted
  2026-05-20, developed with the Carnegie Mellon University Software Engineering
  Institute.
- **This mapping:** hand-authored, 2026-07-08. Rule ids below were verified to
  exist in the ATR corpus at authoring time. Class sizes are read from the rule
  directories.
- **Companion documents:** [`docs/NSA-MCP-MAPPING.md`](../NSA-MCP-MAPPING.md)
  maps the CSI's verbatim 8 security concerns + 9 recommendations section by
  section; this file is the **control-oriented** cut that groups the CSI's
  recommendations by the concrete mechanism an operator would enable (schema
  validation, observability, egress filtering, session trust) and states ATR's
  scope boundary for each. Where they overlap, `NSA-MCP-MAPPING.md` is the more
  granular reference.

## Scope discipline (read first)

**ATR is detection content, not infrastructure.** It is a corpus of
machine-readable rules that flag attack *patterns* in agent/tool inputs,
outputs, descriptions, and call sequences. It is **not** an identity provider, a
sandbox, a logging pipeline, a DLP proxy, a certificate authority, or a scanner.
So for every CSI control the honest question is: *"is this control a detection
problem (ATR can carry content for it) or an architecture problem (ATR can, at
most, detect attempts to violate it)?"* Each row below answers that.

Coverage labels:
- **DETECTION (in-scope):** ATR ships rules that fire on this attack surface.
- **DETECTS-ATTEMPTS:** the control itself is architectural, but ATR detects
  prose/payloads that describe or attempt to defeat it.
- **OUT-OF-SCOPE:** an architectural/cryptographic/infra control with no
  detection surface ATR can meaningfully carry; ATR does not cover it. Flagged
  honestly so this table is not read as "ATR does everything."

This document does **not** claim NSA endorsement -- the CSI carries an explicit
non-endorsement disclaimer. It is a community detection-rule starter set for
operators implementing the CSI.

---

## Part A -- CSI controls grouped by mechanism -> ATR

### 1. Input / parameter validation (validate against schemas, ranges, intended context)

The CSI calls for validating tool-call parameters against their schemas and
intended context, and blocking forwarding of ambiguous-source input.

| CSI control | ATR coverage | Example rules | Label |
|---|---|---|---|
| Validate tool-call parameters against schema / ranges | ATR flags injection payloads *inside* tool arguments (shell / SQL / path / template / null-byte) -- the malicious content a schema check should reject | `skill-compromise/` ATR-2026-00066 parameter-injection | DETECTION |
| Block ambiguous-source input from being forwarded to tools | indirect-injection detection on external content consumed by tools | `prompt-injection/` ATR-2026-00002 indirect-prompt-injection | DETECTION |
| Detect schema/description inconsistency used to smuggle intent | `tool-poisoning/` ATR-2026-00106 schema-description-contradiction | DETECTION |

> Boundary: ATR does not *enforce* a JSON Schema (that is the MCP host's job);
> it detects the adversarial content that a validator is supposed to stop, which
> is useful as a second layer and for catching validator bypasses.

### 2. Tool description / context poisoning (the CSI's named threats)

The CSI names **tool poisoning** (malicious content in tool descriptions) and
**context poisoning** (malicious content injected into agent context) as primary
threats. This is ATR's densest coverage area.

| CSI threat | ATR coverage | Example rules | Label |
|---|---|---|---|
| Tool poisoning (hidden instructions in tool descriptions) | `tool-poisoning/` (85 rules) -- description-embedded consent-bypass, trust-escalation, hidden safety-bypass, silent-action concealment | ATR-2026-00100 consent-bypass, ATR-2026-00101 trust-escalation, ATR-2026-00103 hidden-safety-bypass, ATR-2026-00105 silent-action-concealment | DETECTION |
| Context poisoning (malicious content injected into shared context) | `context-exfiltration/` (111 rules) + indirect-injection: poisoned external content and cross-context leakage | `prompt-injection/` ATR-2026-00002 indirect; `context-exfiltration/` ATR-2026-00102 disguised-analytics, ATR-2026-00261 markdown-image-exfil | DETECTION |
| Malicious content in MCP tool responses | `tool-poisoning/` ATR-2026-00010 mcp-malicious-response, ATR-2026-00011 tool-output-injection | DETECTION |
| Parasitic / chained tool execution used to compose an attack | `skill-compromise/` ATR-2026-00063 skill-chain-attack | DETECTION (topical; see gap note) |

### 3. Output pipeline filtering + chained-execution monitoring

The CSI recommends treating every tool output as untrusted and monitoring
chained execution for indirect injection and toolchain pivots. This is ATR's
strongest cluster.

| CSI control | ATR coverage | Example rules | Label |
|---|---|---|---|
| Treat each tool output as untrusted; screen for indirect injection | `prompt-injection/` indirect-injection (part of 242-rule category) | ATR-2026-00002 indirect-prompt-injection | DETECTION |
| Monitor chained execution / toolchain pivot | `skill-compromise/` ATR-2026-00063 skill-chain-attack; `tool-poisoning/` ATR-2026-00010 malicious-response | DETECTION |

### 4. Observability / logging (log all invocations with params, identities, hashes)

The CSI asks operators to **log all tool and model invocations, including
parameters and caller identity**, feed a SIEM, and minimize false positives.

| CSI control | ATR coverage | Label |
|---|---|---|
| Emit a full audit trail of tool + model invocations (params + identity) | ATR emits **no logs and does no instrumentation** -- this is a pipeline/host responsibility | OUT-OF-SCOPE |
| Feed a SIEM with detections; minimize false positives | ATR supplies the **detection content** a SIEM consumes: machine-readable rules with a stable per-rule `id`/`severity`/`category` event taxonomy, and a 65K-benign 0-FP gate that matches the CSI's "minimize false positives" intent | DETECTION (content only, not the SIEM) |
| Detect attempts to evade/suppress logging | `tool-poisoning/` ATR-2026-00105 silent-action-concealment (description text instructing the agent to hide actions) | DETECTS-ATTEMPTS |

> Boundary: the CSI's observability recommendation is an infrastructure control
> (the MCP host must log). ATR is the rule layer a logging/SIEM stack applies to
> those logs, plus detection of instructions that try to keep activity
> *out* of the logs. It cannot substitute for the instrumentation itself.
> MCP-38's threat MCP-38 (Invisible Agent Activity / No Observability) is the
> attacker-side of this same control -- see the OWASP-axis note in the MCP-38
> crosswalk.

### 5. Egress control / DLP proxy + URL pinning

The CSI recommends a **filtering outgoing proxy (DLP)** and **URL pinning** so a
compromised server cannot exfiltrate data or reach arbitrary destinations.

| CSI control | ATR coverage | Example rules | Label |
|---|---|---|---|
| DLP proxy filtering outbound data | the **proxy** is infra; ATR detects the exfiltration *patterns* the proxy must block | `context-exfiltration/` ATR-2026-00102 disguised-analytics, ATR-2026-00261 markdown-image-exfil | DETECTS-ATTEMPTS |
| URL pinning / block arbitrary egress (SSRF) | SSRF detection on agent URL-fetch instructions | `excessive-autonomy/` ATR-2026-00500 ssrf-via-agent-url-fetch; `tool-poisoning/` ATR-2026-00013 tool-ssrf | DETECTS-ATTEMPTS |
| Enforce the egress allowlist / pin certificates | allowlisting and pinning are network/transport controls | OUT-OF-SCOPE |

### 6. Session trust, per-action least-privilege tokens, signed provenance

The CSI recommends **default-distrust sessions**, **per-action least-privilege
tokens**, and **signed provenance for dynamically discovered servers**.

| CSI control | ATR coverage | Example rules | Label |
|---|---|---|---|
| Sessions default-untrusted; per-action least-privilege scoping | token lifecycle/scoping is an identity/authorization control; ATR detects token/credential *abuse* | `context-exfiltration/` ATR-2026-00114 oauth-token-abuse | DETECTS-ATTEMPTS |
| Signed provenance for dynamically discovered servers | cryptographic signing/verification of manifests is infra; ATR detects supply-chain / registry poisoning *attempts* | `tool-poisoning/` ATR-2026-00095 supply-chain-poisoning, ATR-2026-00096 registry-poisoning | DETECTS-ATTEMPTS |
| Issue, bind, rotate, and verify per-action tokens | token issuance/binding/rotation is an identity-provider control | OUT-OF-SCOPE |
| Verify cryptographic server identity / manifest signatures | signature verification is a CA / crypto control | OUT-OF-SCOPE |

### 7. Sandboxing / resource limits (adjacent CSI controls)

| CSI control | ATR coverage | Example rules | Label |
|---|---|---|---|
| Constrain and sandbox tool execution | sandboxing is architectural; ATR detects escape *attempts* | `privilege-escalation/` shell-escape / eval rules | DETECTS-ATTEMPTS |
| Guard against resource exhaustion / fatigue-based DoS | ATR detects textual descriptions of runaway loops / exhaustion, not live runtime resource state | `excessive-autonomy/` ATR-2026-00050 runaway-agent-loop, ATR-2026-00051 resource-exhaustion | DETECTS-ATTEMPTS |

---

## Part B -- honest gap ledger

Controls the CSI recommends that ATR **does not** cover (OUT-OF-SCOPE above),
collected so the boundary is unambiguous:

1. **Full invocation logging / observability instrumentation** -- ATR emits no
   logs. (Detection *content* for a SIEM is in-scope; the logging pipeline is
   not.)
2. **DLP proxy, egress allowlisting, URL/certificate pinning** -- network and
   transport enforcement. ATR detects the exfiltration/SSRF patterns these
   controls block, but does not implement the controls.
3. **Per-action least-privilege token issuance, binding, and rotation** --
   identity/authorization infrastructure.
4. **Signed provenance / cryptographic server identity and manifest
   verification** -- CA/crypto infrastructure. ATR detects supply-chain and
   registry poisoning attempts, not signature validity.
5. **Sandboxing / container isolation enforcement** -- OS/runtime control. ATR
   detects escape attempts only.
6. **Network scanning for open/vulnerable MCP servers** -- ATR is not a scanner
   and does no network discovery; it is the rule content such scanners consume.

The honest one-line framing: **ATR is the detection-content layer beneath these
controls -- it flags attacks against each surface, and for tool poisoning,
context poisoning, indirect injection, and output-pipeline filtering it is
squarely the detection tool. It does not implement the identity, cryptographic,
logging, or network-enforcement controls the CSI also requires.**

## Provenance

- CSI structure: NSA/CISA *MCP: Security Design Considerations*, May 2026 Ver.
  1.0 (U/OO/6030316-26). Section wording paraphrased from the primary CSI; the
  verbatim 8-concern / 9-recommendation structure is reproduced in
  [`docs/NSA-MCP-MAPPING.md`](../NSA-MCP-MAPPING.md).
- ATR rule ids: verified present in `rules/` at authoring time (2026-07-08).
  Category sizes read from the rule directories.
- License: ATR is MIT.
