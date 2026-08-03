# ATR Standardization Status

**Last updated:** 2026-05-25
**Read this if you saw new `governance/`, `spec/atr-*.md`, `legal/`,
`certification/`, or `engines/` directories and want to know what changed.**

---

## 30-second answer

ATR is adding a formal standards-layer alongside its existing rule corpus
and TypeScript engine. The new layer is **proposal-stage**, NOT operating
governance. It exists so that OASIS, NIST CAISI, IETF, and ecosystem
partners can review what the standard will look like before it is ratified.

**Nothing about how you integrate with ATR has changed.** If your project
consumes the rule YAML files, the `atr-schema.yaml` rule format, the
TypeScript engine API, or the `agent-threat-rules` npm package, **none
of those interfaces have changed**. Continue as before.

---

## Status matrix

| Layer | Artifact | Status | What this means for you |
|---|---|---|---|
| **Rule corpus** | `rules/*` (427 rules) | **STABLE — IN PRODUCTION** | Unchanged. Continues to be the canonical source. |
| **Rule format** | `spec/atr-schema.yaml` | **STABLE — IN PRODUCTION** | Unchanged. Rule YAML files still parse against this. |
| **TS production engine** | `src/`, npm `agent-threat-rules` v2.1.3 | **STABLE — IN PRODUCTION** | Unchanged. No API breakage. |
| **Existing ecosystem integrations** | Microsoft AGT, Cisco AI Defense, MISP CIRCL, OWASP A-S-R-H, precize, Sage, OpenHands, garak (in review) | **UNAFFECTED** | All continue to work without modification. |
| **Existing governance** | `BDFL-charter.md`, `GOVERNANCE.md` v1.1 | **STABLE — CURRENT OPERATING MODEL** | Still the governance in effect. v2.0 charter is proposed but not ratified. |
| **Existing threat model** | `THREAT-MODEL.md` | **STABLE — CURRENT** | Operational threat model (what ATR rules detect). Unchanged. |
| **New governance proposal** | `governance/CHARTER.md` v2.0 | **PROPOSED — NOT RATIFIED** | A proposal for community comment. The 9-seat TSC does NOT yet exist. No seats filled. No elections held. |
| **New standard threat model** | `governance/STANDARD-THREAT-MODEL.md` | **PROPOSED** | Companion to CHARTER.md proposal. Describes attacks against the standard itself. |
| **New event format spec** | `spec/atr-event-v1.0.md` | **PROPOSED** | Target event format. **Current engine does NOT yet emit this format.** Do not migrate your SIEM ingestion yet. |
| **New language detection spec** | `spec/atr-language-detection-v1.0.md` | **PROPOSED** | Target algorithm. Current engine uses existing per-rule logic. |
| **New profile spec** | `spec/atr-profile-v1.0.md` | **PROPOSED** | Target profile format. No formal profile resolver shipping yet. |
| **New correlation spec** | `spec/atr-correlation-v1.0.md` | **PROPOSED** | Target multi-event format. No correlation rules in the canonical corpus yet. Its join keys are defined by the observation spec below, which is also unratified — correlation is not evaluable until both land. |
| **New observation spec** | `spec/atr-observation-v1.0.md` | **PROPOSED** | Target *input* format (the engine's existing `AgentEvent` shape is unchanged). Defines the correlation join keys, an `outcome` enum that is not collapsible to a boolean, and a machine-readable coverage declaration. Current engine does NOT ingest this format. |
| **New category registry** | `spec/category-registry/v1.0.yaml` | **PROPOSED** | Documents the 10 categories currently used + reserved namespaces for the future. |
| **JSON Schemas** | `spec/schema/*.json` | **PROPOSED** | Validation schemas matching the proposed spec prose. |
| **Conformance corpus** | `spec/conformance/` | **PROPOSED — SCAFFOLDING ONLY** | Structure documented; actual fixture files not yet populated. No engine currently claims formal conformance. |
| **DCO requirement** | `legal/CLA.md` | **PROPOSED — NOT ENFORCED** | Existing contributors do NOT need to backfill `Signed-off-by:` lines. Current v1.1 model still applies. |
| **Trademark policy** | `legal/trademark-policy.md` | **PROPOSED — MARKS NOT REGISTERED** | ATR® and ATR-Certified™ marks are NOT yet registered with any trademark office. Policy framework is published for review. |
| **Jurisdiction notes** | `legal/jurisdiction-notes.md` | **PRELIMINARY — NOT LEGAL ADVICE** | Maintainer-authored survey of open questions for counsel. |
| **ATR-Certified™ program** | `certification/program-guide.md` | **PROPOSED — NO CERTIFIED PRODUCTS** | Trust mark program in proposal stage. No third-party audit lab engaged. Do not use the mark in collateral yet. |
| **Reference impl: Python** | `engines/python/` | **SKELETON + INTERFACE CONTRACT** | Documents the interface a Python ATR engine MUST satisfy. No production Python engine ships yet. |
| **Reference impl: Go** | `engines/go/` | **SKELETON + INTERFACE CONTRACT** | Same. |
| **Reference impl: TypeScript** | `engines/typescript/` | **SKELETON — interface contract being backfilled** | The existing `src/` engine IS the de-facto TS reference. Formal interface contract is being written so all three languages have the same shape of documentation. |

---

## Why this scaffolding was added now

Three external pressures converged in 2026-Q2:

1. **OASIS Open Project submission opportunity.** OASIS is the natural
   venue for ATR (precedent: SAML, KMIP, OData). Their proposal template
   requires governance + threat model + spec + IPR + conformance documented
   up front. Phases 0-5 of this work produced those documents.

2. **NIST CAISI dialogue (OSCAL Path 1).** Open since 2026-05-10. CAISI's
   feedback consistently asked for a formal spec layer rather than just
   the rule corpus. Phase 1-3 of this work answers that ask.

3. **F500 procurement questionnaires.** Microsoft AGT integration matured
   to the point that F500 procurement teams started asking "what does
   the governance look like, what does the conformance test look like,
   what does the audit evidence look like?" — questions that a 427-rule
   YAML corpus alone cannot answer.

The work was done as **proposal scaffolding** because:

- We cannot ratify a 9-seat TSC without first proposing it and giving
  the community + ecosystem partners + sovereign authorities time to
  review.
- We cannot register trademarks until OSC (fiscal sponsor) approves
  the filing.
- We cannot launch ATR-Certified™ until an audit lab is engaged.
- We cannot claim engine conformance until the conformance corpus
  fixtures are populated and a signed reference result published.

So everything is published as PROPOSED, with the existing v1.1
governance + production engine continuing to operate during the
community comment window.

---

## What this means for your specific situation

### If you maintain an ecosystem integration of ATR

**Microsoft AGT, Cisco AI Defense, MISP CIRCL, OWASP A-S-R-H, precize,
Sage, OpenHands, garak (in review), and others:**

- Your integration continues to work. Do nothing.
- If you want to weigh in on the proposed governance, see
  `governance/CHARTER.md`. The TSC currently includes 2 vendor seats
  (out of 9). Vendor seat candidates will be solicited only after OASIS
  Project approval; until then, the proposal is open for comment.
- If you want to be notified when v2.0 ratifies, watch this file or
  GitHub releases — we will not silently change integration interfaces.

### If you ship a product that uses ATR rules

- Your product continues to work. Do nothing.
- When the spec layer ratifies, you will be invited to formally claim
  conformance (and optionally pursue ATR-Certified™ Skill / Enterprise).
  Until then, "uses ATR rules" remains the correct description.
- Do NOT use "ATR-Certified™" in product collateral yet. The trust mark
  program is not launched.

### If you are a national authority / sovereign CERT

- The proposed sovereign sub-range mechanism (`ATR-XX-YYYY-NNNNN`) is
  documented in `spec/atr-event-v1.0.md` and `governance/CHARTER.md` §8.2.
- The proposed sovereign liaison seats (2 of 9 TSC) are described in
  `governance/CHARTER.md` §3.2.
- Both are PROPOSED. Formal invitations to specific sovereign authorities
  will be issued only after OASIS Project approval.
- If you want to participate in the proposal review, contact
  adam@agentthreatrule.org.

### If you are a regulator (NIST, EU AI Office, UK ICO, etc.)

- The proposed mapping documents (NIST AI RMF Measure 2.x, EU AI Act
  Art 50, ISO 42001 Annex A.6.2.4) are referenced from
  `spec/atr-profile-v1.0.md`.
- No formal regulatory mapping is claimed yet; the mapping is in
  proposal stage pending TSC ratification.
- A NIST CAISI position paper has been prepared for submission
  via OSCAL Path 1.

### If you are a researcher / red team contributor

- Your contributions continue under the current model. The proposed
  DCO (`legal/CLA.md`) is NOT enforced. You do not need `Signed-off-by:`
  lines on past commits.
- If you want to weigh in on the proposed governance, see
  `governance/CHARTER.md`. Contributor seats (3 of 9 TSC) will be
  elected by qualifying contributors once the TSC is seated.

---

## What happens next

### 2026-05-25 — 2026-06-25 (30-day community comment window)

- Scaffolding published as PROPOSED in this repo.
- Ecosystem partner notification email sent to merged-integration
  maintainers (Microsoft AGT, Cisco, MISP, OWASP A-S-R-H, precize, Sage).
- Issues / PRs welcome at github.com/Agent-Threat-Rule/agent-threat-rules.

### 2026-06-21+

- NIST CAISI position paper submitted via OSCAL Path 1.

### 2026-Q3

- OASIS Open Project proposal submitted (after community comment
  feedback incorporated).
- IETF Internet-Draft submitted (separate workstream).

### 2026-Q4 (target)

- OASIS hosting approved (if approved).
- First TSC election held.
- v2.0 charter formally ratified.
- Trademark registration filed.
- ATR-Certified™ program launched with first audit lab partnership.

### 2027-Q1 (target)

- First sovereign sub-range issued.
- First ATR-Certified™ Enterprise product certified.
- First conformance corpus fixture release.

This timeline is aspirational. Standards work is slow by design. If any
milestone slips, this file will be updated.

---

## Questions or concerns

- **Open an issue:** github.com/Agent-Threat-Rule/agent-threat-rules/issues
  — label `standardization`.
- **Email the maintainer:** adam@agentthreatrule.org
- **For ecosystem-partner-specific concerns:** mention `@Agent-Threat-Rule`
  in your own integration's issue tracker; we monitor.

---

## What this file is NOT

- It is **not** a press release.
- It is **not** a claim that ATR is now an OASIS / NIST / IETF / ISO
  standard. None of those organisations have approved hosting yet.
- It is **not** authorisation to use the ATR® or ATR-Certified™ marks.
- It is **not** legal advice.
- It is **not** a binding commitment to any specific ratification date.

It is a status document for transparency.
