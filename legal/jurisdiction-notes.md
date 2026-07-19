# ATR Jurisdiction Notes

> **STATUS: PRELIMINARY — NOT LEGAL ADVICE. NOT RATIFIED.** This document
> is a maintainer-authored survey of open legal questions to be resolved
> by qualified counsel. It is published for community comment, NOT as
> authoritative guidance. See `STANDARDIZATION-STATUS.md` at repo root
> for full status of standardization scaffolding.

**Version:** 1.0 — preliminary, not legal advice
**Date:** 2026-05-25
**License:** MIT

---

## Disclaimer

This document is preliminary jurisdiction analysis written by the project maintainer (not a lawyer) for the purpose of identifying open legal questions that the TSC + counsel should resolve. It is not legal advice. Adopters operating ATR in any jurisdiction MUST obtain their own legal review.

The TSC will commission qualified legal counsel review per `governance/CHARTER.md` § 4 Tier 4 vote before any sovereign deployment.

---

## Why this document exists

ATR is a detection-rule corpus that crosses jurisdictions in three ways:

1. **Project fiscal sponsor** is a US 501(c)(3) (Open Source Collective Inc.). This pulls some US legal context onto the project (US trademark law, US copyright law, US sanctions compliance).
2. **Adopters deploy ATR in multiple jurisdictions.** EU GDPR, UK DPA, China PIPL, Singapore PDPA, etc. each have requirements for what kind of detection processing is permitted.
3. **Sovereign sub-range mechanism** (per `governance/CHARTER.md` § 8.2) explicitly invites national authorities to issue rules. This creates direct standards-body-to-sovereign relationships that must respect each sovereign's legal context.

This document catalogues the open questions, not the answers.

---

## Question 1 — US sanctions and the sovereign sub-range mechanism

**Question:** If a US-fiscal-sponsored project (OSC) admits an Iranian or North Korean national authority into the sovereign sub-range mechanism, does this constitute a sanctions violation under OFAC?

**Working answer:** The project does not transfer any goods, services, or money to sovereign authorities. It accepts contributions under the same DCO terms as any contributor. Whether DCO acceptance from a sanctioned-country government entity is itself a regulated transaction is **not clear** and requires counsel review.

**Mitigation in current charter:** Sovereign sub-range admission requires TSC Tier 3 vote per `governance/CHARTER.md` § 8.2 → admission can be refused on legal grounds without statement of cause.

**Open work:** Pre-clear with US counsel before publishing the sovereign sub-range list. Identify which sovereign authorities can be admitted under current sanctions and which require specific OFAC license.

---

## Question 2 — EU GDPR and the conformance corpus

**Question:** The conformance corpus contains synthetic skill files and synthetic prompt-injection payloads. If any payload incidentally resembles real user data, does GDPR Article 4 (personal data definition) apply?

**Working answer:** No — synthetic data without real-person identifiers is not personal data under GDPR. But the conformance corpus contributors must affirm payload synthesis (not real-incident extraction) per the contribution process.

**Mitigation in current spec:** `spec/conformance/README.md` § Privacy + data residency requires all fixtures to be synthetic and MIT-licensed.

**Open work:** Update CLA / DCO sign-off to include affirmation that contributed fixtures are synthetic OR are anonymized derivatives of public-domain incident data.

---

## Question 3 — China PIPL + cross-border data transfer

**Question:** If a Chinese organisation runs an ATR engine that produces events containing user-context excerpts, does sending those events to a non-China deployment violate PIPL Article 38 (cross-border data transfer requirements)?

**Working answer:** The engine itself does not transfer events anywhere by default. The deployer's configuration determines where events are routed. PIPL compliance is the deployer's responsibility, not ATR's.

**Mitigation in current event spec:** `spec/atr-event-v1.0.md` § Required fields includes `tool.target_jurisdiction` and `atr.matched_value_redacted` (with redaction enabled by default). This minimises personal data in events emitted from an engine running in China.

**Open work:** Document recommended PIPL-compliant deployment patterns in `docs/PIPL-DEPLOYMENT-GUIDE.md` (post-Phase 5).

---

## Question 4 — UK DPA + GDPR-equivalent

**Question:** UK GDPR (post-Brexit) is largely equivalent to EU GDPR but the ICO has issued specific guidance (e.g., the May 2026 "Five Steps" piece by Ian Hulme) that frames AI security as an Article 32 obligation. Does adopting ATR satisfy Article 32 obligations?

**Working answer:** Adopting ATR detection at runtime can be one piece of an Article 32 "appropriate technical and organisational measures" satisfaction, but ATR alone is not a complete Article 32 control. Article 32 is principles-based; ATR is one measure that contributes to "robustness" but does not cover, e.g., encryption-at-rest, access controls, or staff training.

**Mitigation in current outreach:** Project outreach consistently frames ATR as one tool that contributes to Article 32 robustness, not a complete answer.

**Open work:** Build an explicit `docs/UK-GDPR-ARTICLE-32-MAPPING.md` aligning ATR rule categories to Article 32 principle subsections.

---

## Question 5 — EU AI Act Article 50 evidence chain

**Question:** Article 50 obligations (apply 2 August 2026) require deployer-side evidence of AI interaction disclosure. Are ATR events admissible as evidence in EU AI Act compliance investigation?

**Working answer:** Article 50 evidence has not yet been litigated. The signed, timestamped, OSCAL-mappable ATR event format (per `spec/atr-event-v1.0.md`) is designed to meet evidentiary standards (signature non-repudiation, time-ordering, machine-readable structure), but admissibility in any specific case is determined by the relevant authority and counsel.

**Mitigation in current spec:** Event format includes `evidence.signature` (ed25519), `evidence.observation_id` (UUID v7 time-ordered), and `@timestamp` (RFC 3339 UTC). These match the typical structured-evidence requirements.

**Open work:** Coordinate with the EU AI Office on whether ATR events satisfy Article 50 evidence requirements as currently drafted.

---

## Question 6 — Trademark + sovereign sub-range interaction

**Question:** When a sovereign authority (e.g., German BSI) issues `ATR-DE-2026-NNNNN` rules, do they need a trademark license from the project?

**Working answer:** No separate license needed. Per `legal/trademark-policy.md` § Sovereign sub-range trademark interaction:

> The sovereign authority's use of the ATR mark in this context is explicitly authorised as part of the sub-range admission process, provided [conformance + attestation + clear naming].

**Mitigation in current policy:** Sovereign sub-range admission is the license. No separate paperwork.

**Open work:** Document the standard sovereign authority MOU template that captures the admission terms.

---

## Question 7 — Patent assertion in jurisdictions with no patent non-assertion equivalent

**Question:** The patent non-assertion in `governance/CHARTER.md` § 7.4 is enforceable in jurisdictions that recognise OASIS-style covenants. In jurisdictions without that doctrine (e.g., some emerging-market jurisdictions), is the non-assertion meaningful?

**Working answer:** OASIS Non-Assertion is contractual; it binds the contributor regardless of where they later sue. Enforcement requires litigating in a jurisdiction with covenant-honoring law, which is typically achievable since contributors are mostly in US / EU / common-law jurisdictions.

**Mitigation in current charter:** Charter explicitly cites OASIS Non-Assertion as the model. Choice-of-law clause in any future contract templates should specify a covenant-honoring jurisdiction.

**Open work:** Add explicit choice-of-law clause to the CCLA template (for organisations that need one) and to the audit lab accreditation agreement.

---

## Question 8 — Liability for false positives causing customer harm

**Question:** If an ATR rule produces a false positive that causes a downstream customer to take an action with material business cost (e.g., blocking a legitimate user, false fraud accusation), who is liable?

**Working answer:** The deploying organisation is liable for its own actions based on its detection stack. ATR's licence (MIT) explicitly disclaims liability ("AS IS, WITHOUT WARRANTY OF ANY KIND"). The contribution licence does not transfer liability to contributors or the project.

**Mitigation in current licence + Charter:** the MIT licence covers all ATR artifacts (code, rules, spec). It includes the standard "without warranty" disclaimer.

**Open work:** None — this is settled by standard open-source licence terms. But for ATR-Certified™ Enterprise, the audit lab + vendor contract should explicitly handle this; document in `certification/audit-template.md` (Phase 4).

---

## Question 9 — Conformance corpus + DMCA / takedown notices

**Question:** If a third party claims the conformance corpus contains content that infringes their copyright (e.g., a real-world incident payload they want removed), can they DMCA the project?

**Working answer:** They can issue a DMCA notice to GitHub. GitHub typically forwards to the project. The project would evaluate and respond.

**Mitigation in current corpus design:** All fixtures are MIT-licensed / synthetic per `spec/conformance/README.md`. Real-world incident payloads are only included where the source incident is already public (e.g., disclosed CVE proof-of-concept).

**Open work:** Document the takedown response procedure in `legal/takedown-response.md` (post-Phase 5).

---

## What this document deliberately does NOT do

- Does NOT provide legal advice for any specific deployment.
- Does NOT enumerate every jurisdiction. Lists notable / high-impact jurisdictions where ATR has explicit engagement (US, EU, UK, China, Singapore, Germany, India, Saudi Arabia, Taiwan).
- Does NOT pre-clear specific actions. Each question's "Open work" identifies what needs counsel review before action.

---

## Next steps

The TSC, upon ratification, should:

1. Engage qualified counsel to review each open question above.
2. Publish the counsel's written opinions in `legal/counsel-opinions/<year>/<topic>.md`.
3. Update this document with answers (and revision history).
4. Annually re-review as the legal landscape evolves (especially EU AI Act enforcement which begins August 2026).

---

## References

- `governance/CHARTER.md` § 7 (IPR), § 8 (sovereign sub-ranges)
- `legal/CLA.md` (DCO)
- `legal/trademark-policy.md`
- `spec/atr-event-v1.0.md` § Required fields (evidence chain)
