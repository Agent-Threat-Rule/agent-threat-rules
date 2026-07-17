# ATR Trademark Policy

> **STATUS: PROPOSED v1.0 — NOT YET RATIFIED. MARKS NOT YET REGISTERED.**
> The trademark policy described here is the proposed framework. **The
> ATR® and ATR-Certified™ marks are NOT currently registered with any
> trademark office.** OSC (the fiscal sponsor) has not yet filed
> registration. Anyone using these marks does so at their own risk until
> registration completes. The policy is published in advance of registration
> so that adopters can review the proposed permitted/prohibited use
> framework. See `STANDARDIZATION-STATUS.md` at repo root for full status.

**Version:** 1.0
**Effective (proposed):** Bootstrapping under current Numbering Authority; ratified at TSC seating per `governance/CHARTER.md` § 11.
**Marks claimed (registration pending):** ATR, ATR-Certified, and the ATR project logo (when published)
**Owner (on registration):** Open Source Collective Inc. (fiscal sponsor) on behalf of the Agent Threat Rules project
**License of this document:** MIT

---

## Why this policy exists

Trademarks are how the standard's integrity is enforced when other instruments (copyright, patent, contract) cannot reach. Specifically:

- A bad actor can fork the MIT-licensed rule corpus and specification. Copyright cannot stop that fork.
- A bad actor can claim "ATR-conformant" without passing the conformance corpus. The conformance corpus cannot stop that claim absent trademark enforcement.
- A bad actor can publish a competing "Agent Threat Rules Foundation" that looks legitimate. Without trademark protection on the project name, downstream consumers cannot tell which is canonical.

This policy defines what uses of ATR®, ATR-Certified™, and related marks are permitted; what uses require explicit authorisation; and what uses are prohibited.

---

## Marks covered

**ATR®** — registered trademark for the Agent Threat Rules project. Filed at the United States Patent and Trademark Office in 2026; registration in process. Used in commerce since 2026-03 (per `governance/CHARTER.md` § 7.3).

**ATR-Certified™** — trademark for the certification program (per `certification/program-guide.md`). Awarded to products and skills that pass the formal conformance and audit process.

**ATR project logo** (when published) — registered design mark, same owner.

---

## Permitted uses (no authorisation needed)

You MAY freely use ATR® and the project name to:

- **Reference the project in good faith.** "Our product detects threats using ATR rules." "The ATR project is at github.com/Agent-Threat-Rule/agent-threat-rules." "We contributed rules to ATR."
- **Cite specific rule IDs.** "Our scanner flagged ATR-2026-00525 on this skill."
- **Write academic publications about ATR.** Authors retain full editorial freedom; no review or approval required.
- **Write critical reviews / commentary on ATR.** Free speech, commentary, criticism, satire — all permitted under fair use of the mark.
- **Describe your product as "built on ATR" or "based on ATR"** when this is factually true (you use the published rule corpus or implement the published spec).
- **Display the ATR project logo in documentation, blog posts, conference slides** when referring to the project. Logo must not be modified.

---

## Permitted with attribution

You MAY use the mark in commercial product names, descriptions, or marketing IF you also:

1. Make it clear your product is NOT the ATR project itself or operated by ATR. Example: "AcmeScan uses ATR rules for detection" is fine; "AcmeScan is the ATR Foundation" is not.
2. Do not imply official endorsement by the ATR project, the TSC, the Open Source Collective Inc., or any TSC member organisation unless that endorsement is explicit and current.
3. Link to https://github.com/Agent-Threat-Rule/agent-threat-rules as the canonical project source.

---

## Permitted only via the certification program

The mark **ATR-Certified™** may be used only as awarded through the `certification/` program (Phase 4 deliverable):

- **ATR-Certified™ Skill** — awarded to a specific SKILL.md or MCP server that passes the L1 conformance scan with zero critical findings. Free, community-issued, 90-day validity.
- **ATR-Certified™ Enterprise** — awarded to a specific product release line that passes an independent audit by an accredited audit lab per `certification/audit-template.md`. Paid program with annual re-attestation.

Use of "ATR-Certified" or "ATR Certified" without an active certification from the program is **trademark infringement** and grounds for enforcement.

---

## Prohibited uses

You may NOT:

- **Claim to operate the ATR project.** Only the TSC (per `governance/CHARTER.md` § 3) is authorised to make official statements on behalf of the project.
- **Form lookalike organisations.** Names like "Agent Threat Rules Foundation," "ATR Standards Authority," "ATR Foundation," "OpenATR," "ATR International," etc., are prohibited unless explicitly authorised by the TSC.
- **Register lookalike domains** suggesting affiliation: `atr-foundation.org`, `agent-threat-rules.org` (unless authorised), `atrcertified.com` (unless via the certification program), etc. Domain squatting will be challenged via UDRP / cybersquatting enforcement.
- **Modify the ATR project logo** or use it in ways that suggest endorsement of unrelated products.
- **Use ATR-Certified™** without an active, current certification from the program.
- **Claim conformance** without passing the published conformance corpus (separate from the ATR-Certified™ program — passing the corpus is the technical floor; the program adds audit + recurring attestation).
- **Use the marks in a way that brings the ATR project into disrepute,** including but not limited to associating ATR with harmful products, illegal activity, or content that misrepresents the project's positions or actions.

---

## Sovereign sub-range trademark interaction

Per `governance/CHARTER.md` § 8.2, sovereign authorities (national CERTs, etc.) may issue rules in country-prefixed sub-ranges (`ATR-DE-`, `ATR-SG-`, etc.). The sovereign authority's use of the ATR mark in this context is **explicitly authorised** as part of the sub-range admission process, provided:

- The authority's rules pass the same conformance gate as canonical rules.
- The authority publishes its attestation key and signs its rules per § 8.2.
- The authority's published guidance is clear that "ATR-DE-* rules issued by Germany's BSI" is distinct from "the canonical ATR project."

No additional trademark licence is required for sovereign sub-range use.

---

## Enforcement procedure

When the project becomes aware of a use that violates this policy:

1. **First notice (informal).** A member of the TSC or its designated trademark counsel contacts the user, explains the policy, and asks for the use to be brought into compliance. Most cases resolve here.
2. **Cease-and-desist (formal).** If informal notice fails, a written cease-and-desist is sent. Standard 30-day cure period.
3. **Domain enforcement.** For lookalike domains, UDRP filings via WIPO are used. Cost is borne by Open Source Collective Inc. as fiscal sponsor and trademark owner.
4. **Litigation (last resort).** Only for material confusion-in-trade that survives notice. Decision made by TSC Tier 3 vote per `governance/CHARTER.md` § 4.

The project will not enforce against fair-use, academic, journalistic, or critical-commentary uses regardless of perceived hostility.

---

## How to request specific authorisation

For uses not clearly permitted above, contact:
- `tsc@agentthreatrule.org` (post-ratification mailing list)
- `adam@agentthreatrule.org` (current Numbering Authority)
- Open Source Collective Inc. trademark liaison (per OSC standard procedures)

Typical authorisation request format:
- Who you are (organisation, role, contact)
- What use you propose (specific text, image, domain, product name)
- Why this is in the project's interest
- Confirmation that you will not imply endorsement

The TSC's typical response time is 14 days. Authorisations are public and recorded in `legal/trademark-authorisations/`.

---

## References

- USPTO trademark filings: search for "Agent Threat Rules" at uspto.gov
- WIPO UDRP procedure: https://www.wipo.int/amc/en/domains/
- Open Source Collective Inc. (fiscal sponsor): https://opencollective.com/opensource
- `governance/CHARTER.md` § 7.3 (trademark commitment)
- `governance/STANDARD-THREAT-MODEL.md` § Attacker class 2 (namespace squatter)
