# ATR Technical Steering Committee Charter

> **STATUS: PROPOSED v2.0 — NOT YET RATIFIED**
>
> This document is a **proposal for community comment**, not the operating
> governance of ATR as of this date. The Technical Steering Committee (TSC)
> described here has **not yet been formed**. No seats have been filled. No
> elections have been held. ATR is currently operated under the BDFL model
> in `BDFL-charter.md` and `GOVERNANCE.md` v1.1.
>
> **No integration interface has changed.** The 427-rule corpus, `atr-schema.yaml`
> rule format, TypeScript production engine API, and npm package v2.1.3 are
> all unchanged. Existing ecosystem integrations (Microsoft AGT, Cisco AI
> Defense, MISP CIRCL, OWASP A-S-R-H, precize, Sage) continue to work
> unmodified.
>
> Ratification path: (1) 30-day public comment period, (2) ecosystem partner
> review, (3) OASIS Open Project submission, (4) first TSC election held
> only after OASIS hosting approval. Expected: not before 2026-Q4.
>
> See `STANDARDIZATION-STATUS.md` at repo root for the full status of all
> standardization scaffolding.

**Version:** 2.0 (proposed)
**Status:** Draft for community comment — NOT RATIFIED
**Effective on ratification:** [TBD — see § Ratification]
**Supersedes (on ratification):** GOVERNANCE.md v1.1 (2026-04-15, BDFL/Numbering-Authority model)
**Charter license:** MIT
**Author:** Adam Lin <adam@agentthreatrule.org>, Maintainer, Agent Threat Rules
**Date drafted:** 2026-05-25

---

## 1. Purpose

This charter defines the technical governance of the Agent Threat Rules (ATR)
project. ATR is the open detection-rule standard for AI agent threats,
maintained at github.com/Agent-Threat-Rule/agent-threat-rules under the MIT
license (code, tooling, rule content, and this charter — a single license
throughout). Fiscal sponsor: Open Source Collective Inc. (EIN 81-1567737).

This charter exists because the ATR rule corpus has reached the adoption
threshold where single-maintainer governance is a structural risk to
adopters: Microsoft Agent Governance Toolkit, Cisco AI Defense, MISP CIRCL,
precize / Gen Digital Sage chain all ship ATR rules into production. F500
buyers, national CERTs, and OASIS / NIST / EU AI Office cannot reliably
build dependencies on a BDFL.

Governance is therefore moving from a single Numbering Authority (the
v1.1 model) to a 9-seat Technical Steering Committee (the v2.0 model
defined below), in line with how every successful security-detection
standard has made the same transition (CVE → MITRE FFRDC; STIX/TAXII →
OASIS CTI TC; C2PA → Linux Foundation JDF; CNCF projects → TOC).

---

## 2. Scope of governance

The TSC governs:

- The ATR rule corpus (`rules/`) — additions, removals, deprecations,
  category taxonomy.
- The ATR specification (`spec/atr-schema.yaml`, future
  `spec/atr-spec-v1.0.md`, `spec/schema/*.json`).
- The conformance test corpus (`spec/conformance/`) and the published
  expected-results signed reference.
- The Numbering Authority — assignment of `ATR-YYYY-NNNNN` IDs and any
  sovereign sub-ranges (see § 8).
- The ATR-Certified™ program (see § 9).
- Reference implementations in this repository (`engines/typescript/`,
  `engines/python/`, `engines/go/`).
- This charter, including amendments.

The TSC does NOT govern:

- Commercial products built on top of ATR (e.g., Panguard AI Inc.'s
  Enterprise tier). Commercial offerings are governed by their respective
  vendors. The TSC's role is to ensure the standard remains vendor-neutral.
- Operational delivery of the cloud-hosted Threat Cloud (TC) instance run
  by Panguard AI Inc. TC's *protocol* for syncing rules back to the open
  corpus is in scope; TC's hosting, SLAs, and pricing are not.
- Individual contributors' employment, compensation, or fiscal-sponsor
  relationships beyond the conflict-of-interest disclosure in § 6.

---

## 3. TSC composition (9 seats)

The TSC has nine seats with explicit constituency allocation. This design
follows CNCF's odd-numbered hard-capped pattern (proven across five years
of cross-vendor governance) while adding two seats reserved for sovereign
/ standards-body liaisons — ATR's structural differentiator from the
AAIF Technical Committee, which has zero non-US-hyperscaler
representation as of May 2026.

| Seat class | Count | Elected by | Term | Renewable |
|---|---|---|---|---|
| **Contributor seat** | 3 | Any individual with ≥10 merged rules in the trailing 12 months may vote and run | 2 years, staggered (one election per year) | Yes |
| **Vendor seat** | 2 | Companies adopting ATR in production products. One vote per company group | 2 years | Yes |
| **Sovereign / standards-body liaison** | 2 | TSC nominates; nominees must be authorised by their employing body (NIST CAISI, EU AI Office, JP AISI, UK AISI / NCSC, Singapore IMDA, German BSI, Saudi NCA, Taiwan NAIO, etc.) | 1 year, renewable indefinitely while liaison's body confirms | Yes |
| **Academic seat** | 1 | AI safety / security researchers with ≥3 peer-reviewed publications relevant to AI agent security in the past 5 years | 2 years | Yes |
| **End user / civil-society seat** | 1 | CISOs of organisations using ATR in production OR recognised civil-society organisations (Mozilla, EFF, Center for AI Safety, AI Now, similar) | 2 years | Yes |

### 3.1 Single-company cap (CNCF model)

No more than **two** TSC seats at any time may be held by employees of the
same company or its Related Companies (parent, subsidiary, sibling under
common control). The cap applies across all seat classes.

If a vote, hire, or acquisition would cause a company to exceed the cap,
the parties involved have 30 days to decide which seat is vacated. If no
decision is reached within 30 days, the seat to vacate is determined by
random lot drawn by the Chair in a publicly observable manner (mirroring
CNCF Charter § 6(b)(iv)).

This cap is the single most important structural protection in this
charter. It prevents the gradual capture pattern that has compromised
every standards body lacking it.

### 3.2 Diversity targets (soft, reported, not enforced)

Reported quarterly by the Chair as transparency metrics:

- Target: ≥3 geographies represented across the TSC at any time, with no
  single region (Americas / EMEA / APAC) holding >5 of 9 seats.
- Target: ≥2 of 9 seats from non-vendor backgrounds (academic + civil
  society combined).

These are reporting metrics, not enforced quotas. Hard demographic
quotas trigger legal risk in several jurisdictions and historically lead
to box-checking rather than genuine diversity. The transparency itself
is the corrective mechanism.

### 3.3 Vacant seats and quorum

A seat is **vacant** when (a) the elected holder resigns, dies, or
becomes incapacitated; (b) the holder is removed under Tier 5; (c) a
liaison's employing body withdraws authorisation; (d) the seat is
unfilled at TSC seating because no qualifying candidate stood for
election; or (e) the holder's term expires without re-election.

The TSC's working **quorum** is the larger of (i) 5 of the filled seats
or (ii) a simple majority of the filled seats. Vacant seats do not
count toward quorum and do not count toward any supermajority
denominator. This prevents one or two strategic resignations from
blocking all governance.

A vacant seat MUST be filled within **180 days** by the same election
or nomination procedure that would have filled it on schedule. The
Chair MUST publish a call for candidates within 30 days of the seat
becoming vacant, with the candidate window closing no earlier than
60 days after the call.

If a seat is vacant for more than **90 days**, the Chair MAY appoint an
**interim observer** drawn from the qualifying electorate for that
seat class (e.g., for a vacant academic seat, any qualifying academic
the Chair selects). The interim observer:

- May attend TSC meetings and participate in discussion.
- Does NOT vote, including on tiers 1-5.
- Does NOT count toward quorum.
- Is replaced automatically when the seat is filled by election.
- May stand for election to fill the seat.

The interim observer mechanism exists so that the perspective of a
seat's constituency is not absent from deliberation during the vacancy,
without granting un-elected voting power.

A **liaison seat** (sovereign / standards-body) that has been vacant
for more than 180 days because no sovereign authority has accepted the
liaison invitation MAY be temporarily reallocated to the next-highest-
priority constituency on a Tier 4 supermajority vote, with the
reallocation expiring 12 months later (the seat reverts to liaison
class at that point unless renewed by another Tier 4 vote). This is a
safety valve only; the design assumption is that liaison seats will
be filled, and reallocation should be the exception.

---

## 4. Voting and decision tiers

Decisions are tiered by their reversibility and blast radius. Lower
tiers maintain rule-corpus velocity (which is ATR's competitive
advantage versus heavyweight standards); higher tiers protect the spec
from capture or unforced error.

### Tier 1 — Rule additions, deprecations, severity changes

- **Procedure:** Lazy consensus on the PR. Two TSC approvals + 72-hour
  wait + no unaddressed TSC objection = merge.
- **Quorum:** None (lazy consensus).
- **Tempo:** Hours to days. Matches SigmaHQ's contribution velocity that
  built a 3,000-rule corpus over eight years.
- **Override:** Any single TSC member can demote a Tier 1 decision to
  Tier 2 by raising a substantive objection within the 72-hour window.

### Tier 2 — Rule semantics changes, category renames, schema field additions (backward-compatible)

- **Procedure:** Simple majority of TSC members present at a biweekly
  TSC call.
- **Quorum:** 5 of 9.
- **Notice:** 7 days on a public GitHub Issue with the `tier-2-vote` label.
- **Tempo:** 1-2 weeks.

### Tier 3 — Schema breaking changes, new top-level rule category, new conformance-required field, ATR-Certified™ program changes

- **Procedure:** ATR Enhancement Proposal (AEP) per § 5 + supermajority
  vote.
- **Quorum:** 7 of 9.
- **Threshold:** 6 of 9 (2/3 supermajority).
- **Notice:** 15-day public comment window on the AEP.
- **Tempo:** 4-8 weeks.

### Tier 4 — Charter amendments, TSC seat allocation changes, Numbering Authority transfer, fiscal sponsor change

- **Procedure:** ATR Charter Change (ACC) per § 5 + supermajority vote +
  fiscal sponsor ratification.
- **Quorum:** 8 of 9.
- **Threshold:** 7 of 9 (3/4 supermajority).
- **Notice:** 30-day public comment window. Ratification by Open Source
  Collective Inc. as fiscal sponsor.
- **Tempo:** 6-12 weeks.

### Tier 5 — TSC member removal

- **Procedure:** 2/3 vote of the remaining TSC members.
- **Grounds:** Repeated COI violation, charter violation, prolonged
  inactivity (defined as missing 4 consecutive TSC calls without
  authorised leave), or material breach of the Code of Conduct.
- **Notice:** 14-day notice to the member with right of written reply
  published with the vote record.

---

## 5. RFC process

Three proposal classes, each maps to a decision tier above.

| Class | Acronym | Tier | Form |
|---|---|---|---|
| ATR Rule Proposal | ARP | 1 | GitHub PR adding or modifying a rule file under `rules/` |
| ATR Enhancement Proposal | AEP | 3 | Markdown document in `rfc/AEP-NNNN-<title>.md` |
| ATR Charter Change | ACC | 4 | Markdown document in `rfc/ACC-NNNN-<title>.md` |

### 5.1 ARP (rule-level)

Submit as a PR with:
- Rule YAML file
- True-positive and true-negative test cases inside the rule's
  `test_cases` block
- Benchmark evidence (precision and recall) where applicable
- OWASP Agentic / MITRE ATLAS / Five Eyes mapping in `references` block

CI gates:
- `check-rules-safety.ts` (own-TP-match + 0 FP on benign corpus + 0 FP
  on research-mentions corpus + no cross-rule conflict)
- Schema validation against `spec/atr-schema.yaml`

Merge path: lazy consensus per Tier 1.

### 5.2 AEP (spec-level)

Required for any change that affects what an implementer must do to
remain ATR-conformant. Examples:
- New required field in the rule schema
- New `operator` keyword (beyond regex / ml_classifier / ast / bytecode)
- New top-level `category` in the registry
- Conformance test addition that any engine must pass
- New target field (beyond `user_input`, `agent_output`, `tool_call`,
  `skill_content`, etc.)

Template at `rfc/TEMPLATE-AEP.md`. Sections required: problem statement,
proposed change, impact on conformant implementations, migration path,
security considerations, prior art.

Merge path: 15-day comment + Tier 3 vote.

### 5.3 ACC (charter-level)

Required for any change to this document, to TSC seat allocation, to
the Numbering Authority structure, to fiscal sponsorship, or to the
license commitment.

Template at `rfc/TEMPLATE-ACC.md`. Same sections as AEP plus
"alternatives considered" and "constituencies consulted".

Merge path: 30-day public comment + Tier 4 vote + Open Source Collective
ratification.

### 5.4 RFC numbering

ARPs are implicit — the rule's `ATR-YYYY-NNNNN` ID is the proposal ID
after merge. AEPs and ACCs are numbered sequentially per year:
`AEP-2026-001`, `AEP-2026-002`, …

---

## 6. Conflict of interest

Mandatory recusal on:

1. Rules that detect attacks against products the member's employer
   ships. The member may participate in technical review (regex
   correctness, FP rate) but must abstain from approval votes.
2. Rule responses to incidents that materially involve the member's
   employer.
3. Proposals that would advantage or disadvantage standards bodies
   the member co-chairs or has a fiduciary role in.

### 6.1 Annual disclosure

Every TSC member publishes an annual COI disclosure in
`governance/disclosures/<year>/<member>.md`, listing:
- Current employer and role
- Board / advisor positions in security-relevant organisations
- Material financial interest in any company that builds ATR-based
  products
- Standards-body chairs / vice-chairs held

Disclosures are due 31 January each year, and within 30 days of any
material change. The Chair audits disclosure freshness quarterly.

### 6.2 Founder COI

Adam Lin (founder, original Numbering Authority, founder of Panguard AI
Inc. which builds commercial products on top of ATR) holds an
explicit, declared COI. Recusal:

- Adam will NOT hold a TSC seat after the initial 12 months following
  v2.0 ratification, even if elected. The 12-month transition seat
  exists solely to chair the transition and is non-renewable.
- During the transition seat, Adam recuses from all votes touching
  Panguard AI Inc.'s commercial offerings, including ATR-Certified™
  program structure (which the Enterprise tier sells against),
  Numbering Authority changes that would alter Panguard's reference
  status, and any rule whose target is a Panguard product.

This is documented to set the precedent for any future founder-vendor
dual-role.

---

## 7. Intellectual property

### 7.1 License commitment (carried forward from v1.1, hardened)

- All ATR artifacts — code, tooling, reference implementations, the
  conformance test harness and corpus, rule content (the YAML files in
  `rules/`), and specification documents (this charter, the spec files,
  `spec/atr-schema.yaml`, `governance/*`): **MIT License**. Permanent and
  irrevocable. ATR uses a single license across the whole project so that
  adopters, audit labs, and sovereign authorities face one clear, permissive
  set of terms with no per-path friction.

ATR will never adopt BSL, SSPL, or any source-available licence that
restricts use. Re-affirmed at v2.0 ratification.

### 7.2 Contributor sign-off — DCO, not CLA

All contributions require a Developer Certificate of Origin sign-off
(`Signed-off-by: Name <email>` in the commit message) per the Linux
kernel model. No CLA is required. Contributor surveys at SigmaHQ,
OWASP, and the Linux Foundation consistently identify CLA requirements
as the largest single source of contributor friction; ATR's contributor
base (red-team researchers + detection engineers + sovereign-CERT
analysts) is precisely the demographic most CLA-averse.

### 7.3 Trademarks

ATR®, ATR-Certified™, and the ATR mark are owned by the project
through its fiscal sponsor (Open Source Collective Inc.). The TSC
delegates day-to-day enforcement to the trademark policy in
`legal/trademark-policy.md`, which permits non-commercial reference,
"based on ATR" attribution, and disallows passing-off.

### 7.4 Patent non-assertion

By contributing under DCO, contributors covenant not to assert
Essential Claims against conformant implementations of the ATR
specification. This mirrors OASIS Non-Assertion Mode and is the
permissive default. Contributors retain the right to assert against
non-conformant implementations.

---

## 8. Numbering Authority and sovereign ID ranges

### 8.1 Canonical authority

The ATR Numbering Authority assigns and curates `ATR-YYYY-NNNNN`
identifiers. At v2.0 ratification, the Authority is the TSC acting
collectively, with day-to-day issuance delegated to two or more named
Authority operators appointed by the TSC.

### 8.2 Sovereign sub-ranges

Sovereign governments and national CERTs may, upon application to the
TSC, receive a contiguous sub-range under a country-code prefix:
`ATR-<ISO-3166-alpha-2>-<YYYY>-<NNNNN>`. Examples:

- `ATR-DE-2026-00001` — German BSI-issued rule
- `ATR-SG-2026-00001` — Singapore IMDA-issued rule
- `ATR-TW-2026-00001` — Taiwan NAIO-issued rule

Sovereign sub-ranges allow a national authority to issue rules for its
own jurisdiction's threat landscape without forking the standard.
Sovereign-issued rules must:

- Pass the same conformance gate as community rules
- Carry an `attestation_signature` (ed25519) from the sovereign
  authority's published public key
- Be mirrored to the canonical repository (writeable from the sovereign
  authority's authorised account) for global visibility

The sovereign sub-range mechanism is the structural answer to "how does
this standard survive in a multipolar geopolitical context without
fragmenting." Each sovereign owns its namespace while remaining
conformant to the shared spec.

Operational launch of the sovereign sub-range mechanism is planned for
the project's sovereign solution package (post-Phase 5). This charter
codifies the mechanism so that the path is preserved.

### 8.3 No private namespaces

`ATR-<anything>-YYYY-NNNNN` ranges are reserved for sovereign authorities
admitted by the TSC. Private companies do NOT receive their own ID
prefixes; they contribute rules into the unprefixed canonical range
(`ATR-YYYY-NNNNN`) or carry their own internal IDs separate from the
ATR namespace. This prevents namespace fragmentation by commercial
forks while preserving the sovereign exception.

---

## 9. ATR-Certified™ program (overview)

The ATR-Certified™ program issues a verifiable trust mark to products
and skills that have passed an independent audit against the ATR
specification and conformance corpus. The program is run by the TSC
through a Certification Working Group; day-to-day program operations
are delegated to a non-profit audit administrator (initially Open
Source Collective Inc., transitionable on Tier 4 vote).

Two tracks:

- **ATR-Certified Skill** — free, community-issued, 90-day validity,
  CI-based determination (the Let's Encrypt transparency model
  preserved from v1.1).
- **ATR-Certified Enterprise** — paid third-party audit by an
  accredited audit lab, annual re-attestation, granted to a specific
  product release line.

Program guide, audit template, and certified-products registry live in
`certification/`. Detailed program rules are governed by a separate
document, `certification/program-guide.md`, which is itself an AEP.

---

## 10. Code of conduct

The Contributor Covenant 2.1 applies to all project spaces (GitHub,
TSC calls, conferences ATR is represented at). The TSC delegates CoC
enforcement to a 3-member committee elected annually from outside the
TSC, with appeal to the TSC by 2/3 vote.

---

## 11. Ratification

This charter is ratified when:

1. A 30-day public comment window has closed.
2. The current Numbering Authority (Adam Lin, BDFL under v1.1) accepts
   the charter and convenes the inaugural TSC.
3. The inaugural TSC is seated per § 3 with at least 6 of 9 seats
   filled within 90 days. Vacant seats are filled by interim TSC
   appointment, with the next regular election filling permanently.
4. The fiscal sponsor (Open Source Collective Inc.) acknowledges the
   charter in writing.
5. The first TSC vote — a Tier 4 vote ratifying this charter as the
   binding governance instrument — passes 7 of 9.

Until ratification, the v1.1 Numbering Authority model remains in
effect. This charter becomes effective on Date of Ratification, which
will be recorded at the top of this document.

### 11.1 Initial TSC seating plan (pre-ratification)

To accelerate ratification, the founder will publicly call for
nominations for the 9 seats within 7 days of this charter's first
public commit. Self-nominations are welcome. Existing ecosystem
maintainers from Microsoft Agent Governance Toolkit, Cisco AI Defense,
MISP CIRCL, precize, and the OASIS CoSAI Open Project will be
invited to nominate or self-nominate for the Vendor seats. National
CERTs that have engaged with ATR previously (NIST CAISI, UK NCSC,
Singapore IMDA, Five Eyes joint guidance authors, EU AI Office) will be
invited for the Sovereign liaison seats.

---

## 12. Amendments

This charter is amended only through an ACC per § 5.3. The
amendment record (which sections changed, what passed, which TSC
members voted which way) is published in
`governance/amendments/<year>/<acc-number>-<title>.md`.

---

## Appendix A — Comparison to prior governance models

This appendix records the design decisions behind the v2.0 model.
Reasoning is preserved here rather than buried in commit history.

| Choice | Source | Why for ATR |
|---|---|---|
| 9-seat TSC (odd, mid-sized) | CNCF TOC (11 seats); chosen 9 for ATR scale | 11 too large for ATR's current ecosystem; 7 too small to seat 5 constituencies |
| Hard 2-cap per company group | CNCF Charter §6(b)(iv) | The single most important structural protection against gradual capture |
| 2 Sovereign liaison seats | Unique to ATR; no precedent in CNCF/OASIS/OpenSSF/LF | ATR's positioning as a sovereign-cooperation substrate requires explicit sovereign participation; without this, sovereign adopters route around the standard |
| Tiered decision velocity | OpenSSF TAC matrix | Preserves SigmaHQ-class rule-add tempo while gating spec changes |
| Lazy consensus for Tier 1 | OpenSSF; SigmaHQ informal | Rule corpus growth is ATR's competitive advantage; must not gate at the daily level |
| 2/3 supermajority for spec changes | CNCF removal threshold | Reflects that a broken spec is harder to reverse than a broken rule |
| DCO, not CLA | Linux kernel; OpenSSF | CLA is the #1 source of contributor friction in adjacent communities |
| MIT for all artifacts (code, rules, spec, conformance) | Single permissive OSI license | One license across the project — simplest terms for adopters, audit labs, and sovereign authorities; matches the repo's inbound-MIT contribution model |
| Patent non-assertion (OASIS-style) | OASIS Non-Assertion Mode | Most permissive choice; lowest friction for sovereign and academic adoption |
| Sovereign sub-range namespace | Unique to ATR; partially inspired by IANA registries | Lets a sovereign issue rules under its national authority while remaining conformant. Structurally answers "what about multipolar AI governance" |
| Founder recusal after 12 months | New, ATR-specific | Defuses the founder-vendor dual-role conflict that has compromised similar projects (founder controls standard + sells against standard = irreconcilable) |

---

## Appendix B — What this charter intentionally does NOT do

- Does not pick the spec's technical content (rule grammar, schema
  fields). That is the spec's job.
- Does not specify the engine implementation. That belongs in
  `engines/<lang>/`.
- Does not define commercial pricing for any ATR-based product. That
  belongs to individual vendors.
- Does not commit to a particular standards-body publication path
  (OASIS / NIST / IETF / ISO). The TSC may pursue any or all in
  parallel; the current working recommendation (OASIS Open Project as
  the primary path) is a working proposal, not a charter commitment.

---

## Sources cited in design

- CNCF Charter §6: https://github.com/cncf/foundation/blob/main/charter.md
- OpenSSF TAC Decision Process: https://github.com/ossf/tac/blob/main/process/TAC-Decision-Process.md
- OASIS TC Process: https://www.oasis-open.org/policies-guidelines/tc-process-2017-05-26/
- OASIS IPR Policy (Non-Assertion Mode): https://www.oasis-open.org/policies-guidelines/ipr/
- AAIF Technical Committee: https://aaif.io/tc/
- C2PA Membership Tiers: https://c2pa.org/membership/
- OWASP Project Policy: https://policy.owasp.org/operational/projects
- Linux kernel DCO: https://developercertificate.org/
- Contributor Covenant 2.1: https://www.contributor-covenant.org/
- ATR v1.1 GOVERNANCE.md (predecessor): https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/GOVERNANCE.md
