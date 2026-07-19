# OASIS Open Project Proposal — Agent Threat Rules (ATR)

**Status:** Submitted to OASIS Project Administrator 2026-05-26
**Submitted by:** Adam Lin, Maintainer, Agent Threat Rules <adam@agentthreatrule.org>
**Submission date:** 2026-05-26
**Project name:** Agent Threat Rules (ATR)
**Proposed Project type:** OASIS Open Project (lightweight tier)
**Adjacent to:** CoSAI Open Project (cross-reference, not subsumed)
**Submission channel:** project-admin@oasis-open.org per OASIS getting-started guide
**Permanent URL:** https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/governance/oasis-proposal-2026-05-26.md

---

## 1. Project name and purpose

### 1.1 Name

Agent Threat Rules (ATR)

### 1.2 Purpose

ATR is the open machine-readable detection-rule standard for AI agent threats. It is to AI agent security what Sigma is to SIEM detection, YARA is to malware signatures, and CVE/CWE is to software vulnerabilities. ATR rules are YAML declarative patterns that any conformant engine can load and evaluate at agent runtime.

This Open Project will:
- Maintain the canonical specification for ATR rules, events, profiles, and correlation
- Maintain the conformance test corpus with signed expected-results
- Maintain the canonical rule corpus (currently 427 rules across 10 categories)
- Operate the ATR Numbering Authority issuing ATR-YYYY-NNNNN identifiers
- Coordinate with adjacent standards (CoSAI taxonomy, MITRE ATLAS, NIST AI RMF, OWASP Agentic Top 10, EU AI Act Article 50)
- Run the ATR-Certified™ program for products and skills

---

## 2. Background

The ATR project began in early 2026 as a community-led detection-rule corpus. As of May 2026:

- **427 rules** across 10 categories on the main branch
- **Production adoption** through public GitHub merges:
  - Microsoft Agent Governance Toolkit (PRs #908 + #1277, April 2026)
  - Cisco AI Defense skill-scanner (PRs #79 + #99, April 2026)
  - MISP CIRCL (galaxy #1207 + taxonomies #323, May 2026) — used by national CERTs
  - precize / Gen Digital Sage chain (#74, May 2026)
- **Measured performance**: 100% precision + 89.7% recall on 341-sample internal benchmark; 97.1% recall on NVIDIA garak; 99.7% precision + 63.2% recall on an 850-sample PINT-format corpus (self-built, not Lakera's official PINT)
- **Zenodo DOI**: 10.5281/zenodo.19178002
- **MIT** licensing (single license across the project)
- **Fiscal sponsor**: Open Source Collective Inc. (501(c)(3), EIN 81-1567737)

The project has matured to the point where its current single-maintainer governance model is a structural limit to further adoption. F500 buyers, national CERTs, and OASIS / NIST / EU AI Office have all signalled that the project would benefit from a multi-stakeholder governance model and a standards-body home.

---

## 3. Initial work products

| Work product | Status | Path in repo |
|---|---|---|
| ATR Rule Format Specification v1.0 | Draft (existing) | `ATR-SPEC-v1.md` |
| ATR Event Format Specification v1.0 | Draft (new May 2026) | `spec/atr-event-v1.0.md` |
| ATR Profile Format Specification v1.0 | Draft (new May 2026) | `spec/atr-profile-v1.0.md` |
| ATR Correlation Rule Format v1.0 | Draft (new May 2026) | `spec/atr-correlation-v1.0.md` |
| ATR Language Detection Algorithm v1.0 | Draft (new May 2026) | `spec/atr-language-detection-v1.0.md` |
| ATR Category Registry v1.0 | Draft (new May 2026) | `spec/category-registry/v1.0.yaml` |
| ATR JSON Schemas (rule, event, profile, correlation) | Draft (new May 2026) | `spec/schema/*.json` |
| ATR Conformance Test Corpus v1.0 | Draft packaging (May 2026), full release planned Q3 2026 | `spec/conformance/` |
| ATR rule corpus | 427 rules, ongoing | `rules/` |
| Governance Charter v2.0 | Draft (new May 2026) | `governance/CHARTER.md` |
| Standard Threat Model | Draft (new May 2026) | `governance/STANDARD-THREAT-MODEL.md` |
| Reference implementation (TypeScript) | Production-grade, existing | `src/` → `engines/typescript/` (planned) |
| Reference implementation (Python) | Skeleton + interface contract | `engines/python/` |
| Reference implementation (Go) | Skeleton + interface contract | `engines/go/` |

Roadmap items for the first 12 months of the Open Project:
1. Q3 2026 — First Committee Specification of ATR Rule Format v1.0
2. Q4 2026 — Conformance corpus signed publication; first ATR-Certified™ Enterprise audit lab accredited
3. Q1 2027 — Python and Go reference implementations reach L1 conformance pass

---

## 4. Project structure and governance

The Open Project will be governed by a Project Governing Board (PGB) per OASIS Open Project standard structure. The PGB will be composed of:

- 3 seats for current ATR community maintainers + contributors
- 2 seats for sponsoring OASIS member organisations
- 2 seats for sovereign / standards-body liaisons (per the ATR Charter sovereign liaison model)
- 1 OASIS staff observer
- 1 CoSAI Open Project liaison

The PGB will operate via the OASIS standard Lightweight Process. Detailed governance is in the ATR Technical Steering Committee Charter v2.0 (`governance/CHARTER.md`), which is compatible with OASIS Open Project requirements.

Key governance details:
- Single-company seat cap: **2 seats max** per company group (CNCF model, prevents capture)
- Decision tiers from lazy-consensus (rule additions, daily) to 3/4 supermajority (charter changes)
- ATR Numbering Authority for canonical and sovereign-prefixed identifiers
- DCO (no CLA) for contributor sign-off
- IPR mode: **Non-Assertion** (OASIS default for STIX/TAXII precedent)
- Conflict of interest disclosure annually; founder recusal after 12-month transition seat
- 2 sovereign / standards-body liaison seats — ATR's structural differentiator versus other AI standards venues

---

## 5. Sponsors

This proposal requires endorsement by ≥3 OASIS member organisations. We are in active discussions with the following organisations as potential sponsors:

- **Cisco** (engaged via Cisco AI Defense's adoption of ATR rules, PRs #79 + #99 merged April 2026)
- **IBM** (engaged via OSCAL adjacent participation)
- **Anthropic** (engaged via CoSAI co-chair role + ATR's coverage of Anthropic Semantic Kernel CVEs via Microsoft Copilot loop)

Sponsoring organisations commit to:
- Public statement of support for the project's formation
- PGB seat or observer (their choice)
- Continued participation in the Open Project's quarterly review cycle

Specific sponsor commitments will be confirmed in writing before submission to the OASIS Board.

---

## 6. Open-source license commitment

| Artifact class | Licence |
|---|---|
| All ATR artifacts (code, rules, specifications, conformance corpus) | MIT |

The MIT License is OSI-approved. No source-available or restricted licences will ever be adopted; this is a permanent commitment per `governance/CHARTER.md` § 7.1.

---

## 7. IPR Mode

**Non-Assertion Mode** per OASIS IPR Policy § 10.3.

Reasoning: Non-Assertion provides the lowest friction for sovereign, academic, and commercial adoption while preserving contributors' right to assert against non-conformant implementations. This matches the OASIS CTI TC precedent (STIX/TAXII operate in Non-Assertion Mode).

---

## 8. Anticipated audience and consumers

| Audience | Primary use of ATR |
|---|---|
| AI agent platform vendors (Anthropic, OpenAI, Google, Microsoft, Cisco, etc.) | Embed ATR rule corpus into product detection layer; claim conformance |
| Detection engineering teams (red teams, blue teams, MSSP) | Author and consume rules; integrate with PyRIT / garak / Sigma / RAMPART workflows |
| National CERTs and sovereign authorities | Issue rules under sovereign sub-ranges; reference ATR in national guidance |
| F500 / regulated industry CISOs | Procurement-grade trust mark via ATR-Certified™ Enterprise; compliance binder via OSCAL companion catalog |
| EU AI Act / UK GDPR / Singapore PDPA compliance teams | Cite ATR as the executable detection layer satisfying Article 32 / Article 50 obligations |
| Academic researchers | Cite ATR rule corpus and conformance benchmark in peer-reviewed work; Zenodo DOI in place |
| Civil society / public-interest groups | Use ATR-Certified™ badge to evaluate consumer-facing AI agent products |

---

## 9. Why OASIS Open Project (vs other venues)

| Alternative | Why considered | Why not chosen |
|---|---|---|
| **Full OASIS Technical Committee** | Strongest standards weight | Requires substantial member-org participation; better suited after Open Project maturation |
| **Linux Foundation AAIF** | MCP / A2A / AGNTCY co-location | AAIF TC is 100% US hyperscaler-staffed (May 2026); incompatible with sovereign-cooperation positioning |
| **IETF** | Open standards body | Detection rules are content, not protocol bits-on-wire |
| **NIST direct publication** | Highest US federal weight | US tilt is feature for Five Eyes adoption / bug for ASEAN / MENA neutrality. Better used as citation target |
| **ISO/IEC SC42** | Highest international weight | 3-5 year publication timeline incompatible with 6-month sovereign window |

OASIS Open Project is chosen for: (a) STIX/OSCAL/CoSAI precedent (executable detection content historically goes to OASIS), (b) 12-24 month tempo matching ATR's strategic window, (c) neutrality acceptable to non-aligned jurisdictions, (d) co-location with CoSAI MCP Security taxonomy creating cross-reference (not competition).

---

## 10. Cross-reference to CoSAI Open Project

ATR and CoSAI are complementary peers:

- **CoSAI** publishes **taxonomy / vocabulary / framework research** (MCP Security taxonomy Jan 2026, Agentic IAM research May 2026, Future of Agentic Security paper May 2026, AI Incident Response Framework v1).
- **ATR** publishes **executable detection rules** that operationalise the taxonomies CoSAI defines.

When the CoSAI MCP Security taxonomy names a threat class, an ATR rule can fire on a specific instance of that class. The two artifacts cross-reference at the citation level without overlapping in scope.

The proposal explicitly positions ATR as **adjacent**, not subsumed, with the expectation that:
- CoSAI's taxonomies are normatively referenced in ATR rule `references` blocks
- ATR rule firings are normatively referenced in CoSAI's incident response framework
- The two PGBs maintain liaison seats on each other's project (one seat each)

---

## 11. Initial PGB membership (pre-acceptance)

To accelerate proposal acceptance, initial PGB members will be confirmed during the OASIS staff review period. Current candidates:

- ATR Maintainer: Adam Lin (community maintainer, transitioning per `governance/CHARTER.md` § 6.2 founder recusal)
- Sponsoring members: Cisco + IBM + Anthropic (per § 5)
- Sovereign liaisons: invitations extended to NIST CAISI, UK NCSC, EU AI Office, Singapore IMDA — slots filled as accepted
- OASIS staff observer: TBD by OASIS staff
- CoSAI liaison: nominated by CoSAI Steering

---

## 12. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Sovereign liaison seats remain unfilled at launch | Acceptable — PGB can operate at 7/9 seats indefinitely. Liaison seats invited continuously. |
| Conflict with CoSAI scope | Pre-confirmed via CoSAI Steering before submission. ATR explicitly defers taxonomy work to CoSAI. |
| OASIS approval timeline > 6 months | Project continues development under current Numbering Authority during review. No work blocks on OASIS decision. |
| F500 / enterprise want full OASIS Standard, not Open Project | Migration path to full TC is supported by OASIS; revisit after Open Project maturation. |

---

## 13. Submission checklist

- [x] Project name + purpose (this document § 1)
- [x] Initial work product list (§ 3)
- [x] Project structure and governance (§ 4)
- [ ] Sponsoring members confirmed in writing (§ 5)
- [x] Open-source licence commitment (§ 6)
- [x] IPR Mode declaration (§ 7)
- [x] Anticipated audience (§ 8)
- [ ] Initial PGB roster confirmed (§ 11)
- [ ] Public comment period (30 days, post-OASIS staff review)
- [ ] OASIS Project Advisory Council recommendation
- [ ] OASIS Board approval

---

## 14. Contact

- Project maintainer: Adam Lin <adam@agentthreatrule.org>
- Fiscal sponsor: Open Source Collective Inc. — contact@opencollective.com
- TSC mailing list (post-ratification): tsc@agentthreatrule.org
- Project repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
