# ATR Website — Standards-Conformance Plan
**Author:** Adam Lin · **Date:** 2026-05-26 · **Target:** Take agentthreatrule.org from "SaaS landing" (avg 5/10 standards-feel) to "RFC/W3C-style standards site" (target 9/10).

## Audit Summary (Day 0 baseline)

20 pages, 9,320 LOC. Best: `/quality-standard` 8/10 (already RFC-001 framed). Worst: `/rules` 0/10 (empty delegation), `/wall` 3/10, `/` 3/10, `/red-team` 4/10.

Cross-cutting problems:
1. Marketing animation components (`HeroEntrance`, `CountUp`, `NumberScramble`, `SpeedLines`, `Flywheel`) on most pages.
2. No `Document Status` block, no ToC, no `§N.N` cross-refs, no MUST/SHOULD/MAY callout, no normative/informative labels.
3. Missing standard-site pages: `/spec`, `/conformance`, `/errata`, `/glossary`, `/charter`, `/citations`.
4. CTAs are "Get Started" / "Try Now" instead of "Read the Specification" / "View Schema" / "Implementer Test Suite".
5. Palette: gradient cyan-to-purple. Standards palette is navy + white.
6. Font: sans-serif marketing. Standards body is serif (W3C uses `Source Serif Pro`, IETF uses `Charter`).

---

## Global components (build once, used everywhere)

Path | What | Notes
---|---|---
`components/DocumentStatus.tsx` | Top-of-page banner: `[Working Draft · 3.0.0-alpha.1 · 2026-05-26]` with anchor to `/spec` and link to canonical URL | Single source of truth pulls from `data/spec-meta.json`
`components/SpecSection.tsx` | Auto-numbered `<section>` wrapper with `§N.N` heading anchor | Replaces ad-hoc `<h2>` everywhere
`components/SpecToC.tsx` | Auto-generated ToC from `SpecSection` registration | Sticky left-rail on lg+, collapsible on mobile
`components/NormativeBadge.tsx` + `InformativeBadge.tsx` | Inline `[Normative]` / `[Informative]` chips | Applied to each section + each reference
`components/RFC2119.tsx` | Inline callout: "The keywords MUST, SHOULD, MAY in this document follow RFC 2119" | Auto-included at top of `/spec`
`components/CitationBlock.tsx` | BibTeX / APA / IEEE / Chicago tabbed citation | Used on `/citations` and any page that ships a paper

Tailwind config:
- Palette: navy (`#0b1d3a`), white, slate-700 (links). Kill cyan/purple/gradient.
- Font: `font-serif` = Source Serif Pro (body), `font-sans` = Inter (nav/footer only).

---

## Tier 1 — Homepage + Spec + Implementers (the visible transformation)

**T1.1 — Homepage rewrite (`app/[locale]/page.tsx`)**
- Remove imports: `HeroEntrance`, `CountUp`, `SpeedLines`, `NumberScramble`, `Flywheel`, `HeroGrid`.
- New layout: `<DocumentStatus />` banner → Abstract paragraph (3-4 sentences pulled from README §Abstract) → ToC (links to `/spec` numbered sections) → `§1 Overview` (1 paragraph) → `§2 Adoption` (table — see T1.3) → `§3 Get the spec` (3 download buttons: Markdown, YAML schema, PDF). No animations.
- Move existing 8-scene narrative + Flywheel to `/about/narrative` (opt-in archive, not main flow).

**T1.2 — Create `/spec` canonical page (`app/[locale]/spec/page.tsx`)**
- Mirror the README structure: §1 Background, §2 Conformance Levels, §3 Specification, §4 Adoption, §5 Coverage, §6 Evaluation, §7 Governance, §8 Security, §9 Contributing, §10 Citation, §11 Maintainers, §12 Sponsorship, §13 License.
- Each section uses `<SpecSection>` wrapper.
- Add `[Normative]` badge to §2 Conformance Levels, §3 Specification. Other sections are `[Informative]`.
- Top: `<DocumentStatus />` + `<RFC2119 />` callout. Right rail: `<SpecToC />`.
- Bottom: "References" with Normative / Informative split.

**T1.3 — Rename `/ecosystem` → `/implementers` (`app/[locale]/implementers/page.tsx`)**
- Restructure as Implementer Report table:

  | Organization | Conformance Level | Spec Version | Integration Date | Public Reference |
  |---|---|---|---|---|
  | Microsoft AGT | L1 Engine | 3.0.0-alpha.1 | 2026-04-13 | PR #1277 |
  | Cisco AI Defense | L1 Engine | 2.2.0 | 2026-04-22 | PR #99 |
  | MISP / CIRCL | L1 Galaxy | 2.2.0 | 2026-05-10 | galaxy #1207 |
  | OWASP A-S-R-H | L1 Citation | 2.2.0 | 2026-05-11 | PR #74 |
  | Gen Digital Sage | L1 Engine | 2.2.0 | 2026-05-11 | PR #33 |
- Do not list NIST OSCAL in this table. usnistgov/oscal-content#338 is an open pull request offering AI RMF profile examples, awaiting NIST review; it is not an implementation. (Corrected 2026-10-16: this table previously had a "NIST OSCAL | Path 1 Accepted" row.)
- Add 301 redirect: `/ecosystem` → `/implementers` (Next.js `redirects()` in `next.config.ts`).
- Drop "S-tier / 1-4 commercial" tier language. Use formal `Production / Review / Draft`.

**T1.4 — Footer (`components/Footer.tsx`)**
- Add `Editors: Adam Lin <adam@agentthreatrule.org>` line.
- Add `Canonical URL: https://agentthreatrule.org/spec` line.
- Add `DOI: 10.5281/zenodo.19178002` line with link.
- Remove social media link styling that looks brand-y.

---

## Tier 2 — New pages (placeholders OK, structure > content)

**T2.1 — `/conformance` (`app/[locale]/conformance/page.tsx`)**
- §1 Conformance Levels (L1 Engine / L2 Engine+Publisher / L3 Sub-range Authority).
- §2 Test Suite (link to `spec/conformance/` fixtures in repo).
- §3 Self-Certification Process (PR template + checklist).
- §4 Implementer Reporting (link to `/implementers`).

**T2.2 — `/errata` (`app/[locale]/errata/page.tsx`)**
- Table of known errors per published spec version.
- Even if empty today, page must exist with "No errata reported for current Working Draft (3.0.0-alpha.1)" — placeholder is fine.
- Pulls from `data/errata.json` (build this file with `[]` for now).

**T2.3 — `/glossary` (`app/[locale]/glossary/page.tsx`)**
- 25-30 key terms: `SKILL.md`, `MCP exchange`, `scan_target`, `agent runtime`, `conformance level`, `severity tier`, `maturity status`, `Threat Cloud`, `crystallization`, `provenance`, `auto-review`, `canary`, etc.
- Alphabetical, anchored by term (`/glossary#skill-md`).
- Each entry: 2-3 sentences + link to first appearance in `/spec`.

**T2.4 — `/charter` (`app/[locale]/charter/page.tsx`)**
- §1 Project Mission. §2 Scope (in / out of scope explicit list). §3 Governance (current BDFL → TSC transition). §4 IP Policy (MIT, no CLA). §5 Decision-Making (RFC process, voting threshold). §6 TSC Seating Criteria.
- Pulls from `GOVERNANCE.md` in repo.

**T2.5 — `/citations` (`app/[locale]/citations/page.tsx`)**
- Tabbed: BibTeX / APA / IEEE / Chicago.
- DOI: `10.5281/zenodo.19178002`.
- Replaces the citation snippet currently inline in `/research`.

---

## Tier 2 — Format upgrades on existing pages

T2.6. `/changelog` — Tag each release with `[Breaking]` / `[Compatible]` / `[Editorial]` instead of color badges. Add per-release version anchor (`#v3-0-0-alpha-1`).

T2.7. `/compliance` — Add version block per framework: `NIST AI RMF 1.0 (Jan 2023)`, `OWASP Agentic Top 10 (2026)`, `MITRE ATLAS (2026-04)`, `SAFE-MCP (OpenSSF Sandbox, 2026-05)`, `EU AI Act (Regulation 2024/1689)`, `ISO/IEC 42001:2023`. Add citation footer per framework.

T2.8. `/coverage` — Add §Methodology section: how recall/precision is measured per corpus, sample selection criteria, replication command. DOI/arXiv per corpus where available.

T2.9. `/research` — Replace bullet list with formal citation block (use new `CitationBlock` component). Each paper gets DOI or arXiv ID + open-data link.

T2.10. `/governance` — Version-number the merge gates (`Gate G1.1 Schema Validation`, `G1.2 RFC-001 Quality`, etc.). Add §Appeals Process. Cite RFC-001 by full version.

T2.11. `/quality-standard` — Promote to `/spec/rfc-001/page.tsx`. Add proper RFC header: Status, Editors, Abstract, Status of This Document, ToC, Conformance, References. Old `/quality-standard` becomes a 301 redirect.

T2.12. `/partner-sync` — Link OpenAPI spec (build `public/openapi.yaml`). Add formal HTTP error code table. Add version block (`API v1`).

T2.13. `/responsible-use` — Add §Security Considerations. Specify 90-day responsible disclosure embargo. Link to `SECURITY.md` with explicit PGP key fingerprint.

T2.14. `/threats` — Publish JSON Schema for the threat feed. Add classification criteria definition (what counts as `confirmed_malware` vs `flagged`).

T2.15. `/integrate/garak` — Add §Provenance Format section formally specifying `metadata_provenance.garak_probe` field shape. Canary window (24h) becomes a configurable spec parameter, not hardcoded.

---

## Tier 3 — Things to remove or de-emphasize

T3.1. `/wall` → move to `/community` (out of main nav). Remove "country flags" decoration; keep contributor name + GitHub link + contribution tag only.

T3.2. `PledgeWall` component → delete. Replace any usages with link to `/community`.

T3.3. `/red-team` → rename to `/adversarial-research`. Reframe lead paragraph from "Find the attack. We ship the rule. 2 hours 16 minutes" (product copy) to "ATR's adversarial research program imports payloads from {garak, HarmBench, PyRIT, …}, runs them through a 6-stage pipeline {…}, and produces normative rules." Move time metric (2h 16m) to §Measured Latency with methodology.

T3.4. All marketing animations removed (handled in Global).

T3.5. CTA copy rewrite site-wide:
- "Get Started" → "Read the Specification"
- "Try Now" → "View the JSON Schema"
- "Browse rules" → "Browse the Rule Corpus (§3.5)"
- "Sign up" → "Become an Implementer"

---

## Effort estimate

| Tier | Items | Effort |
|---|---|---|
| Global components | 6 components + Tailwind config + palette + font | ~3 hr |
| Tier 1 | Homepage rewrite + `/spec` + `/implementers` rename + Footer | ~4 hr |
| Tier 2 new pages | 5 placeholder pages (conformance/errata/glossary/charter/citations) | ~2 hr |
| Tier 2 format upgrades | 10 existing pages reformatted | ~5 hr |
| Tier 3 cleanup | Move wall + delete PledgeWall + rename red-team + CTA sweep | ~2 hr |
| Build + smoke test + deploy to Cloudflare Pages | All routes + sitemap regen | ~1 hr |
| **Total** | | **~17 hr** |

Realistic single-night sprint: Global + Tier 1 only (≈7 hr) gets standards-feel from 5/10 → 8/10. Tier 2 + 3 over 1-2 follow-up nights pushes to 9-10/10.

---

## Execution order

1. Build global components (`DocumentStatus`, `SpecSection`, `SpecToC`, `NormativeBadge`, `InformativeBadge`, `RFC2119`, `CitationBlock`) — no visible change yet.
2. Tailwind config: navy palette + serif body.
3. Rewrite `/` (homepage) using new components — first visible "I'm a standard" moment.
4. Build `/spec` — canonical source of authority.
5. Rename `/ecosystem` → `/implementers` + add 301 redirect.
6. Footer update.
7. Build Tier 2 new pages (placeholders).
8. Reformat Tier 2 existing pages (10 of them).
9. Tier 3 cleanup (remove `/wall` from nav, delete `PledgeWall`, rename `/red-team`, CTA sweep).
10. `npm run build && npm run deploy` — push to Cloudflare Pages.
11. Smoke test all 25 routes (20 existing + 5 new).

---

**Hold for user approval before starting execution.**
