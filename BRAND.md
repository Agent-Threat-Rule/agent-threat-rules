<div align="center">

<img alt="ATR — Agent Threat Rules" src="assets/logo-light.png" width="320" />

# Brand and Document Style Reference

[![Document](https://img.shields.io/badge/document-Brand_Reference-blue?style=flat-square)](#)
[![Audience](https://img.shields.io/badge/audience-Contributors-lightgrey?style=flat-square)](#)
[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen?style=flat-square)](#)

</div>

---

This document is the brand-asset and document-style reference for the
ATR project. Contributors authoring governance documents, blog posts,
slide decks, or external proposals should read it before submitting.

The trademark policy itself lives in [TRADEMARK.md](TRADEMARK.md);
this document captures the visual and typographic conventions that
make ATR materials feel like the work of a single standards body.

---

## 1. Logo

The project's primary mark lives at:

- `assets/logo-light.png` — 800 × 339 PNG, transparent background, for
  light backgrounds. This is the default. Repository, web site, and
  governance documents use this variant.

### 1.1 Usage rules

- MUST be presented unmodified. No recoloring, no rotation, no
  drop-shadow, no added text adjacent to the mark.
- MUST be presented with at minimum 24 px of clear space on all
  sides at the rendered size.
- MUST NOT be presented at less than 120 px width.
- MUST NOT be combined with another organization's mark in a way
  that implies endorsement.

### 1.2 Where to render

| Surface | Width | Wrapping markup |
|---------|-------|-----------------|
| Governance documents (root level) | 320 px | `<div align="center"><img alt="ATR — Agent Threat Rules" src="assets/logo-light.png" width="320" /></div>` |
| Sub-directory documents (one level deep) | 240 px | `<div align="center"><img alt="..." src="../assets/logo-light.png" width="240" /></div>` |
| Sub-directory documents (two levels deep) | 240 px | `<div align="center"><img alt="..." src="../../assets/logo-light.png" width="240" /></div>` |
| Web site | per design system | n/a |

A dark-variant logo is intentionally not yet shipped. When the project
publishes documents for dark-background surfaces, a dark variant will
be added to `assets/` and this section will be updated.

## 2. Color

The project's published color set is intentionally minimal. Colors are
referenced by the names used by shields.io for badge fills.

| Name | Use | shields.io alias | Hex |
|------|-----|------------------|-----|
| Brand sage | Primary accent, success states, GitHub-merged badges | `brightgreen`, `2ea44f` | `#2ea44f` |
| Neutral grey | Secondary text, document metadata badges | `lightgrey` | `#9f9f9f` |
| Alert orange | Draft, status-pending, hold | `orange` | `#fe7d37` |
| Reference blue | Cross-document badges, document-class markers | `blue` | `#007ec6` |

Avoid introducing additional colors. If a new state needs a color, add
it to this table and to the badge style table below before using it.

## 3. Status badges

Every formal document MUST carry a row of shields.io badges in the
header block. The badges convey at a glance: status, effective date,
authority, and version.

### 3.1 Standard badge set

| Document class | Standard badge row |
|----------------|---------------------|
| Charter or policy | Status, Effective, Authority, Version |
| Onboarding or operational | For, Edition, Status |
| Meeting agenda | Document, Posted |
| Meeting minutes | Document, Quarter |
| Spec | Status, Version, License |
| Announcement | Draft / Publish-when, plus a credentialing wall (5 max) of merged-PR badges |

### 3.2 Badge URL pattern

All badges use the shields.io static path with `style=flat-square`.
Template:

```
https://img.shields.io/badge/<label>-<value>-<color>?style=flat-square
```

Dashes inside the label or value MUST be escaped as `--`. Spaces are
encoded as `_`.

### 3.3 Badge tone

Keep badge values short. "MISP — galaxy merged" is
acceptable. "MISP — Several clusters merged across multiple
PRs over many months" is not. Badge values must describe what is
still present upstream, not a past state.

## 4. Typography conventions

These conventions apply to governance documents, RFCs, announcements,
and policy texts. They do not apply to rule YAML files, code, or
generated reports.

### 4.1 Word choice

Avoid the following words and phrases. They flag a draft as AI-flavored
or marketing-flavored and are not appropriate in standards-body
materials:

| Avoid | Use instead |
|-------|-------------|
| comprehensive | (drop or use a measurable adjective) |
| leverage | use, apply, employ |
| robust | reliable, validated |
| seamless | (drop) |
| I'm excited to announce | (drop opener; lead with the fact) |
| best-in-class | (drop or replace with an evidence sentence) |

### 4.2 Line wrap

Wrap source markdown at 80 columns where practical. Tables and code
blocks are exempt.

### 4.3 Punctuation

- Do not use em-dashes (`—`) as a substitute for commas or
  parentheses. Use the actual punctuation.
- Bullet lists use `-` not `*`.
- Section headings use `#` syntax, not `===` / `---` underlines.

### 4.4 Normative language

Use BCP 14 normative keywords (MUST, MUST NOT, SHOULD, SHOULD NOT,
MAY, REQUIRED, SHALL, SHALL NOT, RECOMMENDED, NOT RECOMMENDED,
OPTIONAL) only where the obligation is real. Style emphasis uses
italics or bold, not capitalised normative keywords.

### 4.5 Numerals

| Range | Form |
|-------|------|
| 0 – 9 (in prose) | Spelled out: "three seats", "two of three" |
| 10 and up | Numerals: "14-day comment period" |
| In tables, code, version numbers, dates | Always numerals |
| Year ranges | Numerals: "2026 Q3" |

## 5. Document header pattern

Every formal document follows this exact structure for the first
block:

```markdown
<div align="center">

<img alt="ATR — Agent Threat Rules" src="<path>/logo-light.png" width="<size>" />

# <Document Title>

[![Badge1](...)](#)
[![Badge2](...)](#)
[![Badge3](...)](#)

</div>

---

<one-paragraph context sentence>

---

## 1. <First numbered section>
```

Document footer pattern:

```markdown
---

<div align="center">

[Related Doc 1](url) · [Related Doc 2](url) · [Related Doc 3](url)

</div>
```

The middle dot (`·`, U+00B7) separates footer links. Use no more than
four footer links per document.

## 6. Cross-reference style

| Target | Form |
|--------|------|
| Another root-level document | `[FILENAME.md](FILENAME.md)` |
| A section within this document | `[short title](#1-section-anchor)` |
| A section in another document | `[FILENAME.md §N](FILENAME.md#n-section-anchor)` |
| An external reference | `[title](https://...)`; prefer GitHub absolute URLs over relative when the document may be read outside the repo |

Avoid the bare-URL form `<https://example.com>` in body text.

## 7. Date format

Use ISO 8601 dates only: `YYYY-MM-DD`. Do not use US (`MM/DD/YYYY`)
or European (`DD/MM/YYYY`) formats. Do not use month names in
governance documents. Month names are acceptable in announcements.

## 8. Filenames

| Class | Pattern |
|-------|---------|
| Governance policy | `ALL-CAPS.md` at repo root (e.g. `GOVERNANCE.md`, `TRADEMARK.md`, `TSC-CHARTER.md`) |
| Operational guide | `SCREAMING-CASE.md` at repo root |
| Brand and meta | `BRAND.md`, `SECURITY.md`, `CONTRIBUTING.md` |
| Spec | `SPEC.md` (singular, no version in filename — version is inside the doc) |
| Meeting minutes | `YYYY-MM-DD.md` inside a quarter directory |
| Meeting agendas | `AGENDA-YYYY-MM-DD.md` inside a quarter directory |
| Drafts not for publication | `<NAME>.draft.md` |
| Superseded | Keep the original filename; add SUPERSEDED header inside the file |

## 9. External assets

When embedding diagrams, screenshots, or third-party logos in any
document, place the asset under `assets/` and reference by relative
path. Do not hot-link external image URLs.

For diagrams that are programmatically generated, prefer source-and-build
(SVG generated from Mermaid or plantuml) over binary-only PNGs.

## 10. Revision history of this document

| Version | Date | Editor | Summary |
|---------|------|--------|---------|
| 1.0 | 2026-05-16 | Adam Lin (BDFL) | Initial brand reference |

---

<div align="center">

[TRADEMARK.md](TRADEMARK.md) · [SPEC.md](SPEC.md) · [GOVERNANCE.md](GOVERNANCE.md)

</div>
