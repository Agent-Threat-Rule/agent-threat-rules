<div align="center">

<img alt="ATR — Agent Threat Rules" src="assets/logo-light.png" width="320" />

# Technical Steering Committee Onboarding

[![For](https://img.shields.io/badge/for-TSC_members-blue?style=flat-square)](TSC-CHARTER.md)
[![Edition](https://img.shields.io/badge/edition-2026--Q3-lightgrey?style=flat-square)](#)
[![Status](https://img.shields.io/badge/status-Active-brightgreen?style=flat-square)](#)

</div>

---

This document is the practical operating manual for new TSC members.
The normative document is [TSC-CHARTER.md](TSC-CHARTER.md); this is
the working knowledge layered on top.

---

## 1. Welcome

You have been admitted to the ATR Technical Steering Committee. The
following pages contain everything you need in your first thirty
days. Read it once now and refer back as needed. If anything is
unclear after a read, raise it in the next TSC meeting or with the
BDFL at adam@agentthreatrule.org.

## 2. First-Week Checklist

Complete each item before your first regular meeting.

- [ ] Read [SPEC.md](SPEC.md) in full. The Specification is the
      project's most-cited normative artifact. You will be asked to
      vote on amendments to it.
- [ ] Read [GOVERNANCE.md](GOVERNANCE.md), [TSC-CHARTER.md](TSC-CHARTER.md),
      [docs/BDFL-charter.md](docs/BDFL-charter.md), and
      [TRADEMARK.md](TRADEMARK.md).
- [ ] Review [stats.json](stats.json) and the most recent
      [CHANGELOG.md](CHANGELOG.md) entry. These together describe
      the current state of the corpus and recent project velocity.
- [ ] Skim three to five recent merged rule PRs to internalize the
      quality bar.
- [ ] Run the Conformance Test Suite locally per
      [conformance/v1.0/README.md](conformance/v1.0/README.md) and
      confirm it passes against the in-tree engine.
- [ ] Subscribe to the public mailing list and the project's
      [Discussions](https://github.com/Agent-Threat-Rule/agent-threat-rules/discussions).
- [ ] Add yourself to [CONTRIBUTORS.md](CONTRIBUTORS.md) with your
      seat designation, affiliation, and a public email.
- [ ] File a one-time disclosure in `disclosures/<your-handle>.md`
      stating: current employer, equity holdings exceeding 1% in any
      AI security vendor, and any prior or current commercial
      engagement with the ATR project.

## 3. GitHub Access

The BDFL grants you membership in the `@Agent-Threat-Rule/tsc` team
within 24 hours of admission. The team has:

- Pull-request review authority on all repositories in the
  `Agent-Threat-Rule` organization.
- `CODEOWNERS` coverage of `SPEC.md`, `GOVERNANCE.md`, `TRADEMARK.md`,
  `TSC-CHARTER.md`, and all governance documents.
- Merge authority on PRs that have passed the quality gate and that
  the TSC team has approved by the threshold in
  [TSC-CHARTER.md §5.1](TSC-CHARTER.md#51-vote-thresholds).

You do not need to use the merge authority alone. By convention, the
final merge is performed by the BDFL after TSC approval, until the
post-Founding-Three transition completes.

## 4. Communication Channels

| Channel | Purpose | Cadence |
|---------|---------|---------|
| Public meeting (Google Meet) | Live TSC decisions, public observers welcome. Link in each [calendar event](https://calendar.google.com/calendar/embed?src=c_a2dd390e73cd0b26fb32fd145173389ccbec312083436e3c88f7dabb35d31592%40group.calendar.google.com). | Bi-weekly, 30 minutes |
| Mailing list [`atr-tsc@agentthreatrule.org`](https://groups.google.com/a/agentthreatrule.org/g/atr-tsc) | Asynchronous coordination, votes between meetings | As needed |
| [GitHub Discussions: TSC Coordination](https://github.com/Agent-Threat-Rule/agent-threat-rules/discussions/categories/tsc-coordination) | TSC-only posting, community read + reply | As needed |
| [GitHub Discussions: RFC](https://github.com/Agent-Threat-Rule/agent-threat-rules/discussions/categories/rfc) | Public-comment-period documents | During 14-day or 21-day windows |
| `disclosures/` directory in repo | Conflict-of-interest disclosures | Updated on employment change |

Use the mailing list for items requiring a written record. Use
Discussions for items the broader community should see. Use the
meeting for items requiring real-time discussion.

## 5. Pull-Request Review Workflow

### 5.1 What you review

By default, TSC members are not required to review every PR. The
quality gate CI and the standard reviewer rotation handle most rule
PRs. TSC review is expected for:

- Any PR touching `SPEC.md`, `GOVERNANCE.md`, `TRADEMARK.md`, or
  `TSC-CHARTER.md`.
- Any PR proposing a new category or removing a category.
- Any PR introducing or modifying the Conformance Test Suite.
- Any PR whose author is the BDFL or another TSC member.
- Any PR flagged `needs-tsc-review` by a reviewer or the BDFL.

### 5.2 Review labels

| Label | Meaning |
|-------|---------|
| `needs-tsc-review` | At least one TSC member's review required before merge |
| `tsc-approved` | TSC approval threshold met per Charter §5 |
| `tsc-blocked` | A TSC member has raised an objection; resolution required before merge |
| `auto-mergeable` | Retired on 2026-06-03. Nothing merges automatically (the repository has auto-merge turned off); a maintainer has to merge each PR |
| `needs-human-review` | CI safety gate failed; awaits maintainer judgement |

### 5.3 Time expectations

A TSC member is expected to land a `tsc-approved`, `tsc-blocked`, or
substantive comment on a `needs-tsc-review` PR within 7 calendar days
of being requested. If you cannot meet that window, comment with the
date you expect to respond, or hand off explicitly to another TSC
member.

## 6. Bringing a Decision to the TSC

To put an item before the TSC:

1. Open a GitHub Issue in the canonical repository tagged
   `tsc-agenda`.
2. State the proposal in one paragraph, then enumerate the question
   to be voted on as a single closed yes-or-no.
3. Link any background reading.
4. Indicate which Charter §5.1 row covers the decision class.
5. If the decision requires a public comment period, open a
   companion Discussion in the
   [RFC category](https://github.com/Agent-Threat-Rule/agent-threat-rules/discussions/categories/rfc)
   at the same time.

The next meeting agenda will pick up open `tsc-agenda` issues. The
agenda is published 48 hours before the meeting per Charter §6.2.

## 7. Time Commitment

A reasonable estimate of monthly time commitment:

| Activity | Estimate |
|----------|---------|
| Bi-weekly meeting attendance | 60 minutes / month |
| PR review (TSC-scope only) | 90–120 minutes / month |
| Mailing list and Discussions | 30 minutes / month |
| Asynchronous vote response | 15 minutes / month |
| Total | 3–4 hours / month |

Significant standards-body submissions, IANA registrations, or
RFC-adoption pushes are project events that may temporarily increase
this load. The TSC will be informed in advance.

## 8. BDFL Office Hours (First 30 Days)

For the first thirty days after admission, the BDFL offers a
once-weekly 30-minute office-hour slot to walk through any of the
following on request:

- Conformance Suite internals
- Threat Cloud ingestion pipeline
- Rule authoring conventions and the quality gate
- Standards-body submission status (IETF, IANA, NIST OSCAL)
- Trademark policy enforcement workflow

Email the BDFL to schedule. After thirty days, ad hoc office-hour
requests remain available but on best-effort scheduling.

## 9. Resources

| Resource | Where |
|----------|-------|
| Glossary | [docs/glossary.md](docs/glossary.md) (forthcoming) |
| Minutes template | [meetings/TEMPLATE.md](meetings/TEMPLATE.md) (latest version; quarter-archived under `meetings/YYYY-QN/`) |
| Agenda template | [meetings/AGENDA-TEMPLATE.md](meetings/AGENDA-TEMPLATE.md) |
| Decisions log | [meetings/DECISIONS.md](meetings/DECISIONS.md) |
| Brand assets | [BRAND.md](BRAND.md) |
| Numbering registry | [GOVERNANCE.md §ATR Numbering Authority](GOVERNANCE.md) |

---

<div align="center">

[TSC-CHARTER.md](TSC-CHARTER.md) · [SPEC.md](SPEC.md) ·
[GOVERNANCE.md](GOVERNANCE.md) · [BRAND.md](BRAND.md)

</div>
