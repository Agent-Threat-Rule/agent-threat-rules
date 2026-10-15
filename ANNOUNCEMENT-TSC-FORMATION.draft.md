<div align="center">

<img alt="ATR — Agent Threat Rules" src="assets/logo-light.png" width="320" />

# ATR Forms Inaugural Technical Steering Committee

[![Draft](https://img.shields.io/badge/document-DRAFT-orange?style=flat-square)](#)
[![Cisco](https://img.shields.io/badge/Cisco_AI_Defense-419_rules_merged-2ea44f?style=flat-square)](https://github.com/cisco-ai-defense/skill-scanner)
[![MISP](https://img.shields.io/badge/MISP-336_rules_merged-2ea44f?style=flat-square)](https://github.com/MISP/misp-galaxy)

</div>

---

**DRAFT — Publish 24 hours after written acceptance from all three
inaugural seat holders. Do not publish before written acceptance is
on file.**

---

## Summary

The Agent Threat Rules (ATR) project today seats its inaugural
Technical Steering Committee, transitioning the standard from a
single-maintainer BDFL model to a three-seat multi-organization
governance body. The seats are held by maintainers from the ATR
project, Cisco AI Defense, and MISP / CIRCL — representing the open
standard, the largest production ATR adopter, and the leading
open-source threat-intelligence ecosystem, respectively.

This change activates the governance roadmap committed in
[GOVERNANCE.md §v1.1](GOVERNANCE.md) and is the prerequisite for the
project's planned Spec v1.0 advancement and the formal Internet-Draft
submission queued at IETF.

## The Founding Three

| Seat | Holder | Organization | Mandate basis |
|------|--------|--------------|---------------|
| Maintainer | Kuan-Hsin Lin (林冠辛, @eeee2345) | ATR Project | BDFL, transitional |
| Industry | [Vineeth Sai — placeholder pending acceptance] | Cisco AI Defense | Maintainer of `cisco-ai-defense/skill-scanner`, ships ATR rules in production |
| Community / Threat-Intel | [Alexandre Dulaunoy — placeholder pending acceptance] | MISP / CIRCL | Maintainer of `MISP/misp-galaxy` and `MISP/misp-taxonomies`, where ATR is the rule-ID vocabulary |

The seats are governed by [TSC-CHARTER.md](TSC-CHARTER.md). The Charter
defines voting thresholds (2-of-3 majority for rule decisions and
spec amendments, 3-of-3 supermajority for charter changes), public
meeting cadence (bi-weekly, minutes published within seven days),
conflict-of-interest policy, term length (3 / 2 / 3 years staggered),
and the expansion path to a five-seat Committee in v1.2 (Q1 2027) that
adds an academic seat and a government / standards-body seat.

## Why now

At the time of TSC formation:

- 425 rules in the official corpus, MIT-licensed
- 7 organizations have merged ATR rule packs (Microsoft Agent
  Governance Toolkit, Cisco AI Defense, MISP, NIST AI RMF OSCAL
  catalog, OWASP Agent Security Regression Harness, Gen Digital
  Sage, plus 4 awesome-list inclusions)
- 13 external PR merges across these organizations
- Benchmark figures are kept in README §8 Evaluation, reported per
  lane with their caveats, and are not repeated here so they cannot
  go stale
- Conformance Test Suite v1.0 published with 103 true-positive, 103
  true-negative, and 20 edge-case fixtures
- IETF Internet-Draft `draft-lin-atr-core-00` prepared and rendered
  via xml2rfc; submission to datatracker imminent

Per [TSC-CHARTER.md §3](TSC-CHARTER.md), the project is now seating a
Founding Three Technical Steering Committee. This is an accelerated
formation path relative to the earlier
[docs/BDFL-charter.md](docs/BDFL-charter.md) thresholds (which the
Charter supersedes for the v1.1 phase), reflecting the velocity of
external adoption.

## What changes for the community

Nothing changes immediately for end users, rule contributors, or
adopters. Specifically:

- The MIT license remains irrevocable. The TSC has no authority to
  relicense.
- Rule IDs already assigned remain assigned. The numbering namespace
  is unchanged.
- The Conformance Test Suite and the ATR-Compatible mark continue
  under the published [TRADEMARK.md](TRADEMARK.md) policy.
- The Threat Cloud pipeline, the npm and PyPI packages, the GitHub
  Marketplace action, and the OSCAL catalog all continue to ship on
  the existing cadence.

The first decisions reserved for the new TSC are the advancement of
[SPEC.md](SPEC.md) from Draft to Final after the public comment
window, and the formal IETF submission of `draft-lin-atr-core-00`.

## Quotes

**Kuan-Hsin Lin, BDFL and Maintainer Seat:**

> [PLACEHOLDER — one-sentence quote on the significance of the
> three-org composition and the project's commitment to remaining
> vendor-neutral.]

**[Industry Seat holder]:**

> [PLACEHOLDER — provided by seat holder upon acceptance.]

**[Community / Threat-Intel Seat holder]:**

> [PLACEHOLDER — provided by seat holder upon acceptance.]

## How to participate

- Observe the bi-weekly public meeting — subscribe to the
  [public calendar](https://calendar.google.com/calendar/embed?src=c_a2dd390e73cd0b26fb32fd145173389ccbec312083436e3c88f7dabb35d31592%40group.calendar.google.com) or its
  [iCal feed](https://calendar.google.com/calendar/ical/c_a2dd390e73cd0b26fb32fd145173389ccbec312083436e3c88f7dabb35d31592%40group.calendar.google.com/public/basic.ics). Each event carries the Google Meet link.
- Open a GitHub Issue tagged `tsc-agenda` to put an item before the
  TSC.
- Subscribe to the public mailing list
  [`atr-tsc@agentthreatrule.org`](https://groups.google.com/a/agentthreatrule.org/g/atr-tsc).
- File a rule PR through the standard contributor workflow.
- Track open RFC comment periods in the
  [GitHub Discussions RFC category](https://github.com/Agent-Threat-Rule/agent-threat-rules/discussions/categories/rfc).

## Contact

- Project: [Agent-Threat-Rule/agent-threat-rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
- Web: [agentthreatrule.org](https://agentthreatrule.org)
- BDFL: adam@agentthreatrule.org

---

<div align="center">

[TSC-CHARTER.md](TSC-CHARTER.md) · [GOVERNANCE.md](GOVERNANCE.md) · [SPEC.md](SPEC.md)

</div>
