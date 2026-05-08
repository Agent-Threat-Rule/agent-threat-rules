# ATR Outreach Playbook (v3)

This directory holds outreach drafts for OWASP and CSAI Foundation. Each file is **send-ready** with a pre-send checklist and reply playbook.

## Position

ATR is **not** an applicant. ATR is the production-grade open detection-rule corpus that:

- Cisco AI Defense and Microsoft Agent Governance Toolkit ship in production
- Has 320 rules, 10/10 OWASP Agentic Top 10 coverage, 91.8% SAFE-MCP
- Has scanned 96,096 real-world skills and discovered 751 active malware actors
- Achieves 97.1% recall on NVIDIA Garak; 100% recall on SKILL.md
- Has a peer-reviewed paper (Zenodo DOI)
- Is MIT licensed with no commercial conflict

These objective metrics beat ~half the entries currently on the OWASP Q2 2026 Agentic Landscape. Outreach is framed accordingly: **deal-making between peers**, not application for inclusion.

## The artifacts

| File | Channel | Recipient | Frame |
|---|---|---|---|
| [`dm-jim-reavis-linkedin.md`](dm-jim-reavis-linkedin.md) | LinkedIn public comment + DM fallback | Jim Reavis (CEO, CSA) | CNA pipeline handover deal |
| [`issue-genai-agent-security-initiative.md`](issue-genai-agent-security-initiative.md) | GitHub PR | Agentic Top 10 maintainers (precize repo first) | Detection Coverage appendix contribution |
| [`email-owasp-agentic-initiative.md`](email-owasp-agentic-initiative.md) | Email | OWASP Agentic Security Initiative co-leads | Q3 Landscape inclusion under Test & Evaluate |
| [`csai-partnership.md`](csai-partnership.md) | Reference doc — sent on reply | CSAI technical leads | Long-form integration spec |
| [`owasp-landscape-submission.md`](owasp-landscape-submission.md) | Reference doc — sent on reply | OWASP Landscape reviewers | Submission package |

## Send sequence

**Do not fire all three on the same day.** Each step compounds the next.

| Day | Action | Why this order |
|---|---|---|
| **Day 1** | Public LinkedIn comment on Jim Reavis's CSAI announcement | Lowest cost, highest visibility; surfaces ATR to CSAI staff; creates artifact to reference if DM is needed later |
| **Day 3** | Open Detection Coverage PR on `precize/Agentic-AI-Top10-Vulnerability` | Substantive doc-level contribution. PR #14 is already merged there, so this is a follow-up, not a cold contribution |
| **Day 7** | Email OWASP Agentic Security Initiative co-leads | Email arrives with two recent reference points (LinkedIn engagement + open PR) — not cold |
| **Day 12** | If Day 1 silent → DM Jim referencing the public comment | Single follow-up; one new fact, never a re-ask |
| **Day 14+** | If everything silent → second-degree intros, CSA contact form, follow-ups per individual playbooks | Single bumps with new facts only — never re-asks |

## Why this sequence

- **Public LinkedIn first** because public comments amplify Jim's announcement. He gets value before being asked. CSAI staff watching the post see ATR before any DM lands. If the comment fails, you have a public artifact to reference later.
- **PR before email** because OWASP volunteers respond to evidenced contribution far more than promised contribution. The email gets to say "you can see the PR I just opened" instead of "I'd be a good contributor."
- **Email last** because it has the highest stakes (real human time commitment) and benefits most from accumulated reference signal.

## Realistic outcome estimates (90 days)

| Outcome | Probability | Indicator |
|---|---|---|
| LinkedIn comment gets CSAI staff reply | 40% | Reply within 7 days |
| Detection Coverage PR merges | 60% | Merged or in-review within 14 days |
| OWASP email yields Q3 inclusion conversation | 55% | Reply within 10 days |
| ATR appears in Q3 2026 OWASP Solutions Landscape | 40% | Q3 publication mentions ATR |
| CSAI ↔ ATR formal collaboration (CNA disclosure pipeline live) | 30% | Joint disclosure or LOI within 90 days |

**Expected good outcome:** 3–4 of these landing. v3 estimates are higher than v2 because the deal-making frame matches ATR's actual position.

## What NOT to do

- **Don't send all three simultaneously.** Removes the option to reference earlier moves.
- **Don't @-mention OWASP maintainers individually.** Triggers defensiveness.
- **Don't pitch AARM to Jim in v1.** AARM is the second conversation; CNA is the entry.
- **Don't attach long docs cold.** `csai-partnership.md` and `owasp-landscape-submission.md` are reference docs for after a reply, not the opener.
- **Don't follow up with re-asks.** Follow up with **new facts** ("Microsoft just merged 38 more rules"). Never "did you see my email?"
- **Don't soften with "no pressure" / "happy to" / "if interested" / "would love to" / "excited to".** These phrases signal the offer isn't strong. The offer is strong.
- **Don't post a third LinkedIn message** after public comment + DM. Three is spam.
- **Don't ask CEOs for 30-min calendar time.** Ask for a delegation, an intro, or a yes/no.

## Pre-send verification

- [ ] OWASP Agentic Security Initiative co-lead names (genai.owasp.org/initiatives/agentic-security-initiative/)
- [ ] `GenAI-Security-Project/GenAI-Agent-Security-Initiative` and `precize/Agentic-AI-Top10-Vulnerability` accept external PRs
- [ ] Jim Reavis's CSAI announcement is recent (<7 days from send) — older means switch to DM-first
- [ ] CVE numbers (`CVE-2026-24307, -28363, -0628`) are real, assigned, and yours to disclose
- [ ] `751 confirmed malware` / `96K skills` / `Cisco PR #79 merged` / `Microsoft PR #908 merged` all current
- [ ] All linked file paths in drafts resolve

## After-send hygiene

- Log every send (date, channel, recipient, draft version) in your own tracker
- Set 14-day calendar reminder for follow-up decisions
- Each reply gets same-day acknowledgment, even if the substantive answer takes longer
- Don't read tea leaves — replies arrive on their schedule, not yours

## When this playbook is wrong

This playbook assumes ATR is operating from a **strong, peer position** — Cisco + Microsoft production deployments, peer-reviewed paper, 96K dataset. If Cisco rolls back, paper is retracted, scan numbers shrink, **revise the playbook before sending.** Confident outreach against weakened evidence is worse than no outreach.
