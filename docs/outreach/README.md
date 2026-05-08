# ATR Outreach Playbook

This directory holds outreach drafts for OWASP and CSAI Foundation. Each file is **send-ready** with a pre-send checklist and reply playbook. Read this README before firing anything — sequencing matters more than draft quality.

## The artifacts

| File | Channel | Recipient | Status |
|---|---|---|---|
| [`dm-jim-reavis-linkedin.md`](dm-jim-reavis-linkedin.md) | LinkedIn public comment + DM fallback | Jim Reavis (CEO, CSA) | v2, ready |
| [`issue-genai-agent-security-initiative.md`](issue-genai-agent-security-initiative.md) | GitHub PR (issue as fallback) | OWASP GenAI-Agent-Security-Initiative maintainers | v2, ready |
| [`email-owasp-agentic-initiative.md`](email-owasp-agentic-initiative.md) | Email | OWASP Agentic Security Initiative co-leads | v2, ready |
| [`csai-partnership.md`](csai-partnership.md) | Reference doc (sent on reply) | CSAI Foundation technical leads | ready |
| [`owasp-landscape-submission.md`](owasp-landscape-submission.md) | Reference doc (sent on reply) | OWASP Landscape reviewers | ready |

## Send sequence

**Do not fire all three on the same day.** Each step builds reference for the next.

| Day | Action | Why this order |
|---|---|---|
| **Day 1** | Post public LinkedIn comment on Jim Reavis's CSAI announcement | Lowest cost, highest visibility, surfaces ATR to CSAI staff before any DM |
| **Day 3** | Open PR (not issue) on `GenAI-Agent-Security-Initiative` with 5 example rules | Establishes documented contribution before any landscape ask |
| **Day 7** | Send OWASP email — referencing the Day-3 PR | Email arrives with a recent-contribution reference, not cold |
| **Day 10–14** | Follow-ups per individual playbooks if no response | Single bumps with new facts only — never re-asks |

## Why this sequence

- **LinkedIn first** because public comments are zero-cost reciprocity — you amplify Jim's announcement; if he engages, that's a free signal. If he doesn't, you've lost nothing and you have a public artifact to reference in Step 2's DM.
- **PR before email** because OWASP volunteers respond to "I just contributed" much better than "I'd like to be considered." The email gets to say "you can see my recent PR at #X" instead of "trust me, I'd be a good contributor."
- **Email last** because it has the highest stakes (real human time commitment) and benefits most from accumulated reference signal.

## What success looks like (90 days)

| Outcome | Probability | Indicator |
|---|---|---|
| LinkedIn comment gets CSAI staff reply | ~30% | Reply within 7 days |
| OWASP PR merges | ~50% | Merged or in-review within 14 days |
| OWASP email yields review-volunteer slot | ~40% | Reply within 10 days |
| ATR appears in Q3 2026 OWASP Solutions Landscape | ~25% | Q3 publication mentions ATR |
| CSAI ↔ ATR formal collaboration (CNA / AARM ref impl) | ~20% | LOI or joint blog post |

The realistic-good outcome is 2–3 of these landing. Don't optimize for all 5.

## What NOT to do

- **Don't send all three simultaneously.** It looks spray-and-pray and removes the option to reference earlier moves.
- **Don't @-mention OWASP maintainers individually.** It pressures volunteers and triggers defensiveness.
- **Don't pitch AARM to Jim in v1.** AARM is the second conversation, not the first. CNA is the entry.
- **Don't attach long docs cold.** `csai-partnership.md` and `owasp-landscape-submission.md` are reference docs sent **after** a reply, not in the opener.
- **Don't follow up with re-asks.** Follow up with **new facts** ("Microsoft AGT just merged 38 more rules") — never "did you see my email?"
- **Don't post a third LinkedIn message** after public comment + DM. Three messages is spam, full stop.

## Things to verify before sending anything

- [ ] OWASP Agentic Security Initiative co-lead names (genai.owasp.org/initiatives/agentic-security-initiative/)
- [ ] `contribute.genai@owasp.org` exists (currently unverified — drop the cc if uncertain)
- [ ] `GenAI-Security-Project/GenAI-Agent-Security-Initiative` accepts external PRs (check `.github/CONTRIBUTING.md`)
- [ ] Jim Reavis's LinkedIn post is still recent (<7 days from send) — if older, skip public comment, go straight to DM
- [ ] CVE numbers in the LinkedIn comment (`CVE-2026-24307, -28363, -0628`) are real, assigned, and yours to disclose
- [ ] "751 confirmed malware" / "96K skills" numbers match latest scan
- [ ] All linked file paths in drafts resolve (no 404s after recent renames)

## After-send hygiene

- Log every send (date, channel, recipient, draft version) in your own tracker
- Set a 14-day calendar reminder for follow-up decisions
- Don't read tea leaves — replies arrive on their schedule, not yours
- Each reply gets a same-day acknowledgment, even if the substantive answer takes longer

## When this playbook is wrong

This playbook assumes ATR is operating from a **strong, peer position** — production deployments at Cisco/Microsoft, peer-reviewed paper, real wild-scan data. If any of those weakens (e.g. Cisco rolls back, scan numbers shrink), revise the playbook *first*, then send. Outreach against weakened evidence is worse than no outreach.
