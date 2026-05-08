# Email — OWASP Agentic Security Initiative (v2, ready to send)

**Channel:** email
**To:** Initiative co-leads (look up names from genai.owasp.org/initiatives/agentic-security-initiative/)
**Cc:** none on first contact
**Send window:** Tuesday 10–11am US Pacific
**Format:** plain text, no HTML signature

---

**Subject:** Volunteering as Q3 Landscape reviewer for Test & Evaluate column — and one ATR submission question

---

Hi [first names],

I maintain ATR (Agent Threat Rules) — you've already merged ATR's mapping into Agentic-AI-Top10 via [PR #14](https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14), so this isn't a cold intro. Two things:

**1. Volunteering for Q3 Landscape review.** Test & Evaluate is the column I can usefully review — I run external benchmarks on detection-rule corpora (NVIDIA Garak, Invariant Labs PINT, SKILL.md), and we've scanned 96K real-world agent skills with 751 confirmed malware actors. If a Q3 entry claims "detects prompt injection" or "covers Agentic Top 10," I can sanity-check that against ground truth without needing the vendor's product. Happy to take 5–10 entries off your plate.

**2. One process question.** ATR itself fits Test & Evaluate (rule corpus + benchmarks) and I'd like to submit it for Q3. I couldn't find a public submission repo under [genai-security-project](https://github.com/genai-security-project) — what's the canonical path? If there isn't one yet, happy to draft a template that future submitters can use.

For context on ATR (skip if you saw PR #14): MIT-licensed, 320 rules, 10/10 Agentic Top 10 mapping ([docs/OWASP-MAPPING.md](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/OWASP-MAPPING.md)), ships in production at Cisco AI Defense ([PR #79](https://github.com/cisco-ai-defense/skill-scanner/pull/79)) and Microsoft Agent Governance Toolkit ([PR #908](https://github.com/microsoft/agent-governance-toolkit/pull/908)). Paper: [doi:10.5281/zenodo.19178002](https://doi.org/10.5281/zenodo.19178002).

Either of (1) or (2) is fine on its own. (1) is the higher-leverage one for the Initiative.

Best,
Yale Pan
github.com/Agent-Threat-Rule/agent-threat-rules
[contact]

---

## Why this version works

- **Frame:** "I'm here to help" before "I want something." Volunteers respond to peers, not applicants.
- **Single ask each:** review 5–10 entries (specific, scoped) + one process question (low cost).
- **PR #14 reference up front** establishes you're not a cold pitch.
- **No "congrats on Q2" filler.** Specific facts only.
- **(1) before (2)** is deliberate — it makes (2) feel like a postscript.
- **"Happy to draft a template"** turns a request into another offer.

## Pre-send checklist

- [ ] Look up actual co-lead names — do not send "Hi team"
- [ ] Confirm PR #14 link still resolves
- [ ] Send Tuesday 10–11am US Pacific
- [ ] Plain text, no signature image, no calendly link in v1
- [ ] If no reply in 10 days, follow up with one new fact (not a re-ask): "Microsoft AGT just merged 38 more ATR rules — wanted to keep you in the loop."

## Reply playbook

| Reply | Response |
|---|---|
| "Yes, here are 5 entries to review" | Deliver fast (48h), excellent quality. This is the relationship. |
| "We don't need reviewers but submit ATR via X" | Follow X path. Mention you'd still like to volunteer next quarter. |
| "What's the submission template look like?" | Send the template same-day. Don't make them ask twice. |
| Silence (10d) | Single follow-up with new fact, not a re-ask. |
| "Not a fit" | Thank, ask if any other Initiative working group needs the help. |
