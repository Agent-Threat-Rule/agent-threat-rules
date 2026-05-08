# Jim Reavis Outreach (v2) — Public Comment Primary, DM Fallback

**Strategy change vs. v1:** lead with a **public LinkedIn comment** on Jim Reavis's CSAI announcement post, not a DM. Public comment surfaces ATR to the entire CSAI team watching the announcement, costs Jim nothing to engage, and creates a referenceable artifact for the eventual DM (if needed).

**Source post:** https://lnkd.in/e-g_wq7R (CSAI Foundation announcement, 2026-05-02±)
**Jim's LinkedIn:** https://www.linkedin.com/in/jimreavis/

---

## Step 1: Public Comment (primary)

Post directly under Jim's announcement post. Plain text, no emoji.

> Big deal that CSAI is now a CNA — agent and MCP CVE coordination is genuinely missing. We've been routing MCP disclosures (CVE-2026-24307, -28363, -0628 so far) through MITRE root, with 751 active malware actors still un-CVE'd from a 96K-skill wild scan we ran across OpenClaw, Skills.sh, Hermes, and ClawHub. Happy to brief CSAI's CNA team on the disclosure pipeline — ATR rules are MIT, already shipping in Cisco AI Defense and Microsoft Agent Governance Toolkit. github.com/Agent-Threat-Rule/agent-threat-rules

**Char count:** ~580. Single ask = "brief CSAI's CNA team." Single offer = the disclosure pipeline + dataset.

### Why this works

- **Opens by amplifying his announcement** (CNA is genuinely missing) — gives Jim social value to engage rather than a calendar load
- **One specific unpublished fact** ("751 un-CVE'd actors") — the kind of line a CEO forwards internally before reading the full thread
- **Ask is scoped to the team he just announced** (CNA), not to him personally — easier yes, easier delegation
- **Public** means CSAI staff watching the announcement see ATR before Jim has to forward anything; auto-triggers internal awareness
- **Production-deployment proof** (Cisco + Microsoft) does the credibility work in 8 words

### Pre-post checklist

- [ ] Verify the LinkedIn post is still pinned / recent (within 7 days). If older than 7 days, comment is half-buried — use DM instead.
- [ ] Confirm CVE numbers are real and assigned (don't fabricate)
- [ ] Confirm "751" matches latest scan numbers
- [ ] Post Tue–Thu 9–11am US Pacific (CSA staff are typically US-based)
- [ ] No emoji, no "Excited to share", no "Reach out anytime"
- [ ] Single shortlink at the end — repo only, not Calendly

---

## Step 2: DM (only if Step 1 doesn't trigger response in 7 days)

If the public comment is read but generates no CSAI-side outreach within 7 days, send the DM below. The DM **references the public comment** — this is the key move; it shows you're not spraying.

### DM Variant — RECOMMENDED

> Hi Jim — followed up on your CSAI post a few days back with a comment about the agent/MCP CVE pipeline. In case it got buried: ATR is the open detection corpus Cisco AI Defense and Microsoft AGT both ship in production, and we've sat on 751 un-CVE'd malware actors from a 96K-skill wild scan that look like a natural fit for the new CNA. Worth a 20-min intro to whoever leads CSAI's CNA work?
>
> 1-pager: github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/outreach/csai-partnership.md

**Char count:** ~620. Hook = "you saw the comment, here's the action." Single ask = "intro to CNA lead."

### Why the DM references the public comment

- Signals you respect his time (you tried public first, didn't barge into DMs)
- Creates a reference URL CSAI staff can click
- Differentiates from the 50 vendor DMs he gets that week — none of them have a public comment to point to
- Lets Jim forward the DM to the CNA lead with one click ("see this comment + DM, please reply")

---

## Step 3 (fallback): if neither works

If both Step 1 and Step 2 produce silence after 14 days total:

1. **Find a second-degree LinkedIn connection** — most likely route via Cisco / Microsoft contacts who already deploy ATR
2. **Email CSA contact form** with subject: `CNA collaboration — open detection corpus + 751 un-CVE'd MCP malware actors`
3. **DO NOT** post a third LinkedIn message. Three is spam.

---

## What NOT to do

- Don't pitch AARM in the first contact — that's Step 4 work, after CNA contact lands
- Don't lead with "Cisco and Microsoft already ship our rules" as a brag — it works only when framed as "production-grade source" for CSAI's pipeline
- Don't ask Jim for a 30-min call — CEO calendar is the worst possible ask
- Don't send a Calendly link in v1 — feels presumptuous before relationship exists
- Don't attach the csai-partnership.md until they reply — it's a 200-line doc and will not be read cold

---

## Reply playbook

| Reply pattern | Response |
|---|---|
| Jim comments back publicly | Reply concisely, offer to email CNA team directly with no further intro needed |
| CSAI team member DMs you | Move to email immediately; share csai-partnership.md and propose 3 calendar slots |
| Jim DMs "send to X" | Email X same-day, cc Jim once, then drop Jim from the thread |
| 7-day silence on public comment | Move to Step 2 (DM with reference) |
| 14-day total silence | Move to Step 3 (second-degree intro / contact form) |
| "Not a fit" | Thank, ask if any CSA working group has overlap, never re-pitch |
