# MCP Skill Threat Tracker

Tracking security findings from ecosystem-wide MCP skill audits.
This file is the working document for public disclosure and ATR rule development.

**Process:** Scan → Verify → Notify author (90 days) → Public disclosure → ATR rule

---

## Disclosure Policy

| Stage | Action | Timeline |
|-------|--------|----------|
| 1. Discovery | ATR engine scan + manual verification | Day 0 |
| 2. Private notification | Contact author via GitHub issue (private if possible) | Day 0-7 |
| 3. Waiting period | Author has time to fix | 90 days |
| 4. Public disclosure | Add to this tracker, publish report | Day 90 (or after fix) |
| 5. ATR rule | Create detection rule if pattern is generalizable | After disclosure |

**Rules:**
- Never disclose before notifying the author
- If author fixes within 90 days, mark as RESOLVED (positive coverage)
- If author is unresponsive after 90 days, disclose with UNPATCHED status
- If actively exploited in the wild, disclose immediately (0-day exception)

---

## Status Legend

| Status | Meaning |
|--------|---------|
| SCANNING | Under automated scan, not yet verified |
| VERIFIED | Manually confirmed, preparing notification |
| NOTIFIED | Author contacted, waiting for response |
| FIXING | Author acknowledged, fix in progress |
| RESOLVED | Author fixed, safe to use |
| UNPATCHED | 90 days passed, no fix |
| WONTFIX | Author declined to fix |

---

## Findings

<!--
Template for new entries:

### [SKILL-XXXX] skill-name
| Field | Value |
|-------|-------|
| **Skill** | `skill-name` |
| **GitHub** | https://github.com/org/repo |
| **npm** | `package-name` (if applicable) |
| **Stars** | N |
| **Category** | browser-automation / database / ai-service / etc. |
| **Status** | SCANNING / VERIFIED / NOTIFIED / FIXING / RESOLVED / UNPATCHED |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW |
| **Discovered** | 2026-MM-DD |
| **Notified** | 2026-MM-DD (or "pending") |
| **Deadline** | 2026-MM-DD (notification + 90 days) |
| **Resolved** | 2026-MM-DD (or "pending") |

**Finding:**
Brief description of the security issue.

**Impact:**
What an attacker could do by exploiting this.

**Evidence:**
```
Exact payload, log output, or scan result that proves the issue.
```

**ATR Rule:**
- [ ] Pattern generalizable? (applies to more than just this skill)
- [ ] Rule ID: ATR-2026-XXX (or "not applicable")
- [ ] Rule PR: #XX (or "pending")

**Disclosure:**
- [ ] Author notified via: (GitHub issue / email / DM)
- [ ] Author response: (acknowledged / no response / declined)
- [ ] Public post: (link to blog/social post, or "pending")

---
-->

*No findings yet. Run `npx tsx scripts/crawl-mcp-registry.ts` then batch audit to populate.*

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total skills scanned | 0 |
| CRITICAL findings | 0 |
| HIGH findings | 0 |
| MEDIUM findings | 0 |
| Authors notified | 0 |
| Resolved by author | 0 |
| Unpatched (90d+) | 0 |
| ATR rules created | 0 |

*Last updated: 2026-03-14*

---

## Monthly Reports

| Month | Scanned | Findings | Resolved | Report Link |
|-------|---------|----------|----------|-------------|
| 2026-03 | — | — | — | (first scan pending) |

---

## How This Becomes a Post

When a finding reaches RESOLVED or UNPATCHED status:

**Resolved (positive):**
> "We scanned [skill-name] and found [issue]. The author fixed it within [N days].
> This skill is now safe to use. Here's what we found and how to check your own skills."

**Unpatched (warning):**
> "We found [issue type] in [skill-name] ([N stars, M downloads]).
> We notified the author on [date] but received no response after 90 days.
> If you use this skill, here's what you should know and how to protect yourself."

**Both formats include:**
- What the issue is (technical, but accessible)
- How we found it (ATR engine scan)
- How users can check their own skills (`npx agent-threat-rules init`)
- Link to the ATR rule (if applicable)
