# Email — OWASP Agentic Security Initiative

**Status:** draft v1 (see analysis section in this doc before sending)

---

**To:** OWASP GenAI Agentic Security Initiative co-leads
**Cc:** `contribute.genai@owasp.org` (verify; otherwise drop)
**Subject:** ATR — open agent-threat detection corpus, already cited in Agentic Top 10 PR #14 — Q3 landscape consideration + happy to contribute upstream

---

Hi [co-lead names],

I'm Yale Pan, maintainer of **ATR (Agent Threat Rules)** — an MIT-licensed open detection-rule corpus for AI agent threats (the Sigma / YARA equivalent for agents). Writing because ATR was merged into Agentic-AI-Top10 via [PR #14](https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14) earlier this year, and I'd like to (a) keep contributing upstream and (b) raise ATR for consideration in the Q3 2026 *AI Security Solutions Landscape for Agentic AI* under Test & Evaluate.

**Why ATR is relevant to the Initiative's work:**

- **10/10 Agentic Top 10 categories covered** — full mapping in [docs/OWASP-MAPPING.md](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/OWASP-MAPPING.md). Every category has at least one rule with reproducer test cases.
- **Production adoption** — Cisco AI Defense ships 34 ATR rules in their official skill-scanner ([PR #79](https://github.com/cisco-ai-defense/skill-scanner/pull/79)); Microsoft Agent Governance Toolkit imports ATR rules into PolicyEvaluator ([PR #908](https://github.com/microsoft/agent-governance-toolkit/pull/908)).
- **Empirical evidence** — 96,096 real-world agent skills scanned across OpenClaw / Skills.sh / Hermes / ClawHub, **751 confirmed malware** (3 coordinated threat actors mass-publishing poisoned Solana / Workspace / image-gen skills, including a base64 reverse shell to C2 IP `91.92.242.30`). Full report: [openclaw-malware-campaign-2026-04.md](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/research/openclaw-malware-campaign-2026-04.md).
- **External benchmarks** — 97.1% recall on NVIDIA Garak (666 in-the-wild jailbreaks), 100% recall on the SKILL.md benchmark (498 labeled samples), 99.6% precision on Invariant Labs PINT.
- **Peer-reviewed paper** — Pan, Y. (2026). [doi:10.5281/zenodo.19178002](https://doi.org/10.5281/zenodo.19178002).

**What I'm asking:**

1. **Q3 Landscape consideration** — happy to send a one-page submission package or fill any form you use. Submission notes: [docs/outreach/owasp-landscape-submission.md](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/outreach/owasp-landscape-submission.md).
2. **Process pointer** — I couldn't find a public submission repo under [genai-security-project](https://github.com/genai-security-project) (10 repos, none for the Landscape). What's the canonical path? I want to follow it correctly.
3. **Volunteer time, irrespective of (1)** — I can review Q3 Landscape entries in the Test & Evaluate column for technical accuracy, contribute additional Agentic Top 10 attack examples, or present 15 min on the 96K wild scan at the next community call. Whichever helps the Initiative most.

ATR is community-driven and stays MIT — no commercial conflict, no integration sales. If the Initiative would rather I just keep submitting upstream rule contributions and skip the landscape question, that's fine too. I want to be useful, not transactional.

Thanks for the work the Initiative has done — the Agentic Top 10 has been the most-cited reference in our paper and the most-requested mapping target from rule contributors.

Best,
Yale Pan
Maintainer, Agent Threat Rules
https://github.com/Agent-Threat-Rule/agent-threat-rules
[contact]

---

## Pre-send checklist

- [ ] Verify `contribute.genai@owasp.org` is a real address; otherwise remove
- [ ] Look up Initiative co-lead names from genai.owasp.org/initiatives/agentic-security-initiative/ and address by name
- [ ] Confirm PR #14 is merged (it is) and the link resolves
- [ ] Check that the openclaw report file path is correct after any repo renames
- [ ] Send Tue/Wed 9–11am their local timezone (likely US Pacific or Central Europe)
- [ ] Plain text, no HTML signature bloat
