# Email — OWASP Agentic Security Initiative (v3, ready to send)

**Channel:** email
**To:** Initiative co-leads
**Cc:** none on first contact
**Send window:** Tuesday 10–11am US Pacific
**Format:** plain text, no HTML signature

---

**Subject:** ATR — Q3 Landscape inclusion under Test & Evaluate (Cisco AI Defense + Microsoft AGT both ship our rules)

---

Hi [first names],

I maintain ATR (Agent Threat Rules). Two of the vendors already in your Q2 2026 Agentic Landscape — **Cisco AI Defense** and **Microsoft Agent Governance Toolkit** — ship ATR rules in production ([Cisco PR #79](https://github.com/cisco-ai-defense/skill-scanner/pull/79), [Microsoft PR #908](https://github.com/microsoft/agent-governance-toolkit/pull/908), both merged). ATR is the upstream detection-rule corpus they consume. The Q3 Landscape should reflect that the corpus exists as its own entry under Test & Evaluate, not only as a hidden dependency under their cells.

**The asset, in numbers:**

- 320 MIT-licensed detection rules across 10 categories
- 10/10 Agentic Top 10 coverage ([OWASP-MAPPING.md](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/OWASP-MAPPING.md))
- SAFE-MCP 78/85 (91.8%)
- **96,096 real-world skills scanned** — OpenClaw + Skills.sh + Hermes + ClawHub
- **751 confirmed malware actors discovered**, including 3 coordinated threat groups on OpenClaw mass-publishing poisoned Solana / Workspace / image-gen skills with C2 reverse shells ([report](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/research/openclaw-malware-campaign-2026-04.md))
- 97.1% recall on NVIDIA Garak (666 in-the-wild jailbreaks); 100% recall on the SKILL.md benchmark (498 labeled)
- 14ms avg scan latency, 5-tier detection, 4 export formats (SARIF, Splunk, Elastic, generic regex)
- Peer-reviewed paper: Pan, Y. (2026). [doi:10.5281/zenodo.19178002](https://doi.org/10.5281/zenodo.19178002)
- Already merged into Agentic-AI-Top10 via [PR #14](https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14)

**Ask:** Q3 inclusion under Test & Evaluate (and arguably Operate, since the GitHub Action and MCP runtime adapter put rules in CI/CD and runtime paths too). What's the submission path? I couldn't find a public submission repo under [genai-security-project](https://github.com/genai-security-project). Happy to follow whatever process you use; if there isn't a written one yet, I'll draft a template you can reuse for future submitters.

**Offers, take any or none:**

- 15-min slot at the next OWASP GenAI community call on the 96K wild scan and 751 malware finding — actual telemetry from the field is rare in this space
- Q3 reviewer for other Test & Evaluate entries (I run external benchmarks; useful for sanity-checking detection claims)
- Joint OWASP/ATR advisory format for the next agent CVE we disclose

Best,
Yale Pan
github.com/Agent-Threat-Rule/agent-threat-rules
[contact]

---

## Why this frame works

- **First sentence does the heavy lifting** — Cisco + Microsoft are not "social proof," they are *the same vendors already in your landscape*. That reframes inclusion from "please consider us" to "the landscape currently undersells the upstream."
- **Numbers, not adjectives** — every claim is verifiable in 30 seconds.
- **96K scan + 751 actors is the moat** — no other landscape entry has this. Lead with what's unique, not what's common.
- **Single direct ask: Q3 inclusion.** Specific, decisively answerable, frames as inclusion request, not feature request.
- **Offers come last and are optional** — they're sweeteners, not the substance.

## Pre-send checklist

- [ ] Look up co-lead names (genai.owasp.org/initiatives/agentic-security-initiative/) — never "Hi team"
- [ ] Confirm both PR #79 and PR #908 still resolve as merged
- [ ] Confirm 96K / 751 / 97.1% match latest scan
- [ ] Tuesday 10–11am US Pacific
- [ ] Plain text, no signature image, no Calendly link

## Reply playbook

| Reply | Response |
|---|---|
| "Send the submission" | Same-day deliver; one-pager + repo + paper. Treat it as the only thing that matters that day. |
| "What's your link to Cisco / Microsoft?" | Send the merged-PR diff URLs immediately. Offer to introduce their security teams. |
| "We're full for Q3, try Q4" | Accept gracefully; ask what would strengthen the Q4 submission. |
| Silence (10d) | Single follow-up with one new fact (e.g. "IBM mcp-context-forge just opened review on our PR #4109" — only if true). |
| "Not aligned with our criteria" | Ask what the criteria are. If genuine mismatch, accept; if vague, push politely once. |
