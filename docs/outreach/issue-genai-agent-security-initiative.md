# GitHub Issue — GenAI-Security-Project/GenAI-Agent-Security-Initiative

**Status:** draft v1
**Target repo:** https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative
**Issue type:** Discussion / Community Contribution

---

## Title

`Community contribution: ATR (Agent Threat Rules) — open detection-rule corpus mapped 10/10 to Agentic Top 10`

---

## Body

Hi Initiative maintainers — opening this as a community contribution discussion rather than a feature request.

### Context

I maintain **[ATR (Agent Threat Rules)](https://github.com/Agent-Threat-Rule/agent-threat-rules)** — an MIT-licensed, open detection-rule corpus for AI agent threats. ATR was already merged into the Agentic-AI-Top10 attack-example collection via [precize/Agentic-AI-Top10-Vulnerability#14](https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14), so some of you may already be familiar with it. Posting here to consolidate the relationship between ATR and this Initiative explicitly.

### What ATR is (1 paragraph)

ATR is to AI agent security what Sigma rules are to SIEM and YARA rules are to malware detection — a YAML rule format with regex matching, behavioral fingerprinting, LLM-as-judge tier, and explicit mappings to OWASP Agentic Top 10, OWASP LLM Top 10, SAFE-MCP, and MITRE ATLAS. The rules are the standard; the engines (TS / Python) are reference implementations. Cisco AI Defense and Microsoft Agent Governance Toolkit both ship ATR rules in production.

### Numbers, for context

- **320 rules** across 10 attack categories
- **OWASP Agentic Top 10: 10/10 categories** covered ([mapping](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/OWASP-MAPPING.md))
- **SAFE-MCP: 78/85 (91.8%)** ([mapping](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/SAFE-MCP-MAPPING.md))
- **96,096 real-world agent skills scanned**, 751 confirmed malware ([wild scan report](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/research/openclaw-malware-campaign-2026-04.md))
- **External benchmarks:** 97.1% recall on NVIDIA Garak, 100% recall on SKILL.md, 99.6% precision on PINT
- **Paper:** [doi:10.5281/zenodo.19178002](https://doi.org/10.5281/zenodo.19178002)

### What I'm proposing

This is meant to be open-ended — happy to do whichever subset is useful:

- [ ] **Reference ATR from this Initiative's docs** — at least as one example of community-driven detection coverage for the Agentic Top 10. Detection-rule layers are explicitly not in the Top 10's scope, but readers consistently ask "OK, how do I detect these?" — ATR answers that.
- [ ] **Contribute attack reproducers** — every ATR rule has test cases. We can submit them to the Initiative as additional Agentic Top 10 examples (extending what PR #14 started).
- [ ] **Wild-scan dataset for Initiative research** — 96K-skill scan results are available under the same MIT license; useful for empirical Top 10 prevalence analysis.
- [ ] **Q3 AI Security Solutions Landscape** — if the right path is for the Initiative to nominate or shepherd entries, would appreciate guidance on the process. We couldn't find a public submission repo.
- [ ] **Community call talk** — 15 min on what 96K skills + 666 Garak jailbreaks looks like at the rule-detection layer. Useful to ground Top 10 v.next in real telemetry.
- [ ] **Anything else the Initiative needs.** Volunteer rule contributors, evidence for upcoming Top 10 revisions, etc.

### What ATR is not asking for

- Endorsement / branding
- Exclusivity
- Commercial benefit (ATR has no commercial product; rules stay MIT)

### Prior contribution

- [precize/Agentic-AI-Top10-Vulnerability#14](https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14) — full vulnerability mapping merged
- [OWASP/www-project-top-10-for-large-language-model-applications#814](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/pull/814) — pending review

Thanks for the work this Initiative has done. The Agentic Top 10 is the single most-referenced taxonomy in ATR's contributor onboarding.

---

## Pre-post checklist

- [ ] Confirm the repo `GenAI-Security-Project/GenAI-Agent-Security-Initiative` accepts external issues (some OWASP repos are read-only; in that case post on the related `GenAI-LLM-Top10` discussions or the genai.owasp.org community Slack)
- [ ] Check existing issues for similar contribution threads — link/reply rather than open new if one exists
- [ ] Cross-link to PR #14 from the issue body to establish prior good-faith contribution
- [ ] Assign appropriate labels if available (`community-contribution`, `discussion`, `landscape`)
- [ ] Don't @-mention maintainers individually — let the issue route organically
- [ ] Watch the issue; respond within 24h to any clarifying question
