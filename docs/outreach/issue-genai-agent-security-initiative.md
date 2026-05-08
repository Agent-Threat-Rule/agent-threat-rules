# GenAI-Agent-Security-Initiative — PR (v3, ready to draft)

**Strategy change vs. v2:** v2 proposed copying 5 example rules — that signals "small project trying to get noticed" and the rules already exist upstream so the contribution adds no value. v3 is a **substantive doc-level contribution to the Agentic Top 10 itself**: a `Detection Coverage` appendix linking each ASI category to working community detection rules.

This makes ATR part of the Top 10's documented ecosystem rather than an example dump downstream.

**Target repo (primary):** https://github.com/precize/Agentic-AI-Top10-Vulnerability (where ATR PR #14 already merged — this is a follow-up, not a cold contribution)
**Target repo (secondary):** https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative
**Branch name:** `feat/detection-coverage-appendix`

---

## PR Title

`feat(docs): add Detection Coverage appendix mapping each ASI category to community detection rules`

---

## PR Body

PR #14 mapped ATR rules to each Agentic Top 10 category. This follow-up adds a **Detection Coverage** appendix to the main Top 10 doc so readers don't just learn what the threats are — they get a direct path to detect them.

### What's added

A new section `docs/detection-coverage.md` (linked from the main README) that for each ASI01–ASI10 category lists:

1. The threat description (1 line, links to existing canonical text)
2. **Primary detection rules** with severity and rule ID (currently from ATR, but the format accepts any contributor)
3. Reproducer test cases that confirm the rule fires
4. Exemptions / known false-positive patterns

Example excerpt for ASI01:

> ### ASI01: Agent Goal Hijack
>
> Hidden prompts and injection attacks that redirect agent behavior away from its intended goal.
>
> **Detection rules (community-contributed, MIT licensed):**
>
> | Rule ID | Title | Severity | Source |
> |---|---|---|---|
> | ATR-2026-001 | Direct Prompt Injection | CRITICAL | [agent-threat-rules](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/prompt-injection/ATR-2026-00001-direct-prompt-injection.yaml) |
> | ATR-2026-002 | Indirect Prompt Injection | CRITICAL | (same upstream) |
> | ATR-2026-003 | Jailbreak Attempt | HIGH | (same upstream) |
> | ATR-2026-091 | Nested Payload | HIGH | (same upstream) |
> | _your rule here_ | _open for community contributions_ | | |
>
> **Production deployments using these rules:** Cisco AI Defense skill-scanner ([34 ATR rules merged](https://github.com/cisco-ai-defense/skill-scanner/pull/79)), Microsoft Agent Governance Toolkit ([PR #908 merged](https://github.com/microsoft/agent-governance-toolkit/pull/908)).

…repeated for ASI02–ASI10.

### Why this is the right shape

- **Useful to every Top 10 reader.** "How do I detect this?" is the first question after "what is this?" Currently the doc has no answer.
- **Vendor-neutral.** The format accepts contributions from any detection-rule project, not only ATR. ATR is just the first to populate it because we have 10/10 mapping ready.
- **Production-grounded.** Every rule listed is in production at Cisco AI Defense and / or Microsoft AGT. That's not a hypothetical example.
- **Extensible.** Future contributors can add their rules under each category without restructuring.

### Provenance

- All 71 listed ATR rules are MIT-licensed (DCO-clean)
- ATR upstream maintains the rules — this doc references them by URL, not by copy
- Cisco PR #79 + Microsoft PR #908 already merged with these exact rules
- Scan dataset (96,096 real skills, 751 confirmed malware): [openclaw-malware-campaign-2026-04.md](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/research/openclaw-malware-campaign-2026-04.md)

### Not requesting

- ATR-specific badging, exclusivity, or commercial relationship
- This appendix names ATR because ATR is what populates it today — but the schema is open for any detection-rule project to contribute under

---

## Pre-open checklist

- [ ] Confirm `precize/Agentic-AI-Top10-Vulnerability` is still the canonical repo (it was for PR #14)
- [ ] Re-read PR #14's review thread to mirror tone and contribution style of what was previously accepted
- [ ] Verify each ATR rule URL resolves and the YAML parses
- [ ] Make the contribution-format paragraph (the "your rule here" placeholder) prominent — this is what makes it not look ATR-centric
- [ ] DCO sign-off on every commit
- [ ] Run repo's pre-commit hooks if any (markdownlint, link-check)
- [ ] Don't @-mention prior reviewers — let it route normally

## If this repo isn't the right venue

Open the same PR against `GenAI-Security-Project/GenAI-Agent-Security-Initiative` instead. If neither accepts a doc-level PR, fall back to opening a single short issue:

> **Title:** Detection-Coverage appendix proposal — community-driven mapping of ASI categories to working detection rules
>
> **Body:** PR #14 mapped ATR rules to ASI01–ASI10. The natural follow-up is to surface this in the Top 10 doc itself so readers see the detection path. Drafted appendix here: [link]. Open for any detection-rule project to contribute under, not ATR-exclusive. Should I PR it to this repo or somewhere else under genai-security-project?

That issue closes cleanly on a yes/no/redirect.

## Reply playbook

| Reply | Response |
|---|---|
| Approve / merge | Thank, follow up next quarter with proposed updates as ATR coverage evolves |
| "Cool but reduce ATR-specific framing" | Edit immediately to make the schema-neutral framing even more prominent; keep the data |
| Request changes | Address within 48h |
| "Wrong repo, try X" | Re-PR to X same-day |
| Stale (14d) | Bump with one new fact (e.g. "IBM mcp-context-forge just merged ATR adapter") |
| Close-without-merge | Open the fallback issue; document the close reason; preserve relationship |
