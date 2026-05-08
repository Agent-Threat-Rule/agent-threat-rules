# GenAI-Agent-Security-Initiative — PR (not Issue) v2

**Strategy change vs. v1:** open as a **Pull Request**, not an Issue. PRs have a clear close condition (merge / close / request-changes), reduce maintainer load, and demonstrate good-faith contribution before any ask. Issues are kept as a **fallback only** if the repo doesn't accept code contributions.

**Target repo:** https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative
**Branch name:** `community-contrib/atr-detection-examples`

---

## PR Title

`docs(examples): add 5 community detection-rule examples for Agentic Top 10 (ASI01–05) — ATR contribution`

---

## PR Body

This adds 5 community-contributed detection-rule examples — one per top-five Agentic Top 10 category (ASI01–ASI05). Each example is a self-contained YAML rule with reproducer test cases, severity rating, and an OWASP Agentic Top 10 mapping reference.

The intent is to give Initiative readers something concrete after the "what" of the Top 10: **"OK, how would I detect this?"** These are working rules from the [ATR (Agent Threat Rules)](https://github.com/Agent-Threat-Rule/agent-threat-rules) MIT-licensed corpus, so they can be vendored, modified, or referenced without license concerns.

### What's added

| File | Maps to | Severity | Demonstrates |
|---|---|---|---|
| `examples/community-detection-rules/atr/ATR-2026-00001-direct-prompt-injection.yaml` | ASI01 Goal Hijack | CRITICAL | Regex + multi-language patterns |
| `examples/community-detection-rules/atr/ATR-2026-00010-mcp-malicious-response.yaml` | ASI02 Tool Misuse | CRITICAL | MCP-layer detection |
| `examples/community-detection-rules/atr/ATR-2026-00021-api-key-exposure.yaml` | ASI03 Identity Abuse | HIGH | Credential pattern matching |
| `examples/community-detection-rules/atr/ATR-2026-00095-supply-chain-poisoning.yaml` | ASI04 Supply Chain | CRITICAL | Skill registry analysis |
| `examples/community-detection-rules/atr/ATR-2026-00050-runaway-agent-loop.yaml` | ASI08 Cascading Failures | HIGH | Behavioral fingerprinting |

Plus a one-page `examples/community-detection-rules/atr/README.md` explaining the rule format and pointing to the upstream ATR repo for the full 320-rule corpus.

### Provenance

- **License:** MIT (compatible with this repo's license per `.github/CONTRIBUTING.md`)
- **Upstream:** github.com/Agent-Threat-Rule/agent-threat-rules
- **Existing OWASP-track contribution:** [precize/Agentic-AI-Top10-Vulnerability#14](https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14) (merged)
- **Production deployments:** Cisco AI Defense skill-scanner ([PR #79](https://github.com/cisco-ai-defense/skill-scanner/pull/79) merged), Microsoft Agent Governance Toolkit ([PR #908](https://github.com/microsoft/agent-governance-toolkit/pull/908) merged)

### Why this PR is small

It would be easy to dump 320 rules and call it a day. I deliberately kept this to 5 to (a) make review tractable and (b) let the Initiative decide what shape further contribution should take. If this PR lands well, I'm happy to follow up with more — or to fold them somewhere else entirely if there's a better venue.

### Not requesting

No badge, no exclusivity, no commercial relationship. Just a contribution.

---

## Pre-open checklist

- [ ] Confirm the repo accepts external PRs (check `.github/CONTRIBUTING.md`); if read-only, fall back to PR on `GenAI-LLM-Top10` or post the issue version below
- [ ] Sign off CLA / DCO if required
- [ ] Verify the 5 rule files copy cleanly with original ATR rule IDs (so upstream changes flow naturally)
- [ ] Make the README link prominently to upstream ATR — this is contribution, not promotion
- [ ] Run any pre-commit hooks the repo uses (yamllint / spell check)
- [ ] Don't @-mention maintainers in the PR body — let it route normally
- [ ] Watch the PR; respond within 24h to any review comment

## Fallback: Issue (only if PR is not accepted)

If the repo doesn't accept code contributions, open the following Issue instead:

**Title:** `Question: where should community detection-rule examples for Agentic Top 10 categories live?`

**Body:**
> Hi maintainers — Initiative readers consistently ask "OK, how do I detect these?" after going through the Top 10. ATR (an MIT-licensed open detection corpus, already merged into Agentic-AI-Top10 via PR #14) has 320 rules with full ASI01–ASI10 mapping. Would 5 representative examples be welcome here, in `precize/Agentic-AI-Top10-Vulnerability`, or somewhere else under the genai-security-project umbrella?
>
> Happy to PR wherever the right place is. Just want to make sure I'm contributing into the right repo before doing the work.

That issue is short, asks one question, has a clear close condition.

## Reply playbook

| Reply | Response |
|---|---|
| Approve / merge | Thank, propose follow-up: 5 more rules covering ASI06–10 |
| "We'd prefer issue / different repo" | Re-route immediately, no debate |
| Request changes | Address within 48h; treat seriously |
| Stale (14d, no review) | Single bump on PR with one new fact (e.g. "Cisco AI Defense just shipped these 5 rules in their v2 release"), no re-ask |
| Close-without-merge | Thank, ask "is there a better contribution venue?" — preserve relationship |
