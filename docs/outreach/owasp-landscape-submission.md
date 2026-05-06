# ATR Submission to OWASP AI Security Solutions Landscape

## Submission Target

- **Landscape:** AI Security Solutions Landscape for Agentic AI (Q3 2026 update window)
- **Current edition:** [Q2 2026](https://genai.owasp.org/resource/ai-security-solutions-landscape-for-agentic-ai-q2-2026/)
- **Owning initiative:** [OWASP GenAI Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- **Org GitHub:** https://github.com/genai-security-project (no public submissions repo — outreach is via email / community call)

## ATR Profile

- **Name:** ATR (Agent Threat Rules)
- **Type:** Open-source detection rule corpus + standard (analogous to Sigma for SIEM, YARA for malware)
- **License:** MIT (permanent)
- **Repo:** https://github.com/Agent-Threat-Rule/agent-threat-rules
- **Paper:** Pan, Y. (2026). *Agent Threat Rules: A Community-Driven Detection Standard for AI Agent Security Threats.* Zenodo. [doi:10.5281/zenodo.19178002](https://doi.org/10.5281/zenodo.19178002)
- **Landscape category fit:** **Test & Evaluate** (rule corpus + benchmarks) and **Operate** (runtime detection via converters / GitHub Action)

## One-line Positioning

ATR is the open detection-rule layer for AI agent threats — 320 rules, 96K real-world skills scanned, 751 confirmed malware found, shipping in production at Cisco AI Defense and Microsoft Agent Governance Toolkit.

## Key Facts (as of 2026-05)

| Metric | Value |
|---|---|
| Detection rules | **320** across 10 attack categories |
| Regex patterns | 1,600+ (exportable as JSON, SARIF, Splunk SPL, Elasticsearch DSL) |
| OWASP Agentic Top 10 coverage | **10/10 categories** |
| SAFE-MCP (OpenSSF) coverage | **78/85 techniques (91.8%)** |
| MITRE ATLAS | per-rule references |
| Avg scan latency | **14ms / file** (Tier 0–2.5 resolves 99% of events at <5ms, $0) |
| Runtimes supported | 14 (Claude Code, Cursor, Hermes, OpenAI Assistants, Google A2A, …) |

## Production Adoption — 7 merges in 6 weeks

| Org | Integration | Reference |
|---|---|---|
| **Cisco AI Defense** | 34 ATR rules ship in official skill-scanner | [PR #79 merged](https://github.com/cisco-ai-defense/skill-scanner/pull/79) |
| **Microsoft Agent Governance Toolkit** | ATR community rules in PolicyEvaluator | [PR #908 merged](https://github.com/microsoft/agent-governance-toolkit/pull/908) |
| **OWASP Agentic Top 10** | Full vulnerability mapping | [PR #14 merged](https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14) |
| Awesome-LM-SSP (CryptoAILab) | Toolkit listing | [PR #108 merged](https://github.com/CryptoAILab/Awesome-LM-SSP/pull/108) |
| Awesome-LLM-agent-Security | Security Tools listing | [PR #6 merged](https://github.com/wearetyomsmnv/Awesome-LLM-agent-Security/pull/6) |
| awesome-agentic-patterns | Threat-rule-scanning pattern | [PR #58 merged](https://github.com/nibzard/awesome-agentic-patterns/pull/58) |
| Awesome-AI-Security | Agentic Systems listing | [PR #53 merged](https://github.com/TalEliyahu/Awesome-AI-Security/pull/53) |

**Pending review** (OWASP-relevant): [OWASP LLM Top 10 #814](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/pull/814) · [SAFE-MCP / OpenSSF #187](https://github.com/safe-agentic-framework/safe-mcp/pull/187) · [NVIDIA Garak #1676](https://github.com/NVIDIA/garak/pull/1676) · [IBM mcp-context-forge #4109](https://github.com/IBM/mcp-context-forge/pull/4109) · [Meta PurpleLlama #206](https://github.com/meta-llama/PurpleLlama/pull/206) · [Promptfoo #8529](https://github.com/promptfoo/promptfoo/pull/8529)

## Empirical Evidence

| Benchmark | Source | Samples | Recall | Precision | FP Rate |
|---|---|---|---|---|---|
| **NVIDIA Garak** (in-the-wild jailbreaks) | NVIDIA | 666 | **97.1%** | 100% | 0% |
| **SKILL.md benchmark** | 498 labeled samples | 498 | **100%** | 97% | 0.20% |
| **PINT** (adversarial) | Invariant Labs | 850 | 62.7% | 99.6% | — |
| **Wild scan** | OpenClaw + Skills.sh + Hermes + ClawHub | **96,096** | — | — | 1.35% flag rate |

**751 confirmed malware** discovered in OpenClaw alone — at least 3 coordinated threat actors mass-publishing poisoned skills (Solana wallets, Google Workspace tools, image generators) including a base64-encoded reverse shell to C2 IP `91.92.242.30`. Full report: [docs/research/openclaw-malware-campaign-2026-04.md](../research/openclaw-malware-campaign-2026-04.md).

## Agentic SecOps Lifecycle Coverage

| Stage | ATR coverage |
|---|---|
| **Develop & Experiment** | Static scan of SKILL.md / agent configs / MCP manifests |
| **Test & Evaluate** | Rule corpus + benchmarks (Garak, SKILL.md, PINT) + LIMITATIONS.md publishes evasion gaps |
| **Release / CI/CD** | GitHub Action + SARIF v2.1.0 → GitHub Security tab |
| **Deploy / Operate** | MCP runtime evaluation, 5-tier detection (invariants → blacklist → regex → embedding → behavioral → LLM-as-judge) |
| **Monitor** | Threat Cloud — anonymous, privacy-preserving community sensor feed |
| **Govern** | RFC-001 vendor-neutral quality standard (maturity levels, confidence scoring, community signals) |

## Differentiation

ATR is not a scanner product — **it is the detection-rule layer that scanner products consume**. The closest analogies:

- **Sigma rules** are to SIEM what ATR is to AI agent detectors
- **YARA rules** are to malware scanners what ATR is to skill / MCP scanners
- **Snort rules** are to IDS what ATR is to agent runtime monitors

Cisco AI Defense already ships ATR rules. Microsoft AGT can import them via the generic-regex adapter. **Any vendor in the existing landscape can adopt ATR rules or RFC-001 without adopting ATR's rule format** — that is the point.

This makes ATR an **enabling layer** for the landscape rather than competing with the scanners already on it.

## Action Items

1. **Email OWASP GenAI project leads** — start with `contribute.genai@owasp.org` (verify via genai.owasp.org) and the Agentic Security Initiative co-leads
2. **File an issue on `GenAI-Agent-Security-Initiative`** GitHub repo introducing ATR as a community detection corpus that maps to Agentic Top 10 (10/10) — leverages already-merged PR #14
3. **Offer to present at the next OWASP GenAI community call** — 15 min on the 96K wild scan + 751 malware finding
4. **Reference precedent** — XecART and XecGuard were inducted in Q2 2026 (CYBERSEC 2026 announcement); ask Agentic Security Initiative co-leads who shepherded those entries
5. **Target Q3 2026 publication** — landscape is updated quarterly; aim for inclusion in the Test & Evaluate column (and possibly Operate via the GitHub Action / converters)

## Submission Package (attach when emailing)

- This document
- Link to repo + paper (Zenodo DOI above)
- Cisco AI Defense PR #79 + Microsoft AGT PR #908 as production-adoption proof
- [docs/research/openclaw-malware-campaign-2026-04.md](../research/openclaw-malware-campaign-2026-04.md) as evidence of impact
- [docs/OWASP-MAPPING.md](../OWASP-MAPPING.md) as proof of 10/10 Agentic Top 10 alignment
