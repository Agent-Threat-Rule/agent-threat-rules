# ATR Submission to OWASP AI Security Solutions Landscape Q2 2026

> **Re-verify before sending (note added 2026-09-22).** Every figure below is a
> point-in-time snapshot and this file has gone stale before. Before any
> external use, re-run `find rules -name "*.yaml" | wc -l`, cross-check
> `data/stats.json`, and read README section 8 for current benchmark figures.
> Do not cite the withdrawn "99.7% precision / 0.3% FP" pair, the frozen
> "96,096 skills / 751 confirmed malware" pair, or the withdrawn per-lane FP
> rates. The only citable wild-scan figures are 101,280 scanned / 1,434
> flagged (engine v2.0.0, 2026-04-13).

## Submission Target

**Landscape:** AI Security Solutions Landscape for Agentic AI Q2 2026
**URL:** https://genai.owasp.org/resource/ai-security-solutions-landscape-for-agentic-ai-q2-2026/
**Contact:** OWASP GenAI Security Project (genai.owasp.org)

## ATR Profile

- **Name:** ATR (Agent Threat Rules)
- **Type:** Open-source detection rule standard
- **License:** MIT (permanent commitment)
- **URL:** https://github.com/Agent-Threat-Rule/agent-threat-rules
- **Category:** Agentic AI Security / Detection Rules / Supply Chain Security

## Positioning (one-liner)

ATR is an open-source detection rule corpus for AI agent threats -- like Sigma rules for SIEM, but for AI agents. 825 rules across 10 categories (as of 2026-09-22), over 100,000 real-world agent skills and MCP definitions scanned, and rules merged upstream into open-source scanners including cisco-ai-defense/skill-scanner.

## Key Facts

- 825 detection rules across 10 attack categories (as of 2026-09-22; re-verify against `data/stats.json`)
- RFC-001: vendor-neutral quality standard (maturity levels, confidence scoring, community signals)
- Framework coverage (OWASP Agentic Top 10, MITRE ATLAS and others): see `COVERAGE.md`, which is generated from the rule corpus rather than restated here
- Wild scan: 101,280 real-world agent skills and MCP definitions scanned across five registries, 1,434 flagged (engine v2.0.0, as of 2026-04-13). Triage of the flagged set is documented in `docs/research/wild-scan-drift.md`; the confirmed-malicious share is reported there as a floor, not a precision figure
- 34 ATR rules merged into the open-source `cisco-ai-defense/skill-scanner` repository (PR #79). This is an upstream merge into an open-source project, not a statement about any Cisco commercial product
- 4 export formats: SARIF, Splunk SPL, Elasticsearch DSL, generic regex
- Scan latency: see the published benchmark output rather than a fixed figure; per-file latency depends on rule count and event shape
- Runtime adapters: see `docs/RUNTIMES.md` for the current list

## Agentic SecOps Coverage

| Stage | ATR Coverage |
|-------|-------------|
| Development | Static scan of SKILL.md / agent configs |
| CI/CD | GitHub Action (planned), SARIF output for Security tab |
| Pre-deployment | Wild scan pipeline (101,280 skills / MCP definitions scanned, as of 2026-04-13) |
| Runtime | MCP event evaluation (tool calls, LLM I/O) |
| Threat Intelligence | Threat Cloud community feed (anonymous, privacy-first) |

## Differentiation

ATR is not a scanner product -- it is the detection rule layer that scanner products consume. The open-source `cisco-ai-defense/skill-scanner` repository has merged ATR rules upstream; Microsoft AGT can import ATR rules via the generic-regex adapter. Any vendor can adopt the RFC-001 quality standard without adopting ATR's rule format.

The closest analogy: ATR is to AI agent security what Sigma rules are to SIEM, what YARA rules are to malware detection, what Snort rules are to network intrusion detection.

## Action Items

1. Email OWASP GenAI Security Project leads (check genai.owasp.org/about for contacts)
2. Reference the ATR contribution submitted as PR #814 (attack examples for the Agentic Top 10). Re-check the PR's current state before citing it, and describe it as a contribution ATR submitted -- not as adoption or endorsement by the OWASP Foundation
3. Offer to present ATR at next OWASP GenAI community call
