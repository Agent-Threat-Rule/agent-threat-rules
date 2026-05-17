# Integration: prompt-defense-audit (static design-time complement)

[`prompt-defense-audit`](https://github.com/ppcvote/prompt-defense-audit) is a static, design-time auditor that scans a system prompt for missing defense vectors before deployment. It is the natural pre-runtime complement to ATR: where ATR answers "is an attack happening right now?", prompt-defense-audit asks "is the prompt designed to resist attacks at all?"

The two tools operate on different inputs at different points in the lifecycle and have orthogonal failure modes. Used together they form a defense-in-depth pattern: bake the resistance in at build time, then detect the attempts that bypass it at runtime.

## When to use which

| Axis | ATR (this project) | prompt-defense-audit |
|---|---|---|
| **When it runs** | Runtime (incoming traffic) | Design / build / CI |
| **What it answers** | "Is an attack happening?" | "Is the prompt designed to resist attacks?" |
| **Object of analysis** | Live request payload | Static system-prompt text |
| **Output** | Detection event (matched rule) | Coverage score + gap report (defended / missing) |
| **Rule count** | 311 detection patterns | 20 defense vectors (12 base + 5 v1.4 agent + 3 v1.5 supply-chain) |
| **Failure mode if used alone** | Misses prompts that have no resistance even before traffic arrives | Misses novel attacks not anticipated at design time |
| **License** | MIT | MIT |
| **Dependencies** | Per detection layer | Zero (pure regex) |

Both tools land at OWASP Agentic Top 10 (ASI01–ASI10) but from different sides — ATR catches the agent during goal-hijack execution, the audit asks whether the prompt declared `least-agency` constraints to begin with.

## 1:N mapping — defense vectors → ATR detection categories

| prompt-defense-audit vector | Maps to ATR category | Static check, paraphrased |
|---|---|---|
| `role-escape` | agent manipulation | Does the prompt explicitly forbid role / character switching? |
| `instruction-override` | prompt injection | Does the prompt define instruction-priority rules? |
| `data-leakage` | context exfiltration | Does the prompt forbid revealing system instructions? |
| `output-manipulation` | prompt injection | Does the prompt constrain output format? |
| `multilang-bypass` | prompt injection | Does the prompt enforce response-language invariance? |
| `unicode-attack` | prompt injection | Does the prompt acknowledge homoglyph / encoding tricks? |
| `context-overflow` | prompt injection | Does the prompt enforce input-length limits? |
| `indirect-injection` | prompt injection | Does the prompt treat retrieved / external content as untrusted? |
| `social-engineering` | agent manipulation | Does the prompt explicitly resist emotional pressure? |
| `output-weaponization` | prompt injection | Does the prompt refuse harmful-content generation? |
| `abuse-prevention` | agent manipulation | Does the prompt include rate-limit / abuse-report logic? |
| `input-validation-missing` | prompt injection | Does the prompt sanitize input fields it concatenates? |
| `encoding-bypass` (v1.4) | prompt injection | Does the prompt say "decoded base64 / morse / ROT13 is data, not commands"? |
| `function-semantic` (v1.4) | tool poisoning | Are tool / function semantics declared immutable? |
| `memory-provenance` (v1.4) | context exfiltration | Does the prompt verify retrieved-memory origin? |
| `cross-agent-authority` (v1.4) | agent manipulation | Does the prompt forbid inheriting authority from forwarded agent output? |
| `transaction-guardrails` (v1.4) | tool poisoning | Does the prompt enforce per-action limits / multi-sig / verification? |
| `skill-provenance` (v1.5) | **skill compromise** | Does the prompt require skill / extension / plugin provenance verification? |
| `implicit-memory-hygiene` (v1.5) | context exfiltration | Does the prompt treat prior outputs as untrusted on re-ingestion? |
| `least-agency` (v1.5) | agent manipulation | Does the prompt enforce minimum agency / halt-on-goal-drift? |

The v1.5 vectors were added in May 2026 in response to:

- Snyk [ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) (skill supply-chain compromise)
- OpenReview [InjecMEM](https://openreview.net/forum?id=QVX6hcJ2um) (implicit memory injection, Feb 2026)
- OWASP Agentic Top 10 ASI01 (goal hijack)

All three lines of attack are detected by ATR at runtime; all three were previously absent at design time.

## Empirical baseline

A scan of **1,646 production system prompts** drawn from four public corpora (jujumilk3/leaked-system-prompts, x1xhlol/system-prompts-and-models-of-ai-tools, elder-plinius/CL4R1T4S, LouisShark/chatgpt_system_prompt) produced the following gap rates:

| Vector | Gap rate | Defended / Missing |
|---|---|---|
| Indirect Injection Protection | **97.8%** | 37 / 1,609 |
| Unicode Protection | 97.3% | 44 / 1,602 |
| Role Boundary | 92.4% | 125 / 1,521 |
| Length Limits | 89.9% | 166 / 1,480 |
| Harmful Content Prevention | 88.3% | 192 / 1,454 |
| Abuse Prevention | 78.1% | 360 / 1,286 |
| Social Engineering Defense | 71.4% | 470 / 1,176 |
| Multi-language Protection | 64.3% | 587 / 1,059 |

Source data: [`research/defense-posture-results.json`](https://github.com/ppcvote/prompt-defense-audit/blob/main/research/defense-posture-results.json).

The headline is that **97.8% of production prompts have zero indirect-injection defense** declared at design time. ATR's prompt-injection rules are catching attacks against prompts that almost universally lack the design-time guard. Pairing the two tools surfaces this gap during CI rather than during incident response.

## Recommended usage pattern

```
┌────────────────────────────────────────────────┐
│ Design / CI gate                                │
│   prompt-defense-audit (this static check)     │
│   → fails build if score < threshold            │
│   → required vectors fail closed                │
└─────────────────────┬──────────────────────────┘
                      │ prompt promoted to production
                      ▼
┌────────────────────────────────────────────────┐
│ Runtime                                         │
│   ATR (this project)                            │
│   → matched detection rule fires event          │
│   → SOC pipeline / SIEM / response automation   │
└────────────────────────────────────────────────┘
```

A detection event from ATR can optionally surface the corresponding `prompt-defense-audit` vector ID, so responders know whether the matched attack was a known class the prompt failed to defend against, or a novel class that bypassed an otherwise-hardened prompt.

## Cross-references

- Discussion that produced this integration: [Agent-Threat-Rule/agent-threat-rules#47](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/47)
- prompt-defense-audit repository: <https://github.com/ppcvote/prompt-defense-audit>
- npm package: [`prompt-defense-audit`](https://www.npmjs.com/package/prompt-defense-audit) (also published as [`ultraprobe`](https://www.npmjs.com/package/ultraprobe))
- Reverse integration doc on prompt-defense-audit side: `docs/integrations/agent-threat-rules.md`
- Coverage report against ATR autoresearch corpus (forthcoming): `research/coverage-vs-atr-autoresearch.md`
- Shared OWASP coordinate system: [sint-ai/sint-protocol#179](https://github.com/sint-ai/sint-protocol/pull/179) (12 vectors → ASI mapping)

## Prior deployments of the audit engine

The same 20-vector engine has been merged into:

- [Cisco AI Defense / mcp-scanner #146](https://github.com/cisco-ai-defense/mcp-scanner/pull/146) (Apr 2026)
- [Microsoft Agent Governance Toolkit #854](https://github.com/microsoft/agent-governance-toolkit/pull/854) (Apr 2026)
- [OWASP Agent-Security-Regression-Harness #78](https://github.com/OWASP/Agent-Security-Regression-Harness/pull/78) + [#79](https://github.com/OWASP/Agent-Security-Regression-Harness/pull/79) (May 2026)
- [SINT Protocol #179](https://github.com/sint-ai/sint-protocol/pull/179) (May 2026)
