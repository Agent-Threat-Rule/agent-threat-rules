# ATR -> IETF BMWG AI Agent Security Benchmark crosswalk

This document maps the metrics defined in the IETF Benchmarking Methodology
Working Group (BMWG) Internet-Draft **draft-han-bmwg-agent-security-benchmark-00**
onto Agent Threat Rules (ATR) detection content, and states plainly which metrics
ATR covers, partially covers, or is out of scope for.

- **Source:** *AI Agent Security Evaluation Benchmark*,
  draft-han-bmwg-agent-security-benchmark-00, IETF BMWG (individual Internet-Draft,
  published 2026-07-05, not yet WG-adopted).
  <https://datatracker.ietf.org/doc/draft-han-bmwg-agent-security-benchmark/>
- **Structure:** 4 dimensions / 55 second-level metrics, scored pass/fail
  ("Metric Value = Passed Test Cases / Total Test Cases", 0-100 scale).
- **This mapping:** hand-authored, 2026-07-13. Rule IDs and class sizes are read
  from the ATR rule directories at authoring time (**748 rules** total). Verify
  counts against `data/stats.json` before any external citation.
- **Companion documents:** [`atr-cosai-mcp-taxonomy-mapping.md`](atr-cosai-mcp-taxonomy-mapping.md),
  [`atr-unit42-biv-crosswalk.md`](atr-unit42-biv-crosswalk.md),
  [`atr-attack-crosswalk.md`](atr-attack-crosswalk.md),
  [`atr-ast-crosswalk.md`](atr-ast-crosswalk.md).

## Where ATR sits in this benchmark (read first)

The BMWG draft is a **benchmark methodology**: for each metric it runs a set of
test cases against an agent and scores the fraction that pass. It defines *what to
test* and *how to score*, but it does not ship the machine-readable logic that
decides whether a given attack test case succeeded.

ATR is **detection content** -- machine-readable rules that fire on attack patterns
in agent inputs, outputs, tool descriptions, skills, and call sequences. ATR
therefore maps onto the benchmark as a **detection oracle**: for the metrics that
are adversarial "did the attack get through?" tests (injection, tool/skill
poisoning, credential exfiltration, excessive agency), ATR is exactly the
pass/fail decision logic the benchmark needs. ATR does **not** implement the
benchmark harness, and it is **out of scope** for the metrics that measure
model-intrinsic properties (hallucination, bias), runtime control planes
(authorization tiers, sandboxing, emergency shutdown), protocol authentication
(A2A mutual auth, replay), or governance controls (log retention, right-to-be-
forgotten, compliance filing). Those require a runtime enforcement layer or a
model evaluation, not a pattern rule -- and this crosswalk says so metric by metric
rather than overclaiming whole-agent coverage.

**Honest headline:** of 55 metrics, ATR provides direct detection for ~13,
partial detection for ~12, and is out of scope for ~30. ATR is a strong detection
oracle for the attack-surface third of the benchmark, not a whole-agent security
score.

Legend: **D** = Detection (ATR rules fire on this attack pattern) · **P** = Partial
(covered in part; stateless pattern engine limits multi-turn/behavioral cases) ·
**O** = Out of scope (model property / runtime control / protocol / governance --
not a detectable pattern).

## Dimension 1 -- Model-Native Security (10 metrics)

Intrinsic LLM properties during inference. ATR does not evaluate model weights or
behavior in the abstract, so this dimension is almost entirely out of scope.

| Metric | Map | ATR basis / note |
|---|---|---|
| 1.1 Adversarial Sample Defense | O | Model robustness property; not a pattern in agent I/O. |
| 1.2 Hallucination Mitigation | O | Model truthfulness property. |
| 1.3 Decision Calibration | O | Model behavior property. |
| 1.4 Model Reverse-Engineering / Extraction Defense | P | `context-exfiltration` rules flag bulk system-prompt / data extraction attempts, but membership-inference over model weights is out of scope. |
| 1.5 Instruction Following / Safety Alignment | O | Alignment property. |
| 1.6 Safety in Long / Complex Reasoning | O | Model property. |
| 1.7 Industry Compliance Alignment (model layer) | O | Model refusal behavior. |
| 1.8 Bias and Discrimination Mitigation | O | Fairness property, not an attack pattern. |
| 1.9 Harmful Content Defense | P | `model-abuse` rules flag some induced-harmful-output patterns; full content-safety scoring is a model eval. |
| 1.10 Robustness to Command-Boundary Constraints | P | Multi-round enticement is partly covered by `prompt-injection` / `agent-manipulation`; stateless matching limits multi-turn cases. |

Dimension 1: 0 D / 3 P / 7 O.

## Dimension 2 -- Interaction Security (14 metrics)

Agent input/output control and interaction permissions. ATR's core strength for
the attack-pattern metrics; the authorization-tier metrics are runtime controls.

| Metric | Map | ATR basis / note |
|---|---|---|
| 2.1 Direct Jailbreak Defense | D | `prompt-injection` (largest class, ~246 rules): jailbreak templates, role-play enticement. |
| 2.2 Indirect Injection Defense | D | `prompt-injection` core: malicious commands in pages/docs/API/RAG results. |
| 2.3 Multi-Round Strategic Bypass | P | `agent-manipulation` (~108 rules); progressive multi-turn is partly out of a stateless engine's reach. |
| 2.4 Parameter Injection Defense | D | `tool-poisoning` + `privilege-escalation`: command/SQL injection, path traversal in tool params. |
| 2.5 Tool Call Chain Security | P | `tool-poisoning` flags contaminated tool I/O; cross-step propagation tracking is partial. |
| 2.6 Confused Deputy Defense | D | `privilege-escalation` / `excessive-autonomy`: tricked execution of untrusted scripts at elevated privilege. |
| 2.7 Excessive Agency Defense | D | `excessive-autonomy`: autonomous invocation of sensitive tools without authorization. |
| 2.8 Intent / Operation Consistency | P | Deviation between tool op and user intent; ATR flags some, full behavioral consistency is out of scope. |
| 2.9 Input-Output Traceability | O | Logging/attribution control, not a detection pattern. |
| 2.10 Operational Risk Classification | O | Agent capability requirement. |
| 2.11 Real-Time Auth (medium-risk) | O | Runtime authorization control. |
| 2.12 Batch/Session Auth (low-risk) | O | Runtime authorization control. |
| 2.13 User Takeover (high-risk) | O | Runtime human-in-the-loop control. |
| 2.14 Anonymous-User Risk Restriction | O | Runtime authentication control. |

Dimension 2: 5 D / 3 P / 6 O.

## Dimension 3 -- Operational Security (9 metrics listed)

Autonomous-lifecycle and multi-agent risks. Mostly runtime controls; a few
multi-agent contamination metrics are partially detectable.
(Draft states 10 for this dimension; the -00 text enumerates 3.1-3.9. Discrepancy
flagged; recount against the WG version.)

| Metric | Map | ATR basis / note |
|---|---|---|
| 3.1 Emergency Shutdown / Task Termination | O | Runtime kill-switch control. |
| 3.2 Decision-Responsibility Traceability | O | Audit-logging control. |
| 3.3 Malicious Collusion Defense | P | `agent-manipulation` multi-agent rules flag collusive-communication patterns; shared-memory covert channels partly out of scope. |
| 3.4 Decision-Bias Spread Defense | P | `data-poisoning`: contamination of shared knowledge bases. |
| 3.5 Goal Drift Control | P | `excessive-autonomy` flags objective-deviation signals; long-horizon drift is partial. |
| 3.6 Autonomous Iteration Security | P | `model-security` / `excessive-autonomy`: self-modification that strips protections; detectable in part. |
| 3.7 Ecosystem-Level Crash Defense | O | Resilience/circuit-breaker control. |
| 3.8 Sandbox Isolation Effectiveness | O | Runtime isolation control. |
| 3.9 Dynamic Permissions / Sandbox Boundary | O | Runtime least-privilege control. |

Dimension 3: 0 D / 4 P / 5 O.

## Dimension 4 -- Basic Security (22 metrics)

Permission, tool, supply-chain, and infrastructure. ATR's second strong area:
tool/skill/supply-chain poisoning, injection filtering, credential and privacy
exfiltration.

| Metric | Map | ATR basis / note |
|---|---|---|
| 4.1 Compliance Labels and Filing | O | Governance/registration control. |
| 4.2 Privacy Leakage Prevention | D | `context-exfiltration`: cross-user leakage, plaintext-log data exposure. |
| 4.3 Memory Poisoning Defense | D | `data-poisoning`: malicious dialogue entering long-term memory. |
| 4.4 Cross-User / Session Memory Isolation | O | Runtime isolation control (design property). |
| 4.5 Data Deletion / Right to Be Forgotten | O | Data-governance control. |
| 4.6 Compliant Data Transmission | O | TLS/minimization control. |
| 4.7 Memory Data Integrity | P | `data-poisoning`: tamper detection on memory load; partial. |
| 4.8 Search-Result Injection Filtering | D | `prompt-injection`: hidden injections in external search results. |
| 4.9 Cross-Document Reasoning Security | P | `prompt-injection`: spliced-document instruction generation; partial. |
| 4.10 Identity Uniqueness / Authenticatability | O | Protocol identity control. |
| 4.11 Ecosystem Asset Security / SBOM | P | `skill-compromise` supply-chain rules flag risky components; SBOM lifecycle management is out of scope. |
| 4.12 MCP Tool Poisoning Defense | D | `tool-poisoning` core: MCP declaration-vs-execution discrepancy, data-theft/backdoor tools. |
| 4.13 Plugin / Skill Security | D | `skill-compromise` core: pre-install scan + runtime exfil/reverse-shell detection (ecosystem scan of 96,096 skills / 751 confirmed malware; rule ATR-2026-02261 for code-surface credential exfil). |
| 4.14 Prompt Template Tampering Defense | D | `prompt-injection`: system-prompt keyword tampering, semantic backdoors. |
| 4.15 External API Response Cleaning | D | `prompt-injection`: hidden malicious instructions in third-party API data. |
| 4.16 Identity / Access Credential Security | D | `context-exfiltration` + `privilege-escalation`: plaintext-key handling and credential exfil (ATR-2026-00201/00224 shell-surface, ATR-2026-02261 code-surface). |
| 4.17 Security Audit Capabilities | O | Tamper-proof logging control. |
| 4.18 Supply-Chain Material Access Control | P | `skill-compromise`: rejects known-bad components; SBOM-whitelist enforcement is a runtime control. |
| 4.19 A2A Mutual Authentication | O | Protocol authentication control. |
| 4.20 Communication Replay Resistance | O | Protocol anti-replay control. |
| 4.21 Log Retention / Secure Storage | O | Storage-governance control. |
| 4.22 Security Policy Consistency | O | Cluster-config control. |

Dimension 4: 8 D / 3 P / 11 O.

## Summary

| Dimension | Metrics | Detection | Partial | Out-of-scope |
|---|---|---|---|---|
| 1. Model-Native Security | 10 | 0 | 3 | 7 |
| 2. Interaction Security | 14 | 5 | 3 | 6 |
| 3. Operational Security | 9 | 0 | 4 | 5 |
| 4. Basic Security | 22 | 8 | 3 | 11 |
| **Total** | **55** | **13** | **13** | **29** |

ATR is the machine-readable detection oracle for the ~13 attack-surface metrics
(injection, tool/MCP poisoning, skill/supply-chain compromise, credential and
privacy exfiltration, excessive agency) and contributes partial signal on ~13
more. It is deliberately out of scope for the model-property, runtime-control,
protocol, and governance metrics -- those need a model evaluation or an
enforcement layer, which ATR is not.

## Candidate gaps (rule opportunities; not written here)

Metrics marked Partial where a tighter, generalizable rule could raise coverage --
recorded for future rule work, **not** authored from this document's prose (to
avoid report-text memorization; see the project's generalization gate):

- 2.5 Tool Call Chain: ordered cross-tool contamination propagation.
- 3.3 Malicious Collusion: shared-memory covert-channel patterns between agents.
- 4.7 Memory Data Integrity: tamper signatures on memory-load paths.
- 4.9 Cross-Document Reasoning: spliced-instruction assembly across documents.

Any rule for these must be authored from real attack payloads with true-positive
and true-negative test cases and must pass the 65K-sample benign 0-FP gate and the
generalization gate before merge.
