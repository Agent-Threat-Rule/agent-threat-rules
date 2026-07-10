# ATR -> OWASP Agentic Skills Top 10 (AST) Crosswalk

This document maps Agent Threat Rules (ATR) detection rules to the OWASP Agentic Skills Top 10 (AST01-AST10), so a project working from the AST checklist can see which controls ATR already ships executable detections for. It was produced in response to OWASP/www-project-agentic-skills-top-10#22.

## Method and join keys

This is a **curated thematic mapping**, not an id-equality join. ATR carries no native AST id in its metadata, so the crosswalk is generated as follows:

- **Primary join key:** each rule's `tags.category` (a closed 9-value enum). The `category -> AST` table is a one-time editorial mapping (`CATEGORY_TO_AST` in `scripts/generate-ast-crosswalk.py`), each entry carrying a short rationale reproduced below. It is applied mechanically to every rule, so per-control counts regenerate from metadata and cannot drift.
- **Secondary evidence (not a join):** each rule's `references.owasp_agentic` (ASIxx -- the OWASP Agentic Security Initiative Top 10, a *different* taxonomy from AST). Surfaced per row as supporting context, never as the mapping basis.

Regenerate with `python3 scripts/generate-ast-crosswalk.py`. CI runs `--check` so a stale copy fails the build.

Rules in corpus at generation time: **722**.

## Coverage by AST control

| AST | Title | ATR rules | Top supporting ASI (evidence) |
|-----|-------|-----------|-------------------------------|
| AST01 | Malicious Skills | 176 | ASI01 (55), ASI04 (45), ASI05 (44) |
| AST02 | Supply Chain Compromise | 47 | ASI04 (19), ASI01 (11), ASI03 (7) |
| AST03 | Over-Privileged Skills | 195 | ASI01 (88), ASI03 (83), ASI06 (35) |
| AST04 | Insecure Metadata | 96 | ASI05 (37), ASI06 (31), ASI04 (26) |
| AST05 | Untrusted External Instructions | 345 | ASI01 (326), ASI06 (16), ASI04 (14) |
| AST06 | Weak Isolation | 114 | ASI01 (70), ASI03 (37), ASI06 (19) |
| AST07 | Update Drift | 0 | - |
| AST08 | Poor Scanning | 0 | - |
| AST09 | No Governance | 35 | ASI03 (16), ASI01 (15), ASI02 (6) |
| AST10 | Cross-Platform Reuse | 0 | - |

## Category -> AST mapping (the editorial join table)

| ATR category | Rules | AST control(s) | Rationale |
|--------------|-------|----------------|-----------|
| prompt-injection (238) | 238 | AST05 Untrusted External Instructions | Injected/untrusted instructions are exactly the AST05 external-instruction class. |
| context-exfiltration (114) | 114 | AST03 Over-Privileged Skills | Reading/exfiltrating data beyond the skill's need is over-privilege. |
|  |  | AST06 Weak Isolation | Cross-context data leakage indicates weak isolation between skills/sessions. |
| agent-manipulation (107) | 107 | AST05 Untrusted External Instructions | Manipulating an agent via crafted external content is untrusted-instruction abuse. |
| tool-poisoning (96) | 96 | AST01 Malicious Skills | A poisoned tool/skill is a malicious skill at the point of use. |
|  |  | AST04 Insecure Metadata | Tool-description / metadata poisoning is the AST04 insecure-metadata surface. |
| privilege-escalation (46) | 46 | AST03 Over-Privileged Skills | Privilege escalation is the direct consequence of over-privileged skills. |
| skill-compromise (41) | 41 | AST01 Malicious Skills | A compromised skill is a malicious skill. |
|  |  | AST02 Supply Chain Compromise | Skill compromise via a tampered upstream is supply-chain compromise. |
| model-abuse (39) | 39 | AST01 Malicious Skills | Coercing the model into attacker-chosen behaviour manifests as a malicious skill action. |
| excessive-autonomy (35) | 35 | AST03 Over-Privileged Skills | Unbounded action authority is an over-privilege condition. |
|  |  | AST09 No Governance | Autonomy without checks is the AST09 governance gap. |
| data-poisoning (6) | 6 | AST02 Supply Chain Compromise | Poisoned training/reference data enters through the supply chain. |

## What ATR does not cover

ATR is a runtime/near-runtime detection ruleset. AST controls that are primarily process or lifecycle concerns -- **AST07 Update Drift**, **AST08 Poor Scanning**, **AST09 No Governance** (partially), **AST10 Cross-Platform Reuse** -- are not things a detection rule fires on; they are addressed by scanning cadence, provenance tracking, and governance process, not by a pattern match. Rows for those controls reflect only the adjacent runtime signals ATR can contribute, not full coverage.

