# ATR -> OWASP Agentic Skills Top 10 (AST) Crosswalk

This document maps Agent Threat Rules (ATR) detection rules to the OWASP Agentic Skills Top 10 (AST01-AST10), so a project working from the AST checklist can see which controls ATR already ships executable detections for. It was produced in response to OWASP/www-project-agentic-skills-top-10#22.

## Method and join keys

This is a **curated thematic mapping**, not an id-equality join. ATR carries no native AST id in its metadata, so the crosswalk is generated as follows:

- **Primary join key:** each rule's `tags.category` (a closed 9-value enum). The `category -> AST` table is a one-time editorial mapping (`CATEGORY_TO_AST` in `scripts/generate-ast-crosswalk.py`), each entry carrying a short rationale reproduced below. It is applied mechanically to every rule, so per-control counts regenerate from metadata and cannot drift.
- **Secondary evidence (not a join):** each rule's `references.owasp_agentic` (ASIxx -- the OWASP Agentic Security Initiative Top 10, a *different* taxonomy from AST). Surfaced per row as supporting context, never as the mapping basis.

Regenerate with `python3 scripts/generate-ast-crosswalk.py`. CI runs `--check` so a stale copy fails the build.

Rules in corpus at generation time: **793**.

## Coverage by AST control

| AST | Title | ATR rules | Top supporting ASI (evidence) |
|-----|-------|-----------|-------------------------------|
| AST01 | Malicious Skills | 200 | ASI01 (57), ASI05 (53), ASI04 (48) |
| AST02 | Supply Chain Compromise | 54 | ASI04 (21), ASI01 (12), ASI05 (9) |
| AST03 | Over-Privileged Skills | 229 | ASI01 (93), ASI03 (88), ASI06 (39) |
| AST04 | Insecure Metadata | 113 | ASI05 (44), ASI06 (35), ASI02 (28) |
| AST05 | Untrusted External Instructions | 354 | ASI01 (334), ASI06 (16), ASI04 (14) |
| AST06 | Weak Isolation | 126 | ASI01 (75), ASI03 (40), ASI06 (21) |
| AST07 | Update Drift | 0 | - |
| AST08 | Poor Scanning | 0 | - |
| AST09 | No Governance | 38 | ASI03 (18), ASI01 (15), ASI02 (9) |
| AST10 | Cross-Platform Reuse | 0 | - |

## Category -> AST mapping (the editorial join table)

| ATR category | Rules | AST control(s) | Rationale |
|--------------|-------|----------------|-----------|
| prompt-injection (246) | 246 | AST05 Untrusted External Instructions | Injected/untrusted instructions are exactly the AST05 external-instruction class. |
| context-exfiltration (126) | 126 | AST03 Over-Privileged Skills | Reading/exfiltrating data beyond the skill's need is over-privilege. |
|  |  | AST06 Weak Isolation | Cross-context data leakage indicates weak isolation between skills/sessions. |
| tool-poisoning (113) | 113 | AST01 Malicious Skills | A poisoned tool/skill is a malicious skill at the point of use. |
|  |  | AST04 Insecure Metadata | Tool-description / metadata poisoning is the AST04 insecure-metadata surface. |
| agent-manipulation (108) | 108 | AST05 Untrusted External Instructions | Manipulating an agent via crafted external content is untrusted-instruction abuse. |
| privilege-escalation (65) | 65 | AST03 Over-Privileged Skills | Privilege escalation is the direct consequence of over-privileged skills. |
| skill-compromise (44) | 44 | AST01 Malicious Skills | A compromised skill is a malicious skill. |
|  |  | AST02 Supply Chain Compromise | Skill compromise via a tampered upstream is supply-chain compromise. |
| model-abuse (43) | 43 | AST01 Malicious Skills | Coercing the model into attacker-chosen behaviour manifests as a malicious skill action. |
| excessive-autonomy (38) | 38 | AST03 Over-Privileged Skills | Unbounded action authority is an over-privilege condition. |
|  |  | AST09 No Governance | Autonomy without checks is the AST09 governance gap. |
| data-poisoning (10) | 10 | AST02 Supply Chain Compromise | Poisoned training/reference data enters through the supply chain. |

## What ATR does not cover

ATR is a runtime/near-runtime detection ruleset. AST controls that are primarily process or lifecycle concerns -- **AST07 Update Drift**, **AST08 Poor Scanning**, **AST09 No Governance** (partially), **AST10 Cross-Platform Reuse** -- are not things a detection rule fires on; they are addressed by scanning cadence, provenance tracking, and governance process, not by a pattern match. Rows for those controls reflect only the adjacent runtime signals ATR can contribute, not full coverage.

