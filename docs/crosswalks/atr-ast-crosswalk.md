# ATR -> OWASP Agentic Skills Top 10 (AST) Crosswalk

This document maps Agent Threat Rules (ATR) detection rules to the OWASP Agentic Skills Top 10 (AST01-AST10), so a project working from the AST checklist can see which controls ATR already ships executable detections for. It was produced in response to OWASP/www-project-agentic-skills-top-10#22.

## Method and join keys

This is a **curated thematic mapping**, not an id-equality join. ATR carries no native AST id in its metadata, so the crosswalk is generated as follows:

- **Primary join key:** each rule's `tags.category` (10 values in the current corpus; the enum is defined in `spec/atr-schema.yaml`). The `category -> AST` table is a one-time editorial mapping (`CATEGORY_TO_AST` in `scripts/generate-ast-crosswalk.py`), each entry carrying a short rationale reproduced below. It is applied mechanically to every rule, so per-control counts regenerate from metadata and cannot drift.
- **Secondary evidence (not a join):** each rule's `references.owasp_agentic` (ASIxx -- the OWASP Agentic Security Initiative Top 10, a *different* taxonomy from AST). Surfaced per row as supporting context, never as the mapping basis.

Regenerate with `python3 scripts/generate-ast-crosswalk.py`. CI runs `--check` so a stale copy fails the build.

Rules in corpus at generation time: **844**.

## Coverage by AST control

Rule counts are split by maturity, because the lanes differ: the enforce lane (the one meant to block) loads `maturity: stable` only, the alert lane adds `test`, and `experimental` and `draft` rules run in the hunt lane only. A rule mapped to a control is a detection for part of that control's threat surface, not coverage of the control.

| AST | Title | ATR rules | stable | test | experimental | draft | Top supporting ASI (evidence) |
|-----|-------|-----------|--------|------|--------------|-------|-------------------------------|
| AST01 | Malicious Skills | 214 | 21 | 164 | 19 | 10 | ASI05 (78), ASI04 (68), ASI01 (61) |
| AST02 | Supply Chain Compromise | 58 | 1 | 53 | 4 | 0 | ASI04 (31), ASI05 (15), ASI01 (12) |
| AST03 | Over-Privileged Skills | 257 | 44 | 179 | 30 | 4 | ASI03 (95), ASI01 (90), ASI02 (74) |
| AST04 | Insecure Metadata | 123 | 12 | 84 | 17 | 10 | ASI05 (63), ASI02 (44), ASI04 (38) |
| AST05 | Untrusted External Instructions | 362 | 38 | 304 | 13 | 7 | ASI01 (341), ASI04 (15), ASI06 (15) |
| AST06 | Weak Isolation | 138 | 30 | 97 | 10 | 1 | ASI01 (73), ASI03 (46), ASI02 (31) |
| AST07 | Update Drift | 0 | 0 | 0 | 0 | 0 | - |
| AST08 | Poor Scanning | 0 | 0 | 0 | 0 | 0 | - |
| AST09 | No Governance | 40 | 11 | 26 | 2 | 1 | ASI02 (16), ASI01 (15), ASI03 (13) |
| AST10 | Cross-Platform Reuse | 0 | 0 | 0 | 0 | 0 | - |

## Category -> AST mapping (the editorial join table)

| ATR category | Rules | AST control(s) | Rationale |
|--------------|-------|----------------|-----------|
| prompt-injection (254) | 254 | AST05 Untrusted External Instructions | Injected/untrusted instructions are exactly the AST05 external-instruction class. |
| context-exfiltration (138) | 138 | AST03 Over-Privileged Skills | Reading/exfiltrating data beyond the skill's need is over-privilege. |
|  |  | AST06 Weak Isolation | Cross-context data leakage indicates weak isolation between skills/sessions. |
| tool-poisoning (123) | 123 | AST01 Malicious Skills | A poisoned tool/skill is a malicious skill at the point of use. |
|  |  | AST04 Insecure Metadata | Tool-description / metadata poisoning is the AST04 insecure-metadata surface. |
| agent-manipulation (108) | 108 | AST05 Untrusted External Instructions | Manipulating an agent via crafted external content is untrusted-instruction abuse. |
| privilege-escalation (79) | 79 | AST03 Over-Privileged Skills | Privilege escalation is the direct consequence of over-privileged skills. |
| skill-compromise (48) | 48 | AST01 Malicious Skills | A compromised skill is a malicious skill. |
|  |  | AST02 Supply Chain Compromise | Skill compromise via a tampered upstream is supply-chain compromise. |
| model-abuse (43) | 43 | AST01 Malicious Skills | Coercing the model into attacker-chosen behaviour manifests as a malicious skill action. |
| excessive-autonomy (40) | 40 | AST03 Over-Privileged Skills | Unbounded action authority is an over-privilege condition. |
|  |  | AST09 No Governance | Autonomy without checks is the AST09 governance gap. |
| data-poisoning (10) | 10 | AST02 Supply Chain Compromise | Poisoned training/reference data enters through the supply chain. |

> 1 rule(s) carry a category not in the mapping table and are excluded rather than force-fit: `model-security` (1).

## What ATR does not cover

ATR is a runtime/near-runtime detection ruleset. AST controls that are primarily process or lifecycle concerns -- **AST07 Update Drift**, **AST08 Poor Scanning**, **AST09 No Governance** (partially), **AST10 Cross-Platform Reuse** -- are not things a detection rule fires on; they are addressed by scanning cadence, provenance tracking, and governance process, not by a pattern match. Rows for those controls reflect only the adjacent runtime signals ATR can contribute, not full coverage.

