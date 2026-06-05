# ATR Compliance Coverage Policy

Status: v1.0 · 2026-06-05 · Maintainer: Adam Lin (adam@agentthreatrule.org)

This policy defines what "full compliance coverage" means for ATR and — equally
important — what it does **not** mean. It is the auditable basis for the
`compliance:` block on every rule and for the backfill that brings coverage up.

## Principle: honest coverage, never inflated

1. A rule is mapped to a framework control **only if the rule genuinely provides
   runtime detection evidence for that control.** We never add a mapping just to
   raise a coverage percentage.
2. The `context` prose on every mapping is **rule-specific** and auditor-readable.
   It states what the rule detects and why that is evidence for the control. Two
   rules in the same category share a rationale but not identical copy.
3. ATR is **detection evidence, not a compliance guarantee.** Context is phrased
   "provides detection evidence supporting Article X", never "satisfies" or
   "makes you compliant with". A GRC team uses ATR matches as one input to an
   audit; the auditor and counsel make the compliance determination.
4. Every identifier is validated against the published framework
   (`data/compliance-frameworks/*.json`, enforced by `npm run validate:compliance`
   in CI). A fabricated article/clause/subcategory cannot merge. The 72 rules that
   cited the non-existent ISO clauses 8.5/8.6 were corrected to 8.1 on 2026-06-05.

## What can honestly reach ~100%, and what cannot

| Framework | Honest ceiling | Why |
|---|---|---|
| EU AI Act | ~100% | Every ATR rule detects an attempt by an unauthorised party to alter an AI system's use, outputs or performance — exactly what Article 15 (accuracy, robustness and cybersecurity) requires. Article 9 (risk management) is a genuine secondary for every detection control. |
| NIST AI RMF | ~100% | MEASURE 2.7 (security and resilience) applies to every security detection rule; MANAGE/MAP secondaries are category-specific. |
| ISO/IEC 42001 | ~100% | Clause 8.1 (operational planning and control, incl. control of externally provided processes) covers runtime detection; 6.2 (objectives) and 8.2-8.4 (risk/impact) are category-specific. |
| OWASP LLM / Agentic / MITRE ATLAS | ~100% | These are the threat taxonomies ATR rules are written against; near-total by construction. |
| Colorado AI Act SB24-205 | **stays partial — by design** | The Act governs only "consequential decisions" (employment, lending, insurance, housing, education, healthcare, legal/government services). A prompt-injection or MCP-poisoning rule on a general agent is **not** within its scope. Mapping all rules here would be dishonest. Only rules that genuinely concern a consequential-decision system are mapped. |
| ETSI TS 104 223 | **partial** | Maps to specific principles/sub-principles only where a rule genuinely addresses them. |

"Full coverage" therefore means: **every rule maps to every framework control that
genuinely applies to it** — not "every rule maps to every framework."

## Category → control matrix (the backfill basis)

Primary = the rule is a main detection control for that item. Secondary = it
supports the item. Backfill adds the missing primaries first, then secondaries,
writing rule-specific context each time. Existing mappings are preserved.

| Rule category | EU AI Act | NIST AI RMF | ISO 42001 | OWASP LLM / Agentic |
|---|---|---|---|---|
| prompt-injection | 15 (P), 9 · 14 (S) | MS.2.7 (P), MG.2.3 (S) | 8.1 (P), 6.2 (S) | LLM01 / ASI01 |
| tool-poisoning | 15 (P), 9 (S) | MS.2.7 (P), MG.3.2 (S) | 8.1 (P), 8.3 (S) | LLM06, LLM03 / ASI02, ASI04 |
| context-exfiltration | 15 (P), 10 (S) | MS.2.7 (P), MS.2.10 (S) | 8.1 (P), 6.2 (S) | LLM02 / ASI06 |
| agent-manipulation | 15 (P), 14, 9 (S) | MS.2.7 (P), MG.2.3 (S) | 8.1 (P), 6.2 (S) | LLM01 / ASI01, ASI09 |
| privilege-escalation | 15 (P), 14 (S) | MS.2.7 (P), MG.2.3 (S) | 8.1 (P), 6.2 (S) | LLM06 / ASI03 |
| excessive-autonomy | 14 (P), 15, 9 (S) | MG.2.3 (P), MS.2.7 (S) | 6.2 (P), 8.1 (S) | LLM06 / ASI10 |
| data-poisoning | 10 (P), 15, 9 (S) | MS.2.5 (P), MS.2.7 (S) | 8.2 (P), 8.1 (S) | LLM04 / ASI06 |
| model-abuse | 15 (P), 9 (S) | MS.2.6 (P), MS.2.7 (S) | 8.1 (P), 6.2 (S) | LLM01, LLM10 / ASI01 |
| skill-compromise | 15 (P), 9 (S) | MS.2.7 (P), MG.3.1, MG.3.2 (S) | 8.1 (P), 8.3 (S) | LLM03 / ASI04 |
| model-security | 15 (P), 9 (S) | MS.2.7 (P), MS.2.6 (S) | 8.1 (P), 6.2 (S) | LLM01 / ASI01 |

This matrix is a floor, not a cap: a specific rule may genuinely map to more (e.g.
a rule that detects tampering with audit logs also maps to EU AI Act Article 12,
record-keeping). The rule author adds those with specific context.

## Maintenance

- `npm run audit:mappings` — live coverage report (per framework, per category, gaps).
- `npm run validate:compliance` — fails on any invalid identifier; runs in CI.
- New frameworks: add an allowlist file under `data/compliance-frameworks/`, add the
  block to `spec/atr-schema.yaml`, add a row to the matrix above.
