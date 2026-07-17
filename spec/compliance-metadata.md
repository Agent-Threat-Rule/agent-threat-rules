# ATR Rule Compliance Metadata Schema

**Status:** Draft v0.1 · Proposed 2026-04-22
**Scope:** Every `rules/**/*.yaml` may optionally include a top-level `compliance:` block that maps the rule to controls / articles / clauses in published AI compliance frameworks.

## Why

ATR rules already include `references:` pointing to OWASP LLM / OWASP Agentic Top 10 / MITRE ATLAS. That is an academic-citation block useful for researchers.

`compliance:` is a separate, audit-grade block whose purpose is different: an enterprise customer's GRC team must be able to take a detection event, trace it back to a specific rule ID, and show an auditor that the rule addresses a specific **published article or control** of:

1. EU AI Act (Regulation 2024/1689) — Articles 9-15, 50, 72, Annex III
2. Colorado AI Act SB24-205 — enforced 2026-06-30
3. NIST AI RMF 1.0 — Govern / Map / Measure / Manage functions + subcategories
4. ISO/IEC 42001:2023 — clauses 6-10 (AIMS)
5. OWASP Agentic Top 10 (2026) — ASI01..ASI10
6. OWASP LLM Top 10 (2025) — LLM01..LLM10

The `references:` block is not sufficient because:
- It does not distinguish "we studied this paper" from "this rule enforces this specific regulatory control."
- It has no structure for "what clause" vs "what context this rule addresses within that clause."
- It cannot carry the prose an auditor needs to accept the mapping.

## Schema

```yaml
compliance:
  # One key per framework the rule maps to. Omit frameworks that do not apply.
  owasp_agentic:
    - id: "ASI01:2026"          # Required. Canonical category ID.
      context: "..."            # Required. One-sentence prose explaining *how*
                                # this rule addresses the category. Auditor-
                                # readable; no jargon-only text.
      strength: primary         # Optional. primary | secondary | partial.

  owasp_llm:
    - id: "LLM01:2025"
      context: "..."
      strength: primary

  eu_ai_act:
    - article: "12"             # Required. Article number as a STRING, e.g. "12".
      context: "..."            # Required. How this rule provides detection EVIDENCE
                                # for the article (not "satisfies" — ATR is evidence,
                                # not a compliance guarantee).
      strength: primary         # Optional. primary | secondary | partial.

  colorado_ai_act:
    - section: "SB24-205.5"     # Required. Section identifier.
      clause: "High-risk disclosure"
      context: "..."
      strength: primary

  nist_ai_rmf:
    - subcategory: "MG.2.3"     # Required. Full subcategory ID.
      function: "Manage"        # Optional. Govern | Map | Measure | Manage.
      context: "..."
      strength: primary

  iso_42001:
    - clause: "6.2"             # Required. AIMS clause as a STRING (e.g. "6.2", "8.1").
                                # Clause 8 (Operation) has ONLY 8.1-8.4 — 8.5/8.6 do not exist.
      context: "..."
      strength: primary
```

### Field reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` / `article` / `section` / `function`+`subcategory` / `clause` | string/int | yes | Framework-specific canonical identifier. Must match the published framework exactly. |
| `clause` (EU/Colorado/ISO) | string | yes | Short human name for the clause. Helps report readers. |
| `context` | string | yes | One sentence, auditor-readable, explaining *why* the rule addresses this control. Not a copy of the clause text. |
| `strength` | enum | no | `primary` (rule is a main control for this clause), `secondary` (supports it), `partial` (covers part of it). Defaults to `primary` if omitted. |

### Multiplicity

A rule MAY map to multiple items within the same framework (a rule that logs event AND enforces policy touches both Article 12 and Article 14 of the EU AI Act). List each separately.

A rule MAY map to zero frameworks (e.g., an experimental research rule). Omit the `compliance:` block entirely in that case — do not include an empty one.

### Deprecation

When a framework publishes a new version, both old and new keys MAY coexist during a transition window (e.g., both `owasp_llm` 2023 and 2025 items), clearly distinguished by the `id` version suffix.

## Relationship to `references:`

The existing `references:` block is preserved unchanged. `references:` is for academic / research citations (MITRE ATLAS technique IDs, papers, blog posts). `compliance:` is for regulatory audit evidence.

A rule can have entries in both blocks — e.g., `references.mitre_atlas` AND `compliance.nist_ai_rmf` — and often will.

## Validation

- `scripts/validate-compliance.ts` (shipped 2026-06-05; `npm run validate:compliance`) validates every `compliance:` block against a per-framework allowlist of valid IDs / articles / subcategories / clauses. Rules with invalid entries fail CI (wired into `.github/workflows/validate.yml`). It requires non-empty `context` on every item and a valid `strength` enum.
- The allowlists live in `data/compliance-frameworks/*.json` — one file per framework — and are updated via PR when a framework publishes revisions. Frameworks used in rules but without an allowlist file are reported as warnings (not failures), so allowlists can be added incrementally.
- The canonical machine-readable shape is in `spec/atr-schema.yaml` under `properties.compliance`. Where this illustrative document and the schema differ, the schema + validator win.

## Downstream consumers

Downstream consumers of the `compliance:` block include:

- Compliance/audit reporting tools that map detection events (via rule IDs) to auditor-grade framework evidence — for example, periodic evidence reports for GRC or audit review
- ATR-compatible scanners that want to tag each detection with its regulatory context
- GRC platforms (e.g., Vanta, Drata) that integrate ATR rule packs
- Independent auditors verifying AI-system compliance claims

All downstream consumers are welcome — the `compliance:` block is MIT-licensed alongside the rules.

## Out of scope for this spec

- How a scanner renders compliance data in its UI
- How a GRC platform surfaces this in a customer's audit trail
- The legal interpretation of any framework clause — this spec provides the mapping data; auditors and counsel interpret it

## Open questions

1. Should `strength` be required (forcing every mapping to declare its strength)? Argument for: signals rigour. Argument against: extra authoring friction for common `primary` case. **Current answer: optional, default `primary`.**
2. Should framework-specific metadata (e.g., EU AI Act Annex III categories) live alongside article mappings? **Current answer: yes, under a nested `annex:` key within the article object if needed.**
3. How to handle frameworks that don't exist yet but are expected (e.g., Japan AI Safety Act 2027)? **Current answer: add keys as frameworks publish; no speculative schema for unpublished frameworks.**

## Roll-out plan

1. 2026-04-22: this spec document merged
2. 2026-04-W4: 10 sample rules carry `compliance:` block for OWASP Agentic + OWASP LLM (bootstrap from existing `references:` data)
3. 2026-05: 50 rules extended across all 6 frameworks (LLM-assisted authoring + human QA)
4. 2026-06-05 status (462 rules): NIST AI RMF 96.1%, EU AI Act 39.6%, ISO 42001 38.3%. Validator + allowlists + schema shipped; 72 fabricated ISO clauses (8.5/8.6) corrected to 8.1. Run `npm run audit:mappings` for live coverage.
5. In progress: honest full-coverage backfill — every rule mapped to every framework control that GENUINELY applies, with rule-specific context. Frameworks that cannot honestly reach 100% (Colorado AI Act, ETSI) stay partial by design; see docs/COMPLIANCE-COVERAGE-POLICY.md.
6. Ongoing: new ATR rules SHOULD include `compliance:` from day 1; CI (`validate:compliance`) blocks any rule that cites a non-existent framework identifier.
