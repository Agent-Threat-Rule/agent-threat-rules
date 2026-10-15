# ATR Crosswalk Mappings

Detailed mappings from the ATR rule corpus to external standards bodies'
control catalogs. Each file enumerates which ATR rules (or rule categories)
supply evidence for which control subcategory.

These are **Informative Reference** documents — they describe how an
ATR-conformant engine's match output can be cited as runtime evidence
within an external assessment framework. They are not normative for ATR
itself; the normative crosswalk fields live on individual Rules under
`references.<framework>` (atr-method-v1.1.md §9.3).

## Index

| File | External framework | Status | Purpose |
|------|--------------------|--------|---------|
| [atr-to-nist-csf-2.0.md](./atr-to-nist-csf-2.0.md) | NIST CSF 2.0 (CSWP 29, Feb 2024) | Draft v1.0.0 | Draft; not submitted to NIST |

Planned (not yet drafted):

| File | External framework |
|------|--------------------|
| atr-to-etsi-ts-104223.md | ETSI TS 104 223 (UK NCSC AI Cyber Code of Practice upstream) |
| atr-to-eu-ai-act.md | EU AI Act Articles 10 + 14 + 15 |
| atr-to-iso-42001.md | ISO/IEC 42001 (AI Management System) |
| atr-to-oscal-aram.md | NIST OSCAL Assessment Layer (assessment-plan / assessment-results) |

## Convention

Each mapping file MUST:

1. State the source ATR version (`Mapped corpus`) and target framework version.
2. Map at the most granular level the target framework supports (CSF
   subcategory, ETSI sub-principle, EU AI Act article, etc).
3. Cite at least one example ATR Rule ID per external control where Rules
   exist for that control.
4. Be self-contained — readable by a reviewer who is not an ATR expert.
5. Carry an explicit "Open Items" section listing known gaps.

Updates to this index require a PR. New mapping files SHOULD be paired
with corresponding `references.<framework>` field additions in the
schema (`spec/atr-schema.yaml`) so individual Rules can declare their
contribution.
