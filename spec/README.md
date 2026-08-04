# ATR Specification Index

**ATR — Agent Threat Rules**
**The open detection-rule standard for AI agent threats**

> **STATUS: PROPOSED v1.0 — NOT YET RATIFIED**
>
> The specifications in this directory are **drafts for community comment**
> in preparation for OASIS Open Project submission. They are NOT the current
> operating contract of the ATR engine. The TypeScript production engine at
> `npm:agent-threat-rules` continues to operate against the pre-spec-layer
> behavior — these documents describe the target state, not the current state.
>
> **No integration interface has changed.** Existing ecosystem integrations
> work unmodified. See `STANDARDIZATION-STATUS.md` at repo root for full
> proposed-vs-ratified-vs-implemented status.

**Status:** v1.0 — Draft for OASIS Open Project submission — NOT RATIFIED
**License:** MIT (spec docs, schemas, rules, reference implementations, and conformance corpus — one license for the whole project)
**Governance:** governance/CHARTER.md v2.0 (PROPOSED — TSC not yet formed)

---

## What ATR is, in one paragraph

ATR is an open machine-readable detection-rule standard for AI agent
threats. It is to AI agent security what Sigma is to SIEM detection,
YARA is to malware signatures, and CVE/CWE is to software
vulnerabilities. ATR rules are YAML files with declarative patterns
that any conformant engine can load and evaluate. The standard is
maintained by a 9-seat Technical Steering Committee (TSC) under
fiscal sponsorship of Open Source Collective Inc. The corpus,
reference implementations, and conformance test artifacts are all
MIT-licensed — the project uses a single license throughout.

---

## What this folder contains

```
spec/
├── README.md                          ← you are here
├── atr-schema.yaml                    ← (v0.1, existing) YAML rule schema
├── compliance-metadata.md             ← (existing) rule compliance field reference
├── stix-extension/                    ← (existing) STIX 2.1 extension bridge
│
├── SPEC.md                     ← (existing, repo root) rule format spec
├── atr-language-detection-v1.0.md     ← (new) deterministic language detection algorithm
├── atr-event-v1.0.md                  ← (new) OTEL-compatible event format (engine OUTPUT)
├── atr-observation-v1.0.md            ← (new) observation format (engine INPUT) + declared coverage
├── atr-profile-v1.0.md                ← (new) rule-set composition for tiered conformance
├── atr-correlation-v1.0.md            ← (new) multi-event correlation rule format
├── atr-method-v1.1.md                 ← (new) detection method extensions: signature/semantic/behavioral/trace
├── mappings/                          ← (new 2026-05-28) ATR → external framework crosswalk documents
│   ├── README.md                      ← mappings index
│   └── atr-to-nist-csf-2.0.md         ← NIST CSF 2.0 (NIST IR 8596 Informative Reference draft)
│
├── category-registry/
│   └── v1.0.yaml                      ← (new) versioned top-level category list
│
├── schema/                            ← (new) JSON Schemas
│   ├── rule.schema.json               ← rule format JSON Schema
│   ├── event.schema.json              ← event output JSON Schema
│   ├── observation.schema.json        ← observation input JSON Schema
│   ├── profile.schema.json            ← profile JSON Schema
│   └── correlation.schema.json        ← correlation rule JSON Schema
│
└── conformance/                       ← (Phase 2) test corpus + expected-results.json
    └── baseline/                      ← only directory populated today;
                                         profiles/ and correlation/ are not
                                         yet created (see STANDARDIZATION-STATUS.md)
```

---

## The four-layer standard

ATR separates four concerns. This separation is the foundation of
the standard's architecture per governance/CHARTER.md § Appendix A.

| Layer | Lives in | Governance |
|---|---|---|
| **1. Specification** (the immutable contract — what conformant implementations must do) | `spec/` + repo-root `SPEC.md` | TSC AEP process (Tier 3) |
| **2. Reference implementation** (proves the spec is buildable) | `engines/typescript/` + `engines/python/` + `engines/go/` | Maintainer-led; tested against `spec/conformance/` |
| **3. Production engines + integrations** (consumers of the spec) | `src/` (existing TypeScript engine), `integrations/{rampart,sigma,sentinel,splunk,opentelemetry}/` | Vendor-controlled; pass conformance to claim conformance |
| **4. Conformance test corpus** (objective evidence anyone implements correctly) | `spec/conformance/` | TSC; signed with ed25519 key |

---

## How to read the spec

If you are **implementing an ATR engine**, read in this order:

1. `SPEC.md` — rule format. Defines what a rule is and how
   it evaluates.
2. `spec/atr-schema.yaml` and `spec/schema/rule.schema.json` —
   machine-readable rule schemas.
3. `spec/atr-language-detection-v1.0.md` — the deterministic
   algorithm your engine MUST implement for per-language conditions.
4. `spec/atr-event-v1.0.md` and `spec/schema/event.schema.json` —
   the event format your engine MUST emit when a rule fires.
5. `spec/category-registry/v1.0.yaml` — categories your engine
   recognises (and forward-compatibility for unknown categories).
6. `spec/conformance/` (when published) — the test corpus your
   engine MUST pass.
7. `spec/atr-profile-v1.0.md` + `spec/atr-correlation-v1.0.md` —
   RECOMMENDED for full conformance, optional for baseline.
8. `spec/atr-method-v1.1.md` — OPTIONAL. Read only if your engine
   implements detection methods beyond `pattern` (signature, semantic,
   behavioral, or trace). v1.0 Pattern conformance does NOT require
   this document.

If you are **authoring rules**, read:

1. `SPEC.md` — rule fields and evaluation semantics
2. `spec/atr-schema.yaml` — required and optional fields
3. `spec/category-registry/v1.0.yaml` — pick a category
4. `spec/atr-language-detection-v1.0.md` — only if writing
   per-language conditions
5. Existing rules in `rules/<category>/*.yaml` for patterns

If you are **adopting ATR in your product**, read:

1. `README.md` (repo root) — overview
2. `governance/CHARTER.md` — governance model
3. `spec/atr-profile-v1.0.md` — pick which profile your product
   claims conformance to
4. `spec/atr-event-v1.0.md` — your product's output integration
5. `certification/program-guide.md` (when published) —
   ATR-Certified™ program

If you are **a regulator or standards-body reviewer**, read:

1. `governance/CHARTER.md` — TSC structure, IPR, fiscal sponsorship
2. `governance/STANDARD-THREAT-MODEL.md` — what attacks against
   the standard itself we've designed for
3. `spec/README.md` (this file) — index
4. `ai-rmf-oscal-catalog` (separate repo) — NIST AI RMF mapping

If you are **a sovereign authority** considering issuing rules in a
sovereign sub-range:

1. `governance/CHARTER.md` § 8 — sovereign sub-range governance
2. `spec/atr-profile-v1.0.md` — sovereign profile examples
3. `spec/schema/rule.schema.json` — `provenance.attestation_signature`
   field

---

## Conformance levels

A conformant ATR engine claim names what the engine can do. Three
levels:

**Level 1 — Baseline Conformance.** Engine implements:
- Rule schema (`spec/schema/rule.schema.json`)
- Event schema (`spec/schema/event.schema.json`)
- Language detection (`spec/atr-language-detection-v1.0.md`)
- Category registry forward-compat (`spec/category-registry/v1.0.yaml`)
- Passes `spec/conformance/baseline/` corpus

**Level 2 — Profile Conformance.** Adds:
- Profile resolution (`spec/atr-profile-v1.0.md` and schema)
- Multiple profile loading + isolated evaluation
- Passes `spec/conformance/profiles/` corpus

**Level 3 — Correlation Conformance.** Adds:
- Observation ingest (`spec/atr-observation-v1.0.md` and schema), including
  a machine-readable coverage declaration. Correlation join keys are
  defined there; an engine cannot claim L3 while treating `session.id`
  and `agent.id` as optional.
- Correlation rule evaluation (`spec/atr-correlation-v1.0.md` and schema)
- State management across events
- Implements at least `temporal_sequence`, `count_threshold`, and
  `chain_propagation` correlation types
- Passes `spec/conformance/correlation/` corpus (not yet created)

Engines may claim any subset of levels (e.g., L1+L3 without L2). The
ATR-Certified™ program awards trust marks per level.

---

## Versioning policy

The spec uses SemVer with the following rules:

- **PATCH** (`1.0.x`): editorial changes, additional examples,
  conformance corpus expansion. Engines MUST continue to pass.
- **MINOR** (`1.x.0`): backward-compatible field additions (e.g.,
  new optional rule field). Engines SHOULD adopt within 6 months.
- **MAJOR** (`x.0.0`): breaking changes. Engines MUST adopt to
  claim new-version conformance. Minimum 12-month deprecation
  window for the prior major version.

Each spec document declares its individual version (e.g.,
`atr-event-v1.0.md`). The overall spec version is the lowest of
all individual spec versions.

Major-version bumps require ATR Enhancement Proposal (AEP) Tier 3
vote per governance/CHARTER.md § 4.

---

## Status of each spec component (May 2026)

| Component | Version | Status | Files |
|---|---|---|---|
| Rule format | v1.0 | existing-draft | `SPEC.md`, `spec/atr-schema.yaml`, `spec/schema/rule.schema.json` |
| Event format (output) | v1.0 | draft (new May 2026) | `spec/atr-event-v1.0.md`, `spec/schema/event.schema.json` |
| Observation format (input) | v1.0 | draft (new July 2026) | `spec/atr-observation-v1.0.md`, `spec/schema/observation.schema.json` |
| Profile format | v1.0 | draft (new May 2026) | `spec/atr-profile-v1.0.md`, `spec/schema/profile.schema.json` |
| Correlation format | v1.0 | draft (new May 2026) | `spec/atr-correlation-v1.0.md`, `spec/schema/correlation.schema.json` |
| Language detection algorithm | v1.0 | draft (new May 2026) | `spec/atr-language-detection-v1.0.md` |
| Category registry | v1.0 | draft (new May 2026) | `spec/category-registry/v1.0.yaml` |
| Conformance corpus | v1.0 | planned Phase 2 | `spec/conformance/` |

---

## How this spec evolves

New spec components and changes to existing components go through
the **ATR Enhancement Proposal (AEP)** process defined in
governance/CHARTER.md § 5.

AEP template at `rfc/TEMPLATE-AEP.md` (Phase 3 deliverable). Open
AEPs are tracked in `rfc/`.

Reported issues and bugs in the spec go through GitHub Issues with
the `spec-bug` label, expedited as Tier 2 votes (simple majority of
5 of 9 TSC).

---

## Cross-references to related specs

- **Sigma** (SIEM detection rules): different domain (SIEM event
  patterns vs AI-agent runtime patterns), but ATR's rule structure
  draws explicitly on Sigma's design and the bidirectional Sigma ↔
  ATR converter at `integrations/sigma/` (Phase 4 deliverable)
  lets adopters cross-pollinate.
- **STIX 2.1** (Structured Threat Information eXpression): ATR
  publishes a STIX 2.1 extension at `spec/stix-extension/` so ATR
  events flow into STIX-native CTI platforms.
- **OSCAL** (NIST compliance): ATR events map to OSCAL `observation`
  records per `spec/atr-event-v1.0.md` § OSCAL mapping. Companion
  CC0 catalog at `Agent-Threat-Rule/ai-rmf-oscal-catalog`.
- **MITRE ATLAS**: each ATR rule declares MITRE ATLAS technique
  mappings in its `references.mitre_atlas` field. Current coverage
  100 of 113 ATLAS techniques per `docs/MITRE-ATLAS-MAPPING.md`.
- **OWASP Agentic Top 10**: each ATR rule declares OWASP Agentic
  mappings in `references.owasp_agentic`. Full 10/10 category
  coverage per `docs/OWASP-AGENTIC-MAPPING.md`.
- **EU AI Act Article 50**: ATR events carry the evidence fields
  required for Article 50 deployer obligations (signature, agent
  identity, deployment-time provenance). See
  `spec/atr-event-v1.0.md` § Required fields.
- **C2PA** (Content Credentials): when a deepfake-related rule
  fires on agent-generated media, the event includes a C2PA
  manifest reference if available.

---

## Submission to standards bodies

The spec is being prepared for:

1. **OASIS Open Project (primary)** as adjacent to CoSAI.
   Target: Q3 2026 acceptance, Q1 2027 first Committee Specification.
2. **NIST CAISI (citation target)**.
   No formal submission window currently open; awaiting next RFI.
3. **IETF (informational draft, transport / OTEL emission only)**
   when reference implementations are stable.

The spec is not yet submitted to any standards body; current state
is "Draft v1.0, community-maintained at GitHub, transitioning to
OASIS Open Project."

---

## Contact

- Spec issues: GitHub Issues with label `spec-bug` or `spec-question`
- Spec proposals: GitHub Pull Requests with AEP template
- Maintainer: Adam Lin <adam@agentthreatrule.org>
- Fiscal sponsor: Open Source Collective Inc. (501(c)(3),
  EIN 81-1567737)
- TSC (post-ratification): tsc@agentthreatrule.org (mailing list, public)
