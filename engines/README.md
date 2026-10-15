# ATR Reference Implementations

Four-layer separation per `spec/README.md`:

| Layer | Lives in | This directory |
|---|---|---|
| 1. Specification | `spec/` + repo root | — |
| **2. Reference implementation** | **`engines/`** | **← you are here** |
| 3. Production engines + integrations | `src/`, `integrations/` | — |
| 4. Conformance test corpus | `spec/conformance/` | — |

A **reference implementation** is a clean implementation of the spec
intended to prove the spec is buildable in a given language. It is
not necessarily production-grade; it is correctness-grade.

A **production engine** can be a reference impl that has been
hardened, AND/OR a vendor's independent implementation that passes
conformance.

---

## Implementations

| Directory | Status | Language | Conformance |
|---|---|---|---|
| `typescript/` | Reference (production-grade, existing engine moved here in Phase 3) | TypeScript | L1 baseline pending corpus availability |
| `python/` | Skeleton + interface contract (Phase 4) | Python 3.11+ | TBD |
| `go/` | Skeleton + interface contract (Phase 4) | Go 1.22+ | TBD |

---

## What "ATR-conformant engine" means

An engine claims conformance by:

1. Loading the canonical rule corpus (a specific pinned version).
2. Processing the published conformance test corpus in
   `spec/conformance/`.
3. Producing an engine-results.json output matching
   `spec/conformance/expected-results.schema.json`.
4. Meeting the thresholds in
   `spec/conformance/<level>/manifest.json`.
5. (Optional) Publishing an Implementation Conformance Statement
   per `spec/conformance/templates/ICS-template.md` (post-Phase 4).

Conformance levels (L1 / L2 / L3) per `spec/README.md`.

---

## Why three languages

Per the deep research scan grounding `governance/CHARTER.md`:

- **TypeScript** — the current production language. Covers most agent
  platform integrations (Microsoft AGT, Cisco AI Defense, Anthropic
  SDK ecosystem). Stays as reference + production engine.
- **Python** — covers SOC / SecOps ecosystem (Splunk SOAR, Sumo
  Logic, Datadog), Python-first ML platforms, and Python-based
  evaluation tooling. Enterprise SOC teams cannot run TS-only engines.
- **Go** — covers SIEM / EDR vendor ecosystem (Elastic, Wazuh,
  Falco), cloud-native + Kubernetes ingestion, and the broader
  cloud-security tooling stack.

These three cover ~90% of likely production deployments. Additional
languages (Rust, Java) can be added via AEP per
`governance/CHARTER.md` § 5.2.

---

## How to add a new language

Open an AEP per `governance/CHARTER.md` § 5.2 with:
1. Justification (which adoption ecosystem the language opens)
2. Maintainer commitment (≥1 individual willing to maintain the impl)
3. Scaffolding plan
4. CI integration plan
5. Conformance test execution plan

Tier 3 vote (2/3 of 7 of 9 TSC) for spec-implication acceptance;
the impl itself can land under Tier 1 (lazy consensus) once the AEP
passes.

---

## Conformance gate per language

Each language's reference impl MUST:
- Pass the L1 baseline conformance corpus
- Be CI-tested on every PR against the corpus
- Document its `engine_id` per `spec/atr-event-v1.0.md`
- Publish coverage reports per release

Failures in any language's conformance suite block the next ATR
release per `governance/CHARTER.md` § 11.1.
