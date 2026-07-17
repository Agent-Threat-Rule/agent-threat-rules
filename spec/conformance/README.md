# ATR Conformance Test Corpus v1.0

> **STATUS: PROPOSED v1.0 — NOT YET RATIFIED.** This corpus structure
> describes a target conformance program for community comment. No engine
> currently claims formal ATR conformance; existing ecosystem integrations
> consume rules directly without a conformance claim. See
> `STANDARDIZATION-STATUS.md` at repo root for full status.

**Status:** Draft for ratification with first OASIS Open Project artifact publication — NOT RATIFIED
**License:** MIT (a single license across the whole project)
**Signature (on ratification):** ed25519 signature over `manifest.json` and `expected-results.json` for each level, signed by the TSC's hardware-token-threshold key (see `SIGNING.md`)

---

## Purpose

The conformance test corpus is **the objective measure of "is this engine ATR-conformant."** Any implementation that loads the rule corpus, processes the conformance input fixtures, and emits the expected ATR Event Format output for each fixture is conformant. An implementation that does not pass the conformance corpus cannot claim conformance.

This document specifies the structure of the corpus, the procedure for running it, and the procedure for publishing a signed reference result.

The corpus is MIT-licensed so that any third-party audit lab, sovereign authority, or commercial vendor can ingest it under the same permissive terms as the rest of ATR.

---

## Three conformance levels

Per `spec/README.md` § Conformance levels:

| Level | Corpus subdirectory | Required for trust mark | Engines expected to pass |
|---|---|---|---|
| **L1 — Baseline** | `baseline/` | ATR-Certified™ Skill, ATR-Certified™ Enterprise | All conformant engines |
| **L2 — Profile** | `profiles/` | ATR-Certified™ Enterprise (+ Profile claim) | Engines claiming profile-resolution capability |
| **L3 — Correlation** | `correlation/` | ATR-Certified™ Enterprise (+ Correlation claim) | Engines claiming correlation capability |

L1 is required. L2 and L3 are independent additive levels — an engine may claim L1+L3 without L2.

---

## Directory layout

```
spec/conformance/
├── README.md                          ← you are here
├── SIGNING.md                         ← signing procedure for expected-results.json
├── manifest.schema.json               ← JSON Schema for manifest files
├── expected-results.schema.json       ← JSON Schema for engine report
│
├── baseline/                          ← L1 — required for any conformance claim
│   ├── manifest.json                  ← signed; lists all baseline test cases
│   ├── manifest.json.sig              ← ed25519 signature (binary)
│   ├── expected-results.json          ← canonical expected rule firings per fixture
│   ├── expected-results.json.sig      ← ed25519 signature
│   ├── attack-fixtures/               ← true-positive: rules SHOULD fire
│   │   └── *.json                     ← each fixture is one input event
│   ├── benign-fixtures/               ← true-negative: rules MUST NOT fire (FP corpus)
│   │   └── *.md                       ← SKILL.md format, 432+ samples from data/skill-benchmark/benign/
│   ├── language-detection-fixtures/   ← language detection algorithm corpus
│   │   └── v1.0.json
│   └── research-mentions/             ← text that mentions attacks but is not attack
│       └── corpus.jsonl
│
├── profiles/                          ← L2 — required for profile-resolution claim
│   ├── manifest.json                  ← signed; lists profile-resolution test cases
│   ├── manifest.json.sig
│   ├── expected-results.json          ← per-profile expected rule sets
│   ├── expected-results.json.sig
│   └── fixtures/
│       └── {profile-id}.json          ← profile YAML + expected resolved-rule list
│
└── correlation/                       ← L3 — required for correlation claim
    ├── manifest.json
    ├── manifest.json.sig
    ├── expected-results.json
    ├── expected-results.json.sig
    └── streams/
        ├── {correlation-rule-id}.positive.jsonl  ← stream that SHOULD produce correlation event
        └── {correlation-rule-id}.negative.jsonl  ← stream that MUST NOT produce
```

---

## Running the conformance corpus

### Step 1: Engine setup

The engine under test must:
1. Load the canonical ATR rule corpus at a fixed version (e.g.,
   `agent-threat-rules@3.1.0`). Engine MUST NOT modify rules during
   test.
2. Be configured with:
   - Default profile (no profile-based filtering)
   - Standard severity threshold (no rule filtering by severity)
   - Standard maturity filter (load `stable`, `test`, AND `draft`
     rules for full L1 evaluation; production deployments may
     filter)
3. Have unredacted-mode disabled (so output matches the reference
   redacted form).

### Step 2: Process baseline fixtures

For each file in `baseline/attack-fixtures/`:
1. Load the input event (JSON conforming to `spec/schema/event.schema.json`).
2. Apply the engine's standard evaluation pipeline.
3. Capture every rule that fires.
4. Compare against `baseline/expected-results.json` for that fixture's `event_id`.

For each file in `baseline/benign-fixtures/`:
1. Load the input (typically a SKILL.md text).
2. Wrap in standard `mcp_exchange` event format with `scanContext: 'skill'`.
3. Apply standard evaluation.
4. Capture all rule fires.
5. Expected fires = empty set. Any fire = FP → conformance failure.

For each file in `baseline/research-mentions/corpus.jsonl`:
1. Each line is one input record.
2. Same as benign — expected fires = empty set.

For each file in `baseline/language-detection-fixtures/v1.0.json`:
1. Each record has input text + expected language code.
2. Run engine's language detection.
3. Output language code MUST match expected exactly.

### Step 3: Score

Engine produces an `engine-results.json` matching
`expected-results.schema.json`. Score against
`baseline/expected-results.json`:

- **Precision** = TPs / (TPs + FPs)
- **Recall** = TPs / (TPs + FNs)
- **Language-detection accuracy** = matching codes / total fixtures

Conformance pass = precision ≥ 1.0 AND recall ≥ 0.95 AND language
detection accuracy = 1.0. The 0.95 recall threshold accommodates
intentionally-narrow rules that don't cover every variant; the
1.0 precision requirement is strict because false-positive storms
break SOC trust.

### Step 4: Publish

If conformance passes, the engine vendor MAY publish an
"Implementation Conformance Statement" (ICS) per the template in
`spec/conformance/templates/ICS-template.md` (Phase 3
deliverable). The ICS includes:
- Engine identifier (`<vendor>/<product>/<version>`)
- Spec version tested against (e.g., `1.0`)
- Conformance levels claimed (subset of {L1, L2, L3})
- Result hash for verification
- Reference back to the conformance corpus version + signature

ICS publication is the vendor's responsibility. The TSC does NOT
maintain a centralized conformance registry in v1.0 (that is the
ATR-Certified™ program's role, see `certification/`).

---

## Adding fixtures

Adding to the conformance corpus is a Tier 3 (AEP) action because
it changes what engines must pass to claim conformance. AEP
template at `rfc/TEMPLATE-AEP.md` (Phase 3 deliverable).

Common fixture additions:
- **New attack class.** Adding a fixture demonstrating a class of
  attack the corpus didn't previously cover.
- **New benign edge case.** Adding a SKILL.md sample that resembles
  an attack but is benign (precision testing).
- **New language fixture.** Adding language-detection edge cases.

Fixtures MUST be MIT-licensed or otherwise legally clear for permissive
inclusion. Synthetic / generated fixtures are preferred over
real-world incident data unless the incident data is already
public (e.g., disclosed CVE proof-of-concept payloads).

---

## Signed expected-results

The `expected-results.json` for each level is signed with the TSC's
threshold ed25519 signing key. The signature is in
`expected-results.json.sig` (binary).

Consumers MUST verify the signature before trusting the file. The
public verifying key is published at:
- `legal/keys/conformance-signing-pubkey.pem` (Phase 3
  deliverable)
- The corresponding TSC member's GitHub profile keyring (cross-
  verification)
- A Sigstore public-good transparency log entry (Phase 2 deliverable
  with first signed manifest publication)

Signature verification flow:
```bash
openssl pkeyutl -verify \
  -in baseline/expected-results.json \
  -sigfile baseline/expected-results.json.sig \
  -pubin -inkey conformance-signing-pubkey.pem \
  -rawin
```

Or programmatic equivalent in any ed25519 library.

See `SIGNING.md` for the publication and rotation procedure.

---

## Versioning

The corpus is versioned per the spec major.minor (e.g., `v1.0`).
Patch-level changes (additional fixtures that don't change
expected outcomes for existing fixtures) increment the corpus
patch version and re-sign the manifests.

Engines that pass `v1.0.0` may still pass `v1.0.1` (which only
adds fixtures), but a fresh signed result MUST be produced and
published per the publishing flow.

Major corpus changes (which would invalidate prior conformance
claims) require a 12-month deprecation window for the prior
version, during which both versions are signed and available.

---

## Privacy + data residency

All fixtures in this corpus are MIT-licensed and contain
no PII. Synthetic data only. Where the corpus draws on
real-world incidents (e.g., the Mini Shai-Hulud IOC strings), only
the IOC strings are included, not user / victim data.

No corpus content is restricted by jurisdiction. Adopters may use
the corpus anywhere.

---

## References

- `spec/atr-event-v1.0.md` — Event format the corpus tests against
- `spec/atr-profile-v1.0.md` — Profile resolution test scope
- `spec/atr-correlation-v1.0.md` — Correlation rule test scope
- `governance/CHARTER.md` § 7 — Licensing
- `governance/STANDARD-THREAT-MODEL.md` § Attacker class 5 —
  Corpus integrity threats and mitigations
- `SIGNING.md` — Signing procedure
