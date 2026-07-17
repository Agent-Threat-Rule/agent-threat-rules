# Conformance Corpus Signing Procedure

**Last updated:** 2026-05-25
**License:** MIT
**Required reading for:** TSC Numbering Authority operators, conformance corpus contributors

---

## Why signing matters

Per `governance/STANDARD-THREAT-MODEL.md` Attacker class 5 (conformance corpus poisoner), a tampered `expected-results.json` allows a non-conformant engine to pretend to be conformant. The signing procedure makes any tampering visible to every consumer who verifies the signature.

The signing key is jointly held by:
- TSC Numbering Authority operators (per `governance/CHARTER.md` § 8.1, ≥2 named operators)
- Open Source Collective Inc. as fiscal sponsor (counter-signature)

This is a threshold key: both signatures are required for the published reference to validate. Loss or compromise of any single key does not enable forgery.

---

## Signing flow (normative)

### Step 1: Prepare canonical form

The file to be signed (e.g., `baseline/expected-results.json`) MUST be in canonical JSON form before signing:

```bash
# Canonicalize
jq -S --indent 2 . expected-results.json > expected-results.canonical.json
mv expected-results.canonical.json expected-results.json
```

Canonical rules:
- Keys alphabetically sorted at every level.
- Two-space indent.
- LF line endings (no CRLF).
- No trailing whitespace.
- UTF-8 encoding without BOM.

These rules match RFC 8785 (JSON Canonicalization Scheme) for the subset of JSON the corpus uses (no numbers requiring special handling).

### Step 2: Operator 1 signs

```bash
openssl pkeyutl -sign \
  -inkey ${OPERATOR_1_KEY_PATH} \
  -in expected-results.json \
  -rawin \
  -out expected-results.json.op1.sig
```

`${OPERATOR_1_KEY_PATH}` MUST be on a hardware token (YubiKey FIPS, SoloKey, etc.) and never leave the token. The operator's machine MUST be air-gapped or single-purpose for signing.

### Step 3: Operator 2 signs

Independently:

```bash
openssl pkeyutl -sign \
  -inkey ${OPERATOR_2_KEY_PATH} \
  -in expected-results.json \
  -rawin \
  -out expected-results.json.op2.sig
```

Operator 2 MUST be in a different physical location and on a different machine than Operator 1, per `governance/CHARTER.md` § 3.2 geographic-diversity requirement.

### Step 4: Open Source Collective Inc. counter-signature

OSC (fiscal sponsor) provides a counter-signature via their independent key:

```bash
openssl pkeyutl -sign \
  -inkey ${OSC_KEY_PATH} \
  -in expected-results.json \
  -rawin \
  -out expected-results.json.osc.sig
```

### Step 5: Assemble + publish

```bash
# Combine signatures into a single .sig manifest
cat > expected-results.json.sig.manifest <<EOF
{
  "schema_version": "1.0",
  "file": "expected-results.json",
  "signatures": [
    {"signer": "operator-1", "signature": "$(base64 -w 0 expected-results.json.op1.sig)"},
    {"signer": "operator-2", "signature": "$(base64 -w 0 expected-results.json.op2.sig)"},
    {"signer": "osc-fiscal-sponsor", "signature": "$(base64 -w 0 expected-results.json.osc.sig)"}
  ],
  "signed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# Submit to Sigstore Rekor transparency log for global discoverability
cosign sign-blob \
  --bundle expected-results.json.sigstore.bundle \
  expected-results.json
```

The Sigstore Rekor submission makes the signature globally discoverable and tamper-evident.

### Step 6: Commit

```bash
git add expected-results.json \
        expected-results.json.sig.manifest \
        expected-results.json.sigstore.bundle
git commit -s -m "conformance: sign expected-results.json for ${CORPUS_VERSION}"
```

---

## Verification procedure (for consumers)

```bash
# Step 1: Fetch the canonical form
curl -O https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/main/spec/conformance/baseline/expected-results.json
curl -O https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/main/spec/conformance/baseline/expected-results.json.sig.manifest

# Step 2: Verify each signature against the published public keys
jq -r '.signatures[] | .signature' expected-results.json.sig.manifest |
  while read sig_b64; do
    echo "$sig_b64" | base64 -d > /tmp/sig.bin
    openssl pkeyutl -verify \
      -in expected-results.json \
      -sigfile /tmp/sig.bin \
      -pubin -inkey ${PUBKEY_PATH} \
      -rawin
  done

# Step 3 (recommended): Verify via Sigstore transparency log
cosign verify-blob \
  --bundle expected-results.json.sigstore.bundle \
  expected-results.json
```

Public keys are published at:
- `legal/keys/conformance-signing-pubkey-operator-1.pem`
- `legal/keys/conformance-signing-pubkey-operator-2.pem`
- `legal/keys/conformance-signing-pubkey-osc.pem`
- Cross-verified against each TSC member's published GitHub SSH/GPG keyring

---

## Key rotation

Per `governance/CHARTER.md` § 5 (Tier 2 vote — simple majority of 5 of 9):
- Operator keys rotated **annually** or on any suspected compromise.
- OSC key rotated **biennially** or per OSC's internal key-management policy.

Rotation procedure:
1. Generate new key on hardware token.
2. Old key signs a "rotation announcement" that references the new key's pubkey.
3. New key signs a confirmation of the same rotation announcement.
4. Both signed announcements published to the repo and the Sigstore transparency log.
5. Old key destroyed (in hardware token) after a 30-day overlap window.
6. All `*.sig` files re-signed with the new key within the rotation window.

---

## What this procedure deliberately does NOT do

- Does not require certificate authority chain validation. Direct ed25519 public-key trust per the published keyring is the trust root. CA chains add complexity without adding security for this use case.
- Does not require timestamps from a TSA (Time Stamping Authority). Sigstore Rekor provides the timestamping function for free; an explicit TSA layer is redundant.
- Does not encrypt the signed content. Conformance corpus is CC0 public domain; encryption would only add operational friction.

---

## Bootstrapping

At the time of this document's creation (2026-05-25), the TSC is not yet ratified per `governance/CHARTER.md` § 11. The bootstrap signing flow:

1. The current Numbering Authority (Adam Lin, single maintainer) generates a temporary operator key.
2. OSC generates its counter-signature key (per OSC's standard procedures).
3. Initial conformance corpus (v1.0.0) is signed by these two keys.
4. On TSC seating, Operator-1 transitions to a TSC-elected operator; the temporary key is destroyed. The corpus is re-signed by the new operator (Operator-2 = existing OSC counter-signer, or a new threshold structure as the TSC decides).

This bootstrap step is documented to make the trust transition auditable.

---

## References

- RFC 8032 — Ed25519: https://datatracker.ietf.org/doc/html/rfc8032
- RFC 8785 — JSON Canonicalization Scheme: https://datatracker.ietf.org/doc/html/rfc8785
- Sigstore: https://www.sigstore.dev/
- `governance/STANDARD-THREAT-MODEL.md` § Attacker class 5
- `governance/CHARTER.md` § 7.3 (trademarks), § 8.1 (Numbering Authority)
