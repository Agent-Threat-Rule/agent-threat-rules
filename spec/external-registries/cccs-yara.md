# ATR ↔ CCCS-Yara Cross-Reference Convention

Version: 1.0.0
Status: Draft
Date: 2026-05-29
Editor: Adam Lin (林冠辛) <adam@agentthreatrule.org>
Trigger: CybercentreCanada/CCCS-Yara#100 closing comment (2026-05-26)
  by cccs-rs: "better to handle the cross-reference on the ATR side at
  this time... we can revisit later if we want to standardize across
  the board"

---

## 1. Purpose

CCCS-Yara is the Canadian Centre for Cyber Security's public YARA rule
collection. Some ATR Rules cover threats that overlap with CCCS-Yara
rules — for example, an ATR rule detecting a malicious agent skill
package may share a SHA-256 indicator with a CCCS-Yara rule detecting
the dropper binary that delivered it.

When such overlap exists, ATR uses `references.external_references.cccs_yara`
to cite the corresponding CCCS-Yara rule name. ATR does NOT execute or
validate the CCCS-Yara rule; the reference is evidence only.

## 2. Format

ATR rule YAML carries the cross-reference under the existing
`references.external_references.cccs_yara` field (per
`spec/atr-schema.yaml`):

```yaml
references:
  external_references:
    cccs_yara:
      - "APT_CN_BEACON_2024"
      - "Malware_RAT_AsyncRAT"
```

Values are opaque strings matching the `rule` keyword in the upstream
`.yar` file at https://github.com/CybercentreCanada/CCCS-Yara. ATR
authors SHOULD verify the rule name exists in the upstream repository
at authoring time and SHOULD pin the CCCS-Yara commit hash in
`references.research` if long-term stability matters:

```yaml
references:
  external_references:
    cccs_yara: ["APT_CN_BEACON_2024"]
  research:
    - "CCCS-Yara@5d2f8a (https://github.com/CybercentreCanada/CCCS-Yara/blob/5d2f8a/...)"
```

## 3. Semantics

The cross-reference is non-normative in either direction:

- ATR engines MUST NOT load, parse, or execute CCCS-Yara rules.
- CCCS-Yara engines MUST NOT load, parse, or execute ATR rules.
- The cross-reference is data flowing through SIEM / SOAR / OSCAL
  pipelines so analysts can pivot between ecosystems.

When an ATR Rule fires and emits a Match (SPEC.md §7), engines MAY
include the cited `external_references.cccs_yara` entries in the
Match output to help downstream correlation. The reference does NOT
guarantee that running CCCS-Yara on the same Input would also fire.

## 4. Versioning

CCCS-Yara rule names are NOT versioned in the upstream repository.
A rule's content may change while keeping the same name. ATR Rule
authors SHOULD:

- Pin a commit hash in `references.research` when first authoring the
  cross-reference.
- Re-verify the cross-reference annually as part of rule maintenance.
- Drop the cross-reference (do NOT silently update) if the upstream
  CCCS-Yara rule changes scope.

## 5. Reverse-direction convention

If CCCS-Yara contributors later choose to cite ATR Rule IDs from their
side, the recommended field is `metadata.atr_rule_ids` on the upstream
`.yar` rule. This convention is documented here as a courtesy; the
authoritative source is CCCS-Yara's own metadata conventions if and
when they choose to adopt it.

## 6. Example worked cross-reference

A future ATR Rule covering skill-package supply-chain compromise via
known-malicious SHA-256 indicators:

```yaml
id: ATR-2026-DRAFT-cccs-cross-ref-example
title: "Skill package matching CCCS-Yara dropper signature"
status: draft
severity: critical
description: >
  Detects skill packages whose content hash matches a CCCS-Yara
  rule for a known dropper. Cross-references the CCCS-Yara rule
  name as evidence that the indicator is also recognised by the
  Canadian Cybercentre's public corpus.
tags:
  category: skill-compromise
  scan_target: skill
detection:
  method: signature
  signature:
    indicators:
      - type: sha256
        value: "<hash>"
        target_field: skill.content
references:
  external_references:
    cccs_yara: ["Malware_Dropper_GenericLoader_2024"]
  research:
    - "CCCS-Yara@<commit-hash>"
response:
  actions: [block_request, log_alert]
```

When a Match fires, the Match output (SPEC.md §7) can carry
`external_references.cccs_yara` so a SOC analyst pivoting from the
ATR-side detection can immediately query the same SHA-256 against
the CCCS-Yara corpus.

## 7. Open Items

- No reciprocity yet from CCCS-Yara side. Per cccs-rs's 2026-05-26
  comment, they may revisit standardization "across the board" once
  ATR has shipped worked examples. Aim: accumulate ≥10 cross-ref
  examples over 3-6 months, then re-engage cccs-rs with adoption
  evidence.
- Schema slot is intentionally generic. If CCCS-Yara later publishes
  formal rule IDs (UUIDs / hashes), this convention extends naturally;
  authors simply use the new identifier format.

## 8. References

- Schema field: `spec/atr-schema.yaml` → `references.external_references.cccs_yara`
- Closing comment: https://github.com/CybercentreCanada/CCCS-Yara/pull/100
- ATR ↔ external registry convention: this document
