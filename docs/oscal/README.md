# ATR Detection Coverage for NIST SP 800-53 Rev 5 (OSCAL Component Definition)

## What this is

This directory contains a single OSCAL component-definition,
`atr-component-definition.json`, that maps the Agent Threat Rules (ATR) open
detection-rule standard to the **detection and continuous-monitoring aspect** of
selected NIST SP 800-53 Rev 5 controls.

ATR is an MIT-licensed, vendor-neutral open standard for detecting AI-agent
security threats: prompt injection and jailbreak, tool poisoning, skill
compromise, malicious MCP servers, excessive autonomy, context and credential
exfiltration, privilege escalation, and data and model abuse. ATR is detection
content: a set of pattern-based rules that produce detections and structured
evidence as a fast first-pass filter over agent-layer input and tool traffic.

The artifact is expressed in OSCAL (the NIST Open Security Controls Assessment
Language) so that it can be read directly by control-assessment tooling. It
validates against the official OSCAL v1.2.2 component-definition JSON schema
(`oscal_component_schema.json`, included in this directory).

## What this is NOT

- **Not NIST-endorsed, adopted, approved, or certified.** NIST has not reviewed
  ATR. This is a community mapping that *references* the public NIST
  SP 800-53 Rev 5 control catalog. Nothing here is a NIST product or an
  endorsement by NIST.
- **Not an independent third-party evaluation.** This mapping was prepared by a
  maintainer of ATR. It is a self-assessment by the standard's author, not a
  disinterested external assessment. Where this document uses the word
  "independent," it means independent of NIST — not independent of ATR.
- **Not a compliance guarantee.** ATR does not satisfy, meet, or fulfill any
  control. A control is satisfied by people, process, and multiple technologies
  working together. ATR contributes to the detection/monitoring dimension of a
  control and generates supporting evidence — that is all.
- **Detection aspect only.** For every mapped control, the artifact states
  explicitly what ATR does not cover (no collection/SIEM infrastructure, no
  alerting or analyst workflow, no enforcement, blocking, IAM/RBAC, antivirus or
  EDR, no quarantine or remediation, no logging subsystem, no authenticity
  attestation, no policy or configuration baseline).
- **Pattern/regex detection with documented limits.** Detection is predominantly
  deterministic pattern matching. It can miss paraphrased attacks, semantic
  equivalents, non-English payloads, novel or undocumented attacks, multi-turn
  behavioral attacks, multi-modal inputs, token smuggling, and adversarial-suffix
  attacks. Deploy ATR as one layer in a defense-in-depth program; do not rely on
  it alone.

## Verified source data

All numbers below were verified live against the rule files on disk at generation
time, not recalled from memory.

- **Rule count:** 655 rule files across 10 categories.
  - prompt-injection 223, agent-manipulation 106, context-exfiltration 104,
    tool-poisoning 68, skill-compromise 45, model-abuse 37,
    privilege-escalation 35, excessive-autonomy 29, data-poisoning 5,
    model-security 3.
- **ATR commit SHA (pinned):**
  `cb749927a2c4f9bdcbcd1a5f3caecaa6b1f07c1f`
  (`origin/main`; verified live against a clean checkout of this commit).
- **Maturity disclosure (two distinct YAML fields, both verified live;
  both gate which rules fire, neither alone is canonical):**
  - `status` field gates loading. Rules with `status` draft or deprecated are
    never evaluated (the engine skips them unconditionally), so on this commit
    39 rules (37 draft + 2 deprecated) never fire and 616 are eligible to fire
    in the engine's default lane. Counts by `status`: stable 59,
    experimental 557, draft 37, deprecated 2.
  - `maturity` field gates the optional detection lane: `enforce` fires `stable`
    only, `alert` fires `stable`+`test`, and the default lane (`hunt`) fires all
    non-deprecated maturities. So at the default configuration the `maturity`
    field does not restrict which rules fire. Counts by `maturity`: stable 132,
    test 448, experimental 61, draft 14. There are zero rules with a deprecated
    maturity, and the single largest tier is `test` (448), not experimental.
  - Only 125 rules are enforce-eligible (status not draft/deprecated **and**
    maturity `stable`).
  - By either field, only a minority of rules carry a stable designation. The
    full rule count is not represented as production-grade.

Note on `data/stats.json`: on this pinned commit (`origin/main`,
`cb749927a2c4f9bdcbcd1a5f3caecaa6b1f07c1f`) `data/stats.json` reports 655 rules,
matching the 655 rule files on disk; the earlier 652/655 drift is resolved at
this commit. Disk remains authoritative. Always re-verify rule counts, the SHA,
and the maturity/status breakdowns against the live repository before any
external citation, because rules change frequently.

## Controls mapped (7)

The artifact maps ATR to the detection/monitoring aspect of these SP 800-53 Rev 5
controls. Each is scoped to detection-and-monitoring only:

- **SI-4 (System Monitoring)** — anchor mapping; ATR is fundamentally agent-layer
  monitoring content spanning all 655 rules across all 10 categories
  (prompt-injection, agent-manipulation, context-exfiltration, tool-poisoning,
  skill-compromise, model-abuse, privilege-escalation, excessive-autonomy,
  data-poisoning, and model-security).
- **SI-10 (Information Input Validation)** — detection of adversarial agent
  inputs (prompt injection, agent manipulation); not input enforcement or
  sanitization.
- **SI-3 (Malicious Code Protection)** — detection of malicious-code indicators
  in agent skills (skill-compromise) and MCP tool definitions (tool-poisoning)
  only; not antivirus/EDR, no quarantine or removal. Data/knowledge-base/memory
  poisoning is deliberately excluded (not executable malicious code), and ATR
  detects no OS command injection or RCE under SI-3.
- **SR-11 (Component Authenticity)** — detection of counterfeit/tampered/poisoned
  agent supply-chain components; not provenance or signature attestation.
- **CM-7 (Least Functionality)** — detection of an agent exceeding its intended
  function; not configuration or enforcement of a baseline.
- **AC-6 (Least Privilege)** — detection of privilege-overreach signals; not
  IAM/RBAC enforcement.
- **AU-2 (Event Logging)** — informs which agent events are worth logging; does
  not generate, store, or retain audit records. AU-6 and audit-record generation
  are deliberately not claimed.

### Controls considered but deliberately not claimed

These nearby controls were evaluated and intentionally left unmapped, so the
scope is explicit rather than silent:

- **AU-6 (Audit Record Review, Analysis, and Reporting)** — ATR performs no
  analyst review, correlation, or reporting workflow.
- **SI-7 (Software, Firmware, and Information Integrity)** — ATR detects tamper
  and integrity-manipulation *attempts* in agent traffic but does not establish
  or verify integrity baselines for software, firmware, or information.
- **RA-3 (Risk Assessment)** — ATR is detection content, not a risk-assessment
  process or methodology.
- **RA-5 (Vulnerability Monitoring and Scanning)** — ATR's CVE-derived rules
  detect attack *payloads* in agent traffic; they do not scan hosts or
  components for vulnerabilities.
- **SR-3 (Supply Chain Controls and Processes)** — covers supply-chain process
  and policy; ATR detects only malicious-component indicators, which are
  reflected under SR-11 (Component Authenticity), not SR-3.

## Where this lives and how it could honestly be offered

This artifact is intended to live in the ATR repository as a standards-native
OSCAL example, alongside ATR's other mappings (OWASP, MITRE ATLAS, etc.). It is a
machine-readable expression of ATR's existing detection-to-control mapping, in
the format NIST's own tooling consumes.

It could honestly be offered as:

- A **community example** of mapping an open detection standard's coverage to
  SP 800-53 Rev 5, using OSCAL.
- A reference shared in the **NIST COSAiS / OSCAL collaboration Slack** as
  community input, clearly labeled as a community artifact authored by an ATR
  maintainer (a self-assessment, not a third-party evaluation; see the
  authorship and conflict-of-interest note above).

It must never be presented as NIST-adopted, NIST-endorsed, or as evidence of
compliance. The honest framing is: "an open standard's detection coverage,
mapped to the detection aspect of SP 800-53 controls, in OSCAL."

## Vendor neutrality

ATR is an MIT-licensed, vendor-neutral open standard. This artifact references
only ATR and the public NIST SP 800-53 Rev 5 catalog. It does not reference,
depend on, or imply any commercial product. ATR's neutrality as an open standard
is intentional and is preserved here.

## Files

- `atr-component-definition.json` — the OSCAL component-definition (validates
  against OSCAL v1.2.2 component schema).
- `oscal_component_schema.json` — the official NIST OSCAL v1.2.2
  component-definition JSON schema, used for validation.
- `README.md` — this cover note.

## How to re-validate

Using ajv (draft-07, with formats, non-strict, as NIST OSCAL JSON schemas
require):

```
ajv validate \
  -s oscal_component_schema.json \
  -d atr-component-definition.json \
  -c ajv-formats --strict=false --spec=draft7
```

Expected output: `atr-component-definition.json valid`.
