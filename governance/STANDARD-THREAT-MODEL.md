# ATR Standard Threat Model

> **STATUS: PROPOSED v1.0 — NOT YET RATIFIED**
>
> Companion document to `governance/CHARTER.md` (also proposed). See
> `STANDARDIZATION-STATUS.md` at repo root for full status of all
> standardization scaffolding. **No integration interface has changed.**

**Scope:** Attacks against the ATR standard itself — the rule corpus,
the spec, the conformance program, the governance structure, the
distribution channels. Distinct from `THREAT-MODEL.md` (which covers
what attacks ATR rules detect).

**Status:** Draft for community comment, v1.0 — NOT RATIFIED
**Date:** 2026-05-25
**Author:** Adam Lin <adam@agentthreatrule.org>
**Required by (on ratification):** OASIS Open Project submission, NIST CAISI RFI, F500
procurement security questionnaires.

---

## Why this document exists

Every successful security standard has at some point been attacked
as a standard, not just as a vulnerability database. CVE has had
identifier squatting (CNAs misissuing IDs to inflate vendor metrics).
Sigma has had rule poisoning attempts (PRs with backdoored regex).
MITRE ATT&CK has had taxonomy lobbying (vendors pushing techniques
that favour their detection coverage). OWASP has had project capture
(vendors stacking project leadership).

If ATR does not anticipate these attacker classes in the v2.0
governance design, the standard inherits the failure modes that
have compromised every predecessor lacking explicit threat
modeling. This document enumerates the eight attacker classes ATR
must withstand, the trust boundaries each attacker probes, the
mitigation already in the v2.0 charter, and the residual risk that
remains.

---

## Trust boundaries (informational, before attacker walkthrough)

```
   ┌──────────────────────────────────────────────────────────────┐
   │  Outside contributors (PR authors, issue reporters)          │
   └────────────┬─────────────────────────────────────────────────┘
                │  (1) PR / Issue
                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  CI gate: check-rules-safety.ts + schema validate + DCO      │
   └────────────┬─────────────────────────────────────────────────┘
                │  (2) gated proposal
                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  TSC members (9 seats, capped, with COI disclosure)          │
   │  • Tier 1 (rules): lazy consensus, any TSC can demote        │
   │  • Tier 2 (semantics): simple majority of 5+                 │
   │  • Tier 3 (spec breaking): 2/3 of 7+                         │
   │  • Tier 4 (charter): 3/4 of 8+ + fiscal-sponsor ratify       │
   └────────────┬─────────────────────────────────────────────────┘
                │  (3) merged to main
                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  Numbering Authority (2+ operators delegated by TSC)         │
   │  • Assigns ATR-YYYY-NNNNN canonical IDs                      │
   │  • Sovereign sub-ranges (ATR-XX-YYYY-NNNNN) per § 8.2 charter│
   └────────────┬─────────────────────────────────────────────────┘
                │  (4) published
                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  Distribution channels:                                       │
   │  • npm (agent-threat-rules), PyPI (atr-python), Go module    │
   │  • MISP galaxy + taxonomies                                  │
   │  • OASIS specification publication                           │
   │  • Conformance test corpus + signed expected-results.json    │
   └────────────┬─────────────────────────────────────────────────┘
                │  (5) consumed
                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  Downstream: Microsoft AGT, Cisco AI Defense, MISP CIRCL,    │
   │  Splunk/Sentinel, F500 SOCs, sovereign CERTs                 │
   └──────────────────────────────────────────────────────────────┘
```

Each numbered transition is a trust boundary an attacker may probe.

---

## Attacker class 1 — Rule poisoner

**Goal:** Insert a rule that either (a) causes false-positive storms in
downstream SOCs (defender DoS) or (b) silences detection of a real
attack class the poisoner cares about (false-negative attack).

**Vector:** Open a PR with a rule that passes schema validation but
contains a subtle FP-inducing pattern, OR a rule that explicitly
documents detection while encoding logic that never fires on the
attack it claims to detect.

**Subvariant 1a — backdoored regex.** Looks like detection, actually
matches arbitrary input or never matches the named attack.

**Subvariant 1b — denial-of-detection.** Rule appears to detect attack
class X but is intentionally narrowed so real attacks of class X don't
fire (e.g., requires a specific User-Agent that no real attacker uses).

**Mitigations in charter v2.0:**

- CI gate `check-rules-safety.ts` enforces own-TP-must-match (regex
  must actually match every declared true_positive). Defeats
  Subvariant 1b at the contribution stage.
- CI gate enforces 0 FP on the benign corpus (data/skill-benchmark/
  benign/, 432+ known-clean samples). Defeats Subvariant 1a.
- CI gate enforces 0 FP on research-mentions corpus (text that
  MENTIONS attacks without being attacks — papers, READMEs).
- Cross-rule conflict check: a new rule MUST NOT match any existing
  rule's true_negatives. Detects orthogonal subversion.
- Tier 1 lazy consensus requires two TSC approvals before merge.
- Tier 1 includes a 72-hour wait window during which any TSC member
  can demote to Tier 2 by raising a substantive objection — i.e., a
  poisoned rule has a 72-hour bake time during which any vigilant
  TSC member can pull the pin.
- Mandatory DCO sign-off makes contribution accountable to a named
  identity (legal, not anonymous).
- For sensitive rule categories (privilege-escalation, model-security,
  agent-manipulation), Tier 1 may be raised to Tier 2 by TSC standing
  policy if poisoning attempts are observed.

**Residual risk:** If two TSC members are themselves compromised
(insider attacker class), Tier 1 lazy consensus passes. Counter:
the cross-rule conflict check + benign-corpus FP gate runs in CI and
cannot be bypassed by TSC members alone; CI infrastructure is
GitHub-managed and outside any single TSC member's control. Insider
attack at TSC level forces visible CI failures or pre-coordinated
benign-corpus tampering (see Attacker 5 below).

---

## Attacker class 2 — Namespace squatter

**Goal:** Fragment the ATR identifier namespace by issuing competing
`ATR-YYYY-NNNNN` IDs from a non-canonical authority, causing
downstream consumers to receive inconsistent rule semantics under the
same identifier. This is the CVE-prefix squatting problem
(`CVE-2023-99999` claimed by two separate authorities).

**Vector:** Stand up a lookalike GitHub organisation (e.g.,
`AgentThreatRule-Standards`, `Agent-Threat-Rules-Foundation`). Publish
a competing rule pack with overlapping numeric range. Promote via a
SEO-friendly domain claiming to be the "official" ATR registry.

**Mitigations in charter v2.0:**

- § 8.1: The TSC is the sole canonical Numbering Authority. Day-to-day
  issuance is delegated to two or more named operators, but the TSC
  collectively retains the authority. No other body can issue
  `ATR-YYYY-NNNNN` IDs that conformant implementations accept.
- § 8.3: No private namespaces. Companies do not get their own ID
  prefixes. Only sovereign authorities admitted by the TSC receive
  prefixed sub-ranges (`ATR-DE-`, `ATR-SG-`, etc.).
- Trademark ATR® and ATR-Certified™ are owned by Open Source
  Collective Inc. on behalf of the project. Trademark enforcement
  (cease-and-desist + UDRP for lookalike domains) is the legal
  backstop.
- Distribution channels (npm `agent-threat-rules`, PyPI `atr-python`,
  the canonical GitHub org `Agent-Threat-Rule`) are TSC-controlled
  and serve as the "single source of truth" reference downstream
  vendors implement against.
- The conformance corpus (§ 7.1) is published with an ed25519
  signature from a TSC-maintained key. Any "implementation" that
  claims ATR conformance but loads non-canonical IDs fails the
  conformance test.

**Residual risk:** Sub-jurisdictional squatting (e.g., a regional
authority issues `ATR-DE-2026-` IDs without TSC authorisation,
mirroring the legitimate sovereign sub-range scheme) is the highest
remaining risk. Counter: § 8.2 requires each sovereign authority to
publish an attestation public key registered with the TSC; rules
without a verifiable signature from a registered key are flagged by
the engine and treated as community-tier (unprefixed) submissions
regardless of the prefix used in the file.

---

## Attacker class 3 — Governance capturer

**Goal:** Acquire majority influence on the TSC, then steer the
standard toward outcomes that benefit the attacker (e.g., a vendor
suppresses rules that detect their products' weaknesses, or a
state actor steers detection coverage away from their offensive
toolkit).

**Vector:**

- Subvariant 3a — Vendor stacking: hire engineers known to the
  community to run for contributor seats while still employed by
  the attacker.
- Subvariant 3b — Acquisition: acquire a company whose employee
  holds a TSC seat, then exceed the 2-cap by inheritance.
- Subvariant 3c — Sock-puppet contributors: create fake personas
  that contribute rules over time to qualify for contributor-seat
  voting eligibility (Sybil attack on the contributor election).
- Subvariant 3d — Liaison capture: lobby a single national authority
  to nominate liaisons aligned with the attacker.

**Mitigations in charter v2.0:**

- § 3.1: Hard 2-cap per company group with random-lot tiebreaker.
  Defeats 3a and 3b at the structural level.
- § 3: Contributor-seat election eligibility requires ≥10 merged
  rules in the trailing 12 months. Sock-puppet contributors must
  carry that workload publicly, which is detectable (rule-quality
  forensics + temporal-analysis on PR cadence).
- § 6.1 Annual COI disclosure published in repo. Acquisition that
  brings a member into 2-cap violation is detected at the disclosure
  step within 90 days.
- § 3 Sovereign liaison seats are two of nine, capped at one per
  sovereign body. No single national authority controls more than
  one liaison seat.
- § 4 Tier 4 (charter changes) require 3/4 supermajority + fiscal
  sponsor ratification. Capturing the standard's direction requires
  7 of 9 TSC + Open Source Collective's signoff, which raises the
  bar above what any single actor can plausibly accomplish covertly.
- § 4 Tier 5 enables member removal at 2/3 of remaining TSC. A
  captured member can be removed without their own vote.

**Residual risk:** Coordinated multi-vendor capture (3+ companies
each placing 1 contributor seat + sharing a strategic objective) is
not prevented by per-company caps. Counter: COI disclosure makes
employment visible; the academic + civil-society + sovereign seats
serve as structural counterweights (4 of 9 by design). If those 4
remain independent, no 5-vendor coalition can pass Tier 3 or Tier 4
votes.

---

## Attacker class 4 — Regex DoS author (ReDoS)

**Goal:** Ship a rule whose regex causes catastrophic backtracking,
turning the ATR engine into a fork bomb on hostile input. Defender
DoS via legitimate-looking detection.

**Vector:** Contribute a rule with compound `[\s\S]{0,N}` spans or
nested alternation that exhibits exponential time complexity on
crafted input.

**This attack class is observed.** The project's own v3.1.1 deferred
rules (METR misalignment pack, SpAIware memory-poisoning pack) hit
this exact failure mode during the cross-rule check phase of
`check-rules-safety.ts` in late May 2026. The author was not malicious,
but the failure mode is identical to what a poisoner would exploit.

**Mitigations in charter v2.0:**

- The CI gate `check-rules-safety.ts` cross-rule check exercises
  every new rule's regex against every other rule's test cases.
  Catastrophic backtracking manifests as scan-time hang detectable
  by CI timeout. Recommendation: add explicit per-regex execution
  bound (e.g., 100ms timeout per regex per input) to the CI gate as
  an AEP under § 5.2.
- AEP-001 (planned, Phase 1): spec requires implementations to
  enforce a regex complexity bound (e.g., RE2-compatible regex
  grammar, which is non-backtracking by construction). The
  TypeScript reference engine should migrate from JavaScript's
  native regex (PCRE-like, backtracking) to a re2 binding.
- Spec § (planned): rule authors must declare expected
  worst-case regex evaluation time. The conformance gate checks
  observed time stays within the declared bound on the conformance
  corpus.

**Residual risk:** RE2 cannot express all the patterns native PCRE
can, so some current ATR rules may need restructuring. This is a
known migration cost that the AEP will surface. Until RE2 migration,
runtime engines must independently enforce a timeout to prevent
ReDoS regardless of rule content.

---

## Attacker class 5 — Conformance corpus poisoner

**Goal:** Alter the published conformance corpus or expected-results
manifest so that an implementation which is NOT ATR-conformant can
pretend to be conformant, OR vice versa: a legitimate conformant
implementation is locked out via tampered test cases.

**Vector:**

- PR to `spec/conformance/`.
- Compromise of GitHub repo (force-push by attacker who has push
  rights).
- Compromise of the TSC member's signing key used to sign the
  conformance corpus.

**Mitigations in charter v2.0:**

- § 7.1: Conformance corpus content is MIT-licensed (permissive, no
  licensing obstruction) but the canonical expected-results manifest is
  signed with an ed25519 key controlled by the TSC. Tampering
  invalidates the signature, which is checked by any conformance
  validator.
- The signing key is held by the Numbering Authority operators (§
  8.1, 2+ persons) using hardware-token threshold signing. Loss of
  any single key does not enable forgery; rotation occurs per the
  certification working group's published key-rotation schedule.
- The GitHub repo enforces branch protection on `main` (TSC-only
  push) and signed commits for the `spec/conformance/` path.
- A second signing key is held by Open Source Collective Inc. as
  fiscal sponsor; the published reference signature requires both.
- Implementations consuming the conformance corpus MUST verify the
  signature; non-verifying consumption is an implementation bug, not
  a corpus problem.

**Residual risk:** Compromise of the TSC + fiscal sponsor jointly
(both threshold-signing keys) would allow undetected tampering. This
is a fundamental "single root of trust" residual that all signed-
specification standards share (CVE, C2PA, FIDO all face the same).
Counter: publish corpus integrity attestations on a public
transparency log (think Sigstore Rekor or Certificate Transparency
log) so any third party can detect post-publication changes.

---

## Attacker class 6 — Attestation signature forger

**Goal:** Issue forged sovereign-tier rules (e.g., spoof an
`ATR-DE-2026-NNNNN` rule purporting to be issued by German BSI,
when in fact issued by an attacker). Use the false sovereign
attestation to push rules with elevated trust into downstream
consumers.

**Vector:**

- Theft of a sovereign authority's published ed25519 private key.
- Spoof of the sovereign authority's published-key registry entry.
- Compromise of the CA chain anchoring the sovereign authority's
  public key.

**Mitigations in charter v2.0:**

- § 8.2: Sovereign attestation keys are registered with the TSC at
  the time of sovereign authority admission. Registration is on a
  GitHub-tracked artifact; modifications are TSC Tier 2 votes.
- Spec (planned): the engine MUST validate the attestation
  signature against the registered key AND check against a TSC-
  maintained revocation list before honoring sovereign-tier trust.
- Spec (planned): attestation keys carry expiry and require renewal;
  expired keys do not validate.
- Sovereign authorities are responsible for their own key custody
  (the standard cannot prevent a sovereign-CERT compromise) but the
  blast radius is contained to rules issued under that sovereign's
  prefix and discoverable via revocation.

**Residual risk:** A sovereign authority whose key is stolen but
who does not promptly revoke leaves a forgery window. Counter:
implementations should cache only short-lived (e.g., 24-hour)
sovereign-tier trust and re-validate against the revocation list.
This is a tradeoff with operational availability that each adopter
balances.

---

## Attacker class 7 — Supply chain attack on the engine package

**Goal:** Compromise the `agent-threat-rules` npm package (or
PyPI / Go module) so that downstream consumers install an
attacker-controlled engine, which then either fails to detect
specific attack classes or exfiltrates scan data to the attacker.

**This attack class is the very threat ATR-2026-00525 was written
to detect** (Mini Shai-Hulud, May 2026 — `@mistralai/mistralai`,
`mistralai`, `guardrails-ai` all compromised). The ATR project must
not be vulnerable to the same class of attack it ships rules for.

**Vector:**

- Compromise of npm/PyPI publish credentials.
- Typosquat (`agent-treat-rules`, `agent_threat_rules`).
- Dependency confusion (publishing an `@agent-threat-rules/*` scoped
  package without the scope being TSC-owned).

**Mitigations in charter v2.0:**

- Publish credentials are TSC-controlled, rotated quarterly.
  Threshold-signed releases (Sigstore) required for npm and PyPI.
- SLSA Level 3 provenance for each published version, published in
  the GitHub release notes and verifiable from the package metadata.
- npm scope `@agent-threat-rules` is owned by the TSC; sub-packages
  cannot be published outside TSC control.
- Typosquat monitoring: the certification working group runs a
  monthly scan against npm + PyPI for lookalike package names; any
  hit triggers takedown via npm-security@npmjs.com and pypi-
  security@python.org.
- Postinstall scripts are forbidden in the official npm package
  (avoiding the very vector Mini Shai-Hulud used).
- Engine package signs the `expected-results.json` of the
  conformance corpus on every release — installation flow detects
  tampering at first use.

**Residual risk:** Full GitHub org takeover (e.g., session-token
theft from all TSC operators simultaneously) enables undetected
release. Counter: critical actions (publish, release) require
hardware-token MFA for at least two TSC operators (one of whom is
on a different continent than the other, per § 3.2 geographic
diversity reporting).

---

## Attacker class 8 — Sybil attack on community elections

**Goal:** Acquire majority of contributor-seat votes by inflating
fake contributor accounts through PR farms or AI-generated rule
contributions. Use the seat to influence governance per Attacker 3.

**Vector:** Generate plausible-looking rule PRs at scale (LLM
assistance lowers cost), each from a distinct GitHub account, to
manufacture the ≥10-merged-rule eligibility threshold for the
contributor seat.

**Mitigations in charter v2.0:**

- § 3 Contributor seat eligibility: ≥10 merged rules in the
  trailing 12 months. Quantity threshold combined with the
  Tier 1 review process means a Sybil attacker must produce 10
  rules that survive both CI gates AND TSC scrutiny per persona.
  Cost-of-attack scales with persona count.
- DCO sign-off requires a named identity per commit. Voting
  registration may require a corroborating identity check (e.g.,
  GPG-signed contribution history, or a long-lived GitHub account
  with diverse activity).
- Election ballots are public (vote-counting transparency). Any
  pattern of newly-created accounts voting in lockstep is detectable
  by the Chair and grounds for invalidation per Tier 5 procedure.

**Residual risk:** A patient adversary (e.g., a well-resourced state
actor) can sustain a Sybil campaign over 12+ months at moderate cost
($10K-50K range in LLM compute + GitHub account costs). Counter:
elections occur annually; the next year's election can correct any
captured seats. The structural counterweight (academic + civil
society + sovereign seats = 4 of 9) limits a Sybil-captured
contributor block to 3 of 9 votes.

---

## Cross-cutting mitigations summary

| Mitigation | Applies to |
|---|---|
| `check-rules-safety.ts` CI gate (own-TP-match + 0 FP + cross-rule no-conflict) | 1, 4 |
| TSC single-company 2-cap | 3 |
| Tier 4 charter changes require 3/4 + fiscal sponsor ratify | 3, 5 |
| ed25519 signed conformance corpus + threshold signing | 5, 6 |
| Sovereign attestation key registry + revocation | 6 |
| SLSA L3 release provenance + signed npm/PyPI publishes | 7 |
| Annual COI disclosure | 3 |
| Lazy-consensus 72hr wait window for Tier 1 | 1 |
| Contributor eligibility ≥10 merged rules in 12mo | 8 |
| Quarterly diversity reporting (transparency) | 3 |
| Founder recusal after 12 months | 3, 7 |

---

## What this threat model deliberately does NOT cover

- Attacks against products built ON TOP of ATR (e.g., a commercial
  scanner or platform that bundles ATR rules). Those threat models
  belong to the individual vendors.
- Attacks against AI agents themselves. That is the subject of
  `THREAT-MODEL.md` (the rule-corpus threat model).
- Attacks against the Open Source Collective Inc. (fiscal sponsor)
  as an organisation. That is OSC's governance scope.
- Legal attacks against the standard (patent assertion against
  conformant implementations, jurisdiction-specific compliance
  challenges). Those belong in `legal/jurisdiction-notes.md` once
  authored.

---

## Versioning

This document is amended via the AEP process (Tier 3) and re-
published when the v2.0 charter is amended or when a new attacker
class is observed in production. Version history at
`governance/STANDARD-THREAT-MODEL-CHANGELOG.md` once the first
amendment lands.

---

## Sources

- CNCF Foundation Charter: https://github.com/cncf/foundation/blob/main/charter.md
- OpenSSF TAC Decision Process: https://github.com/ossf/tac/blob/main/process/TAC-Decision-Process.md
- OASIS IPR Policy: https://www.oasis-open.org/policies-guidelines/ipr/
- Sigstore key transparency: https://www.sigstore.dev/
- SLSA framework: https://slsa.dev/
- Mini Shai-Hulud analysis (Wiz, May 2026): https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
- CVE numbering authority structure: https://www.cve.org/PartnerInformation/Partner/CNAs
- RE2 vs PCRE regex complexity: https://github.com/google/re2/wiki/WhyRE2
- Linux kernel DCO: https://developercertificate.org/
