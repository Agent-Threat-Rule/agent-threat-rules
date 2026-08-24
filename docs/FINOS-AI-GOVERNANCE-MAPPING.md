# ATR → FINOS AI Governance Framework v2.0 Mapping (Agentic Risks)

Version: 0.1.0 (INTERNAL DRAFT — not published, not submitted)
Status: Draft for future FINOS AI Governance Framework Informative Reference / PR basis (human review gate before any upstream submission)
Date: 2026-06-12
Editor: Adam Lin (林冠辛) <adam@agentthreatrule.org>
Mapped corpus: Agent Threat Rules v3.5.8 (793 rules / 10 categories, disk==stats.json verified 2026-07-12)
Reference framework: FINOS AI Governance Framework v2 (published 2025-10-20), Risk Catalogue
Reference framework license: CC-BY-4.0 (finos/ai-governance-framework). Risk and
mitigation text quoted below is reproduced under that license.
Source revision: finos/ai-governance-framework `main` branch, re-verified 2026-06-12
(risk + mitigation files and `CONVENTIONS.md` read directly). Contribution mechanics
(for any future upstream step): the repo requires a DCO `Signed-off-by:` line on
every commit, commit first line ≤ 72 chars, imperative mood, and that PRs follow the
existing doc layout — see Open Items.

---

## 1. Purpose

This document aligns the Agent Threat Rules (ATR) detection corpus with the
**agentic-AI risks** in the FINOS AI Governance Framework (AIGF) v2 risk
catalogue. It positions specific ATR Rules as the **executable runtime detection**
that a financial-services firm can deploy as a *technical control / continuous
assurance evidence source* against each agentic risk.

FINOS AIGF is a financial-services-oriented governance framework; this vertical
mapping is designed to compose with a bank's EU AI Act compliance work (where
credit-scoring and similar agentic workflows are high-risk Annex III systems and
Article 15 demands accuracy/robustness/cybersecurity controls).

### 1.1 Claim boundary (read first)

This is an **alignment** document authored by the ATR project. It is NOT a FINOS
work product and does NOT represent FINOS adoption or endorsement of ATR. FINOS
AIGF risks are governance statements; ATR Rules are one *detective/preventive
technical control* that can supply runtime evidence against a risk. A firm
satisfies a FINOS risk through a portfolio of governance, process, and technical
mitigations — ATR addresses the runtime-detection slice, not the full mitigation
set. The FINOS framework defines its own mitigation catalogue; this draft maps
ATR both to **risk IDs** and to the specific **FINOS mitigation IDs** each risk
lists, so the reader can see *which* FINOS mitigation an ATR rule supplies runtime
evidence toward. Note: ATR is a *detective/preventive technical control* feeding a
FINOS mitigation; it does not implement the mitigation's governance, vaulting,
isolation, or process components. The mitigation IDs were read from the FINOS
mitigation catalogue (`docs/_mitigations/mi-NN_*.md`) and cross-checked against the
"Key Mitigations" list each risk publishes on the FINOS site (verified 2026-06-12).

### 1.2 Relationship to FINOS's own cross-reference convention (read before any upstream move)

FINOS AIGF already encodes external-standard mappings, but only in **one
direction**: each risk/mitigation file carries YAML front-matter keys of the form
`<framework>_references:` that point *from* an AIGF item *to* an external control
catalogue. As verified 2026-06-12, the convention (`CONVENTIONS.md`) and live files
use keys such as `nist-sp-800-53r5_references:`, `nist-ai-600-1_references:`,
`iso-42001_references:`, `owasp-llm_references:`, `owasp-ml_references:`,
`ffiec-itbooklets_references:`, and `eu-ai-act_references:`, each entry being a
control ID plus an inline `# comment`, and each framework backed by a control list
in `docs/_data/<framework>.yml` (e.g. `eu-ai-act.yml`, `nist-sp-800-53r5.yml`,
`owasp-llm.yml`). Example, from `mi-21` (AIR-DET-021):

```yaml
nist-sp-800-53r5_references:
  - au-2   # AU-2 Event Logging
mitigates:
  - ri-24  # Agent Action Authorization Bypass
```

Two consequences for ATR:

1. **Direction.** This ATR→FINOS document is the *reverse* of FINOS's own pattern
   (FINOS maps out to external catalogues; it does not maintain inbound crosswalks
   from third-party detection projects). There is therefore no existing FINOS slot
   that this file drops into. Its natural home is the **ATR repository** as an
   Informative Reference, with the normative direction carried on each Rule's
   `references.finos_aigf` field (atr-method-v1.1.md §9.3) — mirroring how ATR
   already handles other crosswalks.
2. **If an upstream FINOS contribution is ever pursued**, the convention-aligned
   form is NOT this prose file but an `agent-threat-rules_references:` (or similar)
   front-matter key, which would require (a) a new `docs/_data/agent-threat-rules.yml`
   control list and (b) FINOS maintainers electing to recognise ATR as a referenced
   framework — i.e. a maintainer/governance decision, not a documentation PR. That
   is a high bar and is explicitly out of scope for this draft. The realistic
   first step is a discussion/issue, never an unsolicited front-matter PR.

## 2. Conventions

Risk IDs and titles are quoted verbatim from the FINOS AIGF v2 risk catalogue
(`docs/_risks/ri-NN_*.md`; canonical published IDs render as `AIR-SEC-NNN` /
`AIR-OP-NNN` from front-matter `type` + `sequence`). Mitigation IDs render as
`AIR-PREV-NNN` (preventive) / `AIR-DET-NNN` (detective) from the mitigation
front-matter `type` + `sequence` (`docs/_mitigations/mi-NN_*.md`); the per-risk
"FINOS mitigation(s)" set below is taken from the "Key Mitigations" list each risk
publishes on air-governance-framework.finos.org and corroborated by the
`Mitigates:` back-references in the mitigation files (both verified 2026-06-12).
The FINOS site renders these IDs zero-padded to three digits (e.g. `AIR-PREV-018`);
the un-padded form (`AIR-PREV-18`) is the same identifier. Each ATR Rule cited
exists on disk (verified 2026-06-12) with its `title:` quoted verbatim. `Method`
is the ATR detection method per atr-method-v1.1.md §4.

---

## 3. Agentic Risk → ATR Mapping

### 3.1 AIR-SEC-024 — Agent Action Authorization Bypass

FINOS summary: agentic systems may bypass intended authorization controls and
perform unauthorized actions (e.g. unauthorized financial transactions,
regulatory violations). (FINOS cross-refs OWASP LLM06:2025 Excessive Agency.)

| ATR Rule | Title | Method | Role |
|----------|-------|--------|------|
| ATR-2026-00549 | "Destructive tool invocation without prior human approval" | trace | Asserts a human-approval predecessor span must exist before a destructive/privileged tool span; fires when an agent acts without the required gate |
| ATR-2026-00099 | "High-Risk Tool Invocation Without Human Confirmation" | pattern | Detects high-risk tool calls lacking confirmation |
| ATR-2026-00098 | "Unauthorized Financial Action by AI Agent" | pattern | Finance-specific: detects unauthorized financial action instructions — directly relevant to the FS transaction-authorization concern |

FINOS mitigation(s) ATR supplies evidence toward (verified 2026-06-12): this risk
publishes five Key Mitigations — AIR-PREV-018 (Agent Authority Least Privilege
Framework), AIR-PREV-019 (Tool Chain Validation and Sanitization), AIR-DET-021
(Agent Decision Audit and Explainability), AIR-PREV-022 (Multi-Agent Isolation and
Segmentation), AIR-PREV-023 (Agentic System Credential Protection Framework). ATR's
rules above are runtime evidence primarily for the *detective* mitigation
**AIR-DET-021** (the missing-gate/bypass event is exactly the "suspicious tool
selection / execution pattern" that mitigation says to detect) and for the
detection/monitoring portion of the preventive control **AIR-PREV-019** (validating
that an agent's tool decision was appropriate). The least-privilege, isolation, and
credential-vaulting machinery of AIR-PREV-018/022/023 is architectural and is not
supplied by ATR. Audit-trail note: FINOS's own `mi-21` front-matter maps AIR-DET-021
to NIST SP 800-53r5 AU-2 / AU-3 / AU-6 and CA-7 (verified 2026-06-12); an ATR match
emits a structured event (rule_id, severity, matched selectors — SPEC.md §7) that is
the kind of audit-record content those AU-family controls call for, which is why ATR
sits most cleanly under the *detective* mitigation rather than the preventive ones.

Coverage: Strong (detection). The architectural authZ enforcement (policy engine,
least-privilege) is the firm's control; ATR detects the bypass/missing-gate
condition at runtime.

### 3.2 AIR-SEC-025 — Tool Chain Manipulation and Injection

FINOS summary: malicious inputs manipulate agentic systems into selecting
inappropriate tools and executing dangerous API sequences with corrupted
parameters — extends prompt injection to real-world consequences (financial
fraud, data exposure, system compromise).

| ATR Rule | Title | Method | Role |
|----------|-------|--------|------|
| ATR-2026-00550 | "Privileged tool call following untrusted retrieval (indirect prompt injection trail)" | trace | Detects the corrupted tool-sequence pattern: privileged tool call causally following untrusted content without sanitization |
| ATR-2026-00011 | "Instruction Injection via Tool Output" | pattern | Detects injected instructions arriving through tool output that drive subsequent tool selection |
| ATR-2026-00111 | "Shell Metacharacter Injection in Tool Arguments" | pattern | Detects corrupted/dangerous tool-call parameters (argument injection) |

FINOS mitigation(s) ATR supplies evidence toward (verified 2026-06-12): this risk
publishes two Key Mitigations — AIR-PREV-019 (Tool Chain Validation and
Sanitization) and AIR-DET-021 (Agent Decision Audit and Explainability). ATR maps
directly onto both: the rules above are the runtime detection that backs the
"sanitise parameters / validate the tool-call sequence" intent of **AIR-PREV-019**
and the "detect suspicious tool selections and execution patterns" intent of
**AIR-DET-021**.

Coverage: Strong. This is a core ATR competency (prompt-injection + tool-poisoning
categories); ATR provides directly testable detections for the manipulated
tool-chain class.

### 3.3 AIR-SEC-026 — MCP Server Supply Chain Compromise

FINOS summary: compromised MCP servers inject tainted data and capabilities into
agentic systems, corrupting agent reasoning at scale via external services agents
depend on.

| ATR Rule | Title | Method | Role |
|----------|-------|--------|------|
| ATR-2026-00095 | "MCP Tool Supply Chain Poisoning" | pattern | Detects poisoned MCP tool content distributed through the supply chain |
| ATR-2026-00010 | "Malicious Content in MCP Tool Response" | pattern | Detects tainted data injected via MCP tool responses |
| ATR-2026-00161 | "MCP Tool Description — IMPORTANT Tag Cross-Tool Shadowing Attack" | pattern | Detects a compromised MCP server shadowing/hijacking other tools via crafted descriptions |

FINOS mitigation(s) ATR supplies evidence toward (verified 2026-06-12): this risk
publishes two Key Mitigations — AIR-PREV-020 (MCP Server Security Governance) and
AIR-PREV-023 (Agentic System Credential Protection Framework). ATR contributes to
the *behavioral monitoring / anomaly-detection* portion of **AIR-PREV-020** (that
mitigation explicitly calls for "real-time anomaly detection" and "behavioral
monitoring" over MCP servers — ATR's poisoned-content and shadowing detections are
that runtime signal). ATR does not provide the vendor-assessment, TLS-1.3-mutual-
auth, or cryptographic-checksum components of AIR-PREV-020, nor the credential-
vaulting of AIR-PREV-023.

Coverage: Partial → Strong on the *content* dimension. Cryptographic provenance
of MCP builds is a supply-chain control; ATR is the runtime detection backstop for
tainted MCP content and capability shadowing.

### 3.4 AIR-SEC-027 — Agent State Persistence Poisoning

FINOS summary: agents retain malicious instructions through poisoned persistent
state, creating long-term cross-session backdoors that are hard to detect.

| ATR Rule | Title | Method | Role |
|----------|-------|--------|------|
| ATR-2026-00551 | "Cross-conversation memory write (scope-escape via memory store)" | trace | Detects a write into persistent/cross-conversation memory that escapes the originating session/tenant scope — the planting step of state poisoning |

FINOS mitigation(s) ATR supplies evidence toward (verified 2026-06-12): this risk
publishes one Key Mitigation — AIR-PREV-022 (Multi-Agent Isolation and
Segmentation), which covers "state segregation" and "trust boundary enforcement".
ATR rule 00551 is the runtime detection that a state-segregation boundary was
crossed (a write escaping its originating session/tenant scope). The isolation
mechanism itself (separate namespaces, signed/MAC'd persisted memory) is the
architectural control AIR-PREV-022 prescribes; ATR detects its failure.

Coverage: Partial. ATR detects the cross-scope persistence-write that seeds a
poisoned-state backdoor; durable integrity-protection of agent state (signing/MAC
of persisted memory) is an architectural control. Single-rule coverage — flagged
in Open Items as a candidate for a dedicated state-integrity rule.

### 3.5 AIR-SEC-029 — Agent-Mediated Credential Discovery and Harvesting

FINOS summary: agents' autonomous decision-making and legitimate access are
exploited to discover and exfiltrate credentials/API keys/secrets across
infrastructure, enabling lateral movement at scale.

| ATR Rule | Title | Method | Role |
|----------|-------|--------|------|
| ATR-2026-00115 | "Bulk Environment Variable Harvesting and Exfiltration" | pattern | Detects bulk env-var/secret harvesting — the force-multiplier behavior this risk describes |
| ATR-2026-00113 | "Credential File Theft from Agent Environment" | pattern | Detects credential-file access/theft from the agent environment |
| ATR-2026-00021 | "Credential and Secret Exposure in Agent Output" | pattern | Detects secrets surfacing in agent output (exfiltration channel) |

FINOS mitigation(s) ATR supplies evidence toward (verified 2026-06-12): this risk
publishes one Key Mitigation — AIR-PREV-023 (Agentic System Credential Protection
Framework), whose seven implementation areas include "behavioral monitoring" and
"systematic monitoring of credential access patterns to detect harvesting
attempts". ATR's credential-harvesting / exfiltration rules above are exactly that
behavioral-monitoring signal. The credential-vault, HSM, and short-lived-token
machinery of AIR-PREV-023 is architectural and out of ATR scope.

Coverage: Strong (detection). ATR's context-exfiltration category provides
multiple directly testable detections for the discover-and-harvest behavior.

### 3.6 AIR-OP-028 — Multi-Agent Trust Boundary Violations

FINOS summary: a breach in one agent propagates to others through shared
resources and communication channels, cascading across the agent network and
undermining business processes.

| ATR Rule | Title | Method | Role |
|----------|-------|--------|------|
| ATR-2026-00548 | "Cross-agent session context leak across delegation chain" | trace | Detects context leaking across a delegation chain — a trust-boundary crossing between agents |
| ATR-2026-00074 | "Cross-Agent Privilege Escalation" | pattern | Detects privilege escalation propagating across agents |
| ATR-2026-00076 | "Insecure Inter-Agent Communication Detection" | pattern | Detects insecure inter-agent communication that enables cross-agent propagation |

FINOS mitigation(s) ATR supplies evidence toward (verified 2026-06-12): this risk
publishes AIR-PREV-022 (Multi-Agent Isolation and Segmentation) as its Key
Mitigation (the mitigation file lists ri-28 among the risks it mitigates). ATR's
cross-agent leakage/escalation rules above are the runtime detection that an
isolation/trust boundary AIR-PREV-022 is meant to enforce has been crossed —
including its "failure isolation" and "comprehensive monitoring" elements. The
isolation primitives themselves (separate runtimes/namespaces, default-deny
cross-domain) are the architectural control; ATR detects the violation.

Coverage: Strong (detection) for the cross-agent leakage/escalation signals;
isolation (separate runtimes/namespaces, default-deny cross-domain) is the
architectural control these detections complement.

---

## 4. EU AI Act co-deployment note (financial-services context)

For a bank deploying a high-risk agentic workflow (e.g. credit-scoring,
Annex III §5(b)), the FINOS agentic risks above and EU AI Act Article 15
(accuracy, robustness, cybersecurity) overlap: the same ATR runtime detections
that supply assurance evidence against AIR-SEC-024/025/026/029 also serve as
Article 15 cybersecurity-of-AI-system technical controls. This mapping is intended
to let one ATR deployment produce evidence usable in **both** the FINOS governance
narrative and the EU AI Act technical-documentation/conformity narrative.

Boundary: ATR is a *complement*, not a substitute, for the firm's governance,
human-oversight (Article 14), and data-governance (Article 10) obligations, nor
does it discharge the FINOS framework's non-technical mitigations. The bank
remains the deployer of record.

## 5. Open items

- AIR-SEC-027 (Agent State Persistence Poisoning) is covered by a single trace
  rule (00551, the cross-scope memory-write planting step). A dedicated
  state-integrity / poisoned-memory-read detection is a candidate addition.
- This mapping covers the v2 agentic risk subset (AIR-SEC-024/025/026/027/029,
  AIR-OP-028). Non-agentic risks (e.g. AIR-OP-006 Non-Deterministic Behaviour,
  AIR-SEC-010 Prompt Injection as a standalone risk) have ATR coverage but are out
  of scope for this agentic-focused draft.
- FINOS mitigation catalogue cross-references are now included (added 2026-06-12).
  Each risk section lists the FINOS Key Mitigation(s) it publishes and states which
  ATR maps onto (always the *detective* or *monitoring* portion, never the
  architectural/vaulting/isolation portion). Source: the per-risk "Key Mitigations"
  lists on air-governance-framework.finos.org plus the `Mitigates:` back-references
  in `docs/_mitigations/mi-NN_*.md`. The FINOS risk *YAML front-matter* itself does
  NOT carry a `related_mitigations` field (it carries only `related_risks`), so the
  risk→mitigation linkage was read from the published site + mitigation files, not
  from the risk front-matter. Re-verify before external submission, as the
  catalogue is versioned.
- Risk IDs/titles verified against the FINOS AIGF v2 `main` branch source on
  2026-06-12; re-verify before any external submission.
- **Observed contribution shape (2026-06-12).** Recent merged AIGF PRs are
  substantive but FINOS-internal: agentic risks & mitigations (#218, Paul Merrison),
  AIGF Taxonomy (#238), the v2 release (#235), financial-specific example rewrites,
  doc-quality consistency passes, and the April-2026 SR 11-7 GenAI carve-out reflect
  (#297). The repo *does* accept domain-substantive content (not just typos), which
  is more encouraging than the AISVS history — but every merged item is authored
  within the FINOS AI Readiness working group's own scope; none imports a
  third-party project's inbound crosswalk. So the same direction caveat (§1.2)
  applies: ATR-side hosting first; any FINOS contribution is a working-group
  conversation, not a drop-in PR.
- **Contribution mechanics, if pursued.** Every commit needs a DCO
  `Signed-off-by:` trailer (CC-BY-4.0 project); commit first line ≤ 72 chars,
  imperative mood; follow existing doc layout; keep commits small and focused;
  reference the related issue. FINOS is a Linux Foundation project with a
  `GOVERNANCE.md`; substantive direction is set in the AI Readiness working group,
  so the realistic entry is engaging that group / opening an issue, not an
  unsolicited content PR. (Verify current governance + working-group cadence before
  any approach.)
- No FINOS maintainer has reviewed this mapping. It is a draft basis for a future
  issue/working-group discussion, gated on human review.

## 6. References

- FINOS AI Governance Framework v2 (2025-10-20): https://air-governance-framework.finos.org/
- Repository: https://github.com/finos/ai-governance-framework
- Risk sources (verbatim IDs/titles): `docs/_risks/ri-24…`, `…ri-25…`, `…ri-26…`,
  `…ri-27…`, `…ri-28…`, `…ri-29…`
- Mitigation sources (verbatim IDs/titles, verified 2026-06-12):
  `docs/_mitigations/mi-18…` (AIR-PREV-018), `mi-19…` (AIR-PREV-019),
  `mi-20…` (AIR-PREV-020), `mi-21…` (AIR-DET-021), `mi-22…` (AIR-PREV-022),
  `mi-23…` (AIR-PREV-023). Per-risk Key-Mitigation lists corroborated at
  https://air-governance-framework.finos.org/risks/ (e.g. ri-24 page lists
  AIR-PREV-018/019/022/023 + AIR-DET-021).
- Cross-reference convention (front-matter `<framework>_references:` keys, inline
  `# comment` form): `CONVENTIONS.md`; backing control lists in `docs/_data/*.yml`
  (incl. `eu-ai-act.yml`, `nist-sp-800-53r5.yml`, `nist-ai-600-1.yml`,
  `owasp-llm.yml`, `owasp-ml.yml`, `iso-42001.yml`, `ffiec-itbooklets.yml`,
  `sr11-7.yml`) — all verified present 2026-06-12.
- Contribution mechanics (DCO sign-off, ≤72-char commit, imperative mood, CC-BY-4.0):
  https://github.com/finos/ai-governance-framework/blob/main/CONTRIBUTING.md
- ATR SPEC.md (Core v1.0.0) · atr-method-v1.1.md (Method Extensions v1.1.0)
- This file is an Informative Reference per spec/mappings/README.md.
