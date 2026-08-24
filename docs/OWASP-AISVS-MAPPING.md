# ATR → OWASP AISVS 1.0 Mapping (C9 / C10 / C13)

Version: 0.1.0 (INTERNAL DRAFT — not published, not submitted)
Status: Draft for future OWASP AISVS Informative Reference / PR basis (human review gate before any upstream submission)
Date: 2026-06-12
Editor: Adam Lin (林冠辛) <adam@agentthreatrule.org>
Mapped corpus: Agent Threat Rules v3.5.8 (793 rules / 10 categories, disk==stats.json verified 2026-07-12)
Reference framework: OWASP AI Security Verification Standard (AISVS) 1.0, chapters C9, C10, C13
Reference framework license: CC BY-SA 4.0 (OWASP/AISVS README). Requirement text
quoted below is reproduced under that license; this mapping is a derivative
Informative Reference and inherits the ShareAlike obligation if redistributed.
Source revision: AISVS GitHub `main` branch (the repo's default/working branch;
the README links chapter sources under `main/1.0/en`), re-verified 2026-06-12. No
tagged release exists yet (github.com/OWASP/AISVS/releases is empty as of
2026-06-12), so `main` is the only citable source; all requirement IDs below were
re-read from the chapter files on 2026-06-12.

Requirement-ID citation format: per the AISVS README ("How to Reference AISVS
Requirements"), the version-qualified form `v1.0-C<chapter>.<section>.<requirement>`
is preferred for external documents because bare IDs may renumber between versions.
This mapping therefore cites each requirement as e.g. `v1.0-C9.1.3` in the tables
below.

---

## 1. Purpose

This document aligns the Agent Threat Rules (ATR) detection corpus with three
chapters of the OWASP AI Security Verification Standard (AISVS) 1.0:

- C9 — Autonomous Orchestration & Agentic Action Security
- C10 — Model Context Protocol (MCP) Security
- C13 — Monitoring, Logging & Anomaly Detection

For each chapter this mapping selects the AISVS verification requirements that an
ATR-conformant engine can help satisfy, and positions specific ATR Rules as the
**executable verification method / runtime detection** behind that requirement.

### 1.1 Claim boundary (read first)

This is an **alignment** document authored by the ATR project. It is NOT an
OWASP work product and does NOT represent OWASP adoption, endorsement, or
inclusion of ATR. AISVS requirements verify the *presence and correctness of a
control*; ATR Rules are one mechanism that can provide evidence that a detection
or enforcement control exists and fires on the relevant attack class. An ATR
Rule firing on a test payload demonstrates a detection capability; it does not by
itself prove an organization has met the full requirement (which may also demand
configuration, isolation, identity, or process controls outside ATR's scope).

Where a requirement is primarily about architecture, identity, sandboxing, or
key management (e.g. C9.4 cryptographic agent identity, C10.2 OAuth 2.1 token
validation), ATR contributes only a *detection* signal and is explicitly marked
"partial / detection-only" below.

**On AISVS vendor-neutrality.** The AISVS README states the standard is
"vendor-neutral and does not endorse specific products or frameworks" and is "Not
a tool recommendation list." This mapping is consistent with that posture: it does
NOT ask AISVS to name, endorse, or recommend ATR, and it does NOT propose changing
any AISVS requirement text. It is a one-directional, externally-maintained
crosswalk — analogous to how any test tool documents which requirements its tests
exercise — describing how *one open-source detection corpus* can serve as
verification evidence for requirements AISVS already defines. ATR is open-source
(MIT) and itself vendor-neutral; the rule corpus is citable by ID without using or
purchasing any product. If proposed upstream at all, the appropriate form is an
Informative-Reference / "verification tooling example" pointer, never an edit to a
normative requirement.

## 2. Conventions

Each row cites at least one real ATR Rule ID that exists on disk as a canonical
`id:` field (all rule IDs in this document verified present 2026-06-12; files are
named `ATR-2026-NNNNN-<slug>.yaml`). Rule titles are quoted verbatim from the rule
`title:` field. The `Method` column states the ATR detection method (`pattern`,
`signature`, `semantic`, `behavioral`, `trace`) per atr-method-v1.1.md §4.
AISVS requirements are cited in the version-qualified form
`v1.0-C<chapter>.<section>.<requirement>` (per the README referencing guidance).
Requirement text in quotes is verbatim from the AISVS chapter source files on the
`main` branch (`1.0/en/0x10-C09…`, `…C10…`, `…C13…`), re-read 2026-06-12.

---

## 3. C9 — Autonomous Orchestration & Agentic Action Security

AISVS C9 source: `1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md`.

ATR's contribution to C9 is strongest where a requirement asks for **runtime
detection or pre-/post-execution gating of agent actions** — ATR's `trace`
method (declarative assertions over the agent's span/event DAG) and `pattern`
method map directly onto these. ATR does NOT provide the sandboxing, identity, or
budget-enforcement machinery that several C9 requirements demand; for those, ATR
is a detection complement, not the control.

| AISVS Req | Verbatim requirement (abridged where noted) | ATR Rule(s) as verification method | Method | Coverage |
|-----------|---------------------------------------------|------------------------------------|--------|----------|
| v1.0-C9.1.3 | "Verify that security testing covers runaway loops, budget exhaustion, and partial-failure scenarios, confirming safe termination and consistent state." | ATR-2026-00553 "Runaway tool-call loop within a single session"; ATR-2026-00050 "Runaway Agent Loop Detection"; ATR-2026-00051 "Agent Resource Exhaustion Detection" | trace (00553), pattern (00050/00051) | Partial — ATR detects runaway-loop / exhaustion signatures and trajectories; budget *enforcement* (C9.1.1/C9.1.2) is runtime-side, out of ATR scope |
| v1.0-C9.2.1 | "Verify that the agent runtime enforces an execution gate that blocks privileged or irreversible actions … until an explicit human approval is received and verified." | ATR-2026-00549 "Destructive tool invocation without prior human approval"; ATR-2026-00099 "High-Risk Tool Invocation Without Human Confirmation" | trace (00549), pattern (00099) | Strong (detection) — 00549's `require` primitive asserts a human-approval predecessor span must exist before a destructive tool span; surfaces the gate violation. Enforcement remains runtime-side |
| v1.0-C9.6.3 | "Verify that all access control decisions are enforced by application logic or a policy engine, never by the AI model itself, and that model-generated output … cannot override or bypass access control checks." | ATR-2026-00143 "Casual Unauthorized Privilege Escalation"; ATR-2026-00144 "Rationalized Safety Control Bypass"; ATR-2026-00430 "Natural-Language Trust-Escalation / Authority Impersonation" | pattern | Partial — ATR detects model-output attempts to assert authorization ("the user is allowed…"); the architectural enforcement is the org's, ATR flags the bypass attempt |
| v1.0-C9.6.4 | "Verify that secrets and credentials required by an agent at runtime are not exposed within the model's observable context, including the context window, system prompts, or tool call parameters …" | ATR-2026-00021 "Credential and Secret Exposure in Agent Output"; ATR-2026-00150 "Credential Data Leaked in Tool Response" | pattern | Strong (detection) — pattern rules detect secrets surfacing in observable context/tool I/O. Out-of-band injection design is architectural |
| v1.0-C9.8.4 | "Verify that runtime monitoring detects unsafe emergent behavior (oscillation, deadlocks, uncontrolled broadcast, abnormal call graphs) and automatically applies corrective actions (throttle, isolate, terminate)." | ATR-2026-00052 "Cascading Failure Detection in Agent Pipelines"; ATR-2026-00553 "Runaway tool-call loop within a single session" | pattern (00052), trace (00553) | Partial — ATR supplies the *detection* half (abnormal trajectories / cascades); automated corrective action is runtime-side |
| v1.0-C9.9.6 | "Verify that tool invocations where argument origin violates the applicable security policy are blocked before execution." | ATR-2026-00550 "Privileged tool call following untrusted retrieval (indirect prompt injection trail)" | trace | Strong (detection) — 00550 asserts over the span DAG that a privileged tool call must not causally follow an untrusted-retrieval span without an intervening sanitization/approval span; this is the runtime evidence that origin-based policy (C9.9.4/C9.9.5) was violated |

### 3.1 C9 notes

- ATR's `trace` method is the natural fit for C9's gate/origin/loop requirements
  because those requirements are inherently about *relationships between events*
  (approval-before-action, untrusted-source-before-privileged-tool), which is
  exactly what a declarative span-DAG assertion expresses.
- ATR explicitly does **not** cover: 9.1.1/9.1.2 budget enforcement, 9.3.x
  sandbox isolation, 9.4.x cryptographic agent identity / signing, 9.6.x OAuth
  delegation propagation. These are runtime/architecture controls; ATR can detect
  *symptoms* of their absence but is not the control itself.

---

## 4. C10 — Model Context Protocol (MCP) Security

AISVS C10 source: `1.0/en/0x10-C10-MCP-Security.md`.

ATR has its deepest agentic coverage here: the `tool-poisoning` category (47
rules) plus MCP-specific CVE rules map directly onto C10's component-integrity,
schema-validation, and input-validation requirements.

| AISVS Req | Verbatim requirement (abridged where noted) | ATR Rule(s) as verification method | Method | Coverage |
|-----------|---------------------------------------------|------------------------------------|--------|----------|
| v1.0-C10.1.1 | "Verify that MCP server and client components are obtained only from trusted sources and verified using signatures, checksums, or secure package metadata, rejecting tampered or unsigned builds." | ATR-2026-00095 "MCP Tool Supply Chain Poisoning"; ATR-2026-00096 "Skill Registry Poisoning and Compromised Tool Distribution" | pattern | Partial — ATR detects poisoning indicators in distributed MCP/skill content; cryptographic build verification is the supply-chain control, ATR is the detection backstop |
| v1.0-C10.4.1 | "Verify that MCP tool responses are validated before being injected into the model context to prevent prompt injection, malicious tool output, or context manipulation." | ATR-2026-00010 "Malicious Content in MCP Tool Response"; ATR-2026-00011 "Instruction Injection via Tool Output" | pattern | Strong — these rules are direct runtime validators of MCP tool-response content |
| v1.0-C10.4.4 | "Verify that MCP servers perform strict input validation for all function calls, including type checking, boundary validation, and enumeration enforcement." | ATR-2026-00543 "LiteLLM MCP Server Creation Authenticated argv Injection (CVE-2026-30623)"; ATR-2026-00538 "LangChain-ChatChat Unauthenticated MCP STDIO Server Configuration RCE (CVE-2026-30617)"; ATR-2026-00415 "Flowise Custom MCP STDIO Command Injection (CVE-2026-40933)" | pattern | Strong — CVE-mapped rules detect the exact unvalidated-argument MCP injection classes this requirement guards against |
| v1.0-C10.4.5 | "Verify that MCP clients maintain a hash or versioned snapshot of tool definitions and that any change to a tool definition … triggers re-approval before the modified tool can be invoked." | ATR-2026-00106 "Schema-Description Contradiction Attack"; ATR-2026-00161 "MCP Tool Description — IMPORTANT Tag Cross-Tool Shadowing Attack" | pattern | Partial — ATR detects malicious/contradictory tool-definition changes (rug-pull / shadowing); the hash-snapshot + re-approval flow is client-side, ATR flags the abusive mutation |
| v1.0-C10.4.8 | "Verify that MCP tool and resource schemas … along with schema manifests are validated for authenticity and integrity using signatures to prevent schema tampering or malicious parameter modification." | ATR-2026-00100 "Consent Bypass via Hidden LLM Instructions in Tool Descriptions"; ATR-2026-00105 "Silent Action Concealment Instructions in Tool Descriptions" | pattern | Partial — ATR detects hidden-instruction tampering inside tool descriptions/schemas; signature-based authenticity is the integrity control |
| v1.0-C10.6.2 | "Verify that MCP servers expose only allow-listed functions and resources, and restrict function invocation to statically defined, pre-approved names that cannot be influenced by user or model-provided input." | ATR-2026-00542 "Upsonic MCP Command Allowlist Bypass RCE (CVE-2026-30625)"; ATR-2026-00536 "nginx-ui MCP Endpoint Unauthenticated Command Execution (CVE-2026-33032)" | pattern | Strong — CVE rules detect allowlist-bypass / unauthenticated-invocation conditions this requirement forbids |

### 4.1 C10 notes

- C10.2 (OAuth 2.1 token validation, on-behalf-of flows) and C10.3 (transport
  TLS/Origin/Host validation, protocol downgrade) are protocol/identity controls
  outside ATR's content-inspection scope and are intentionally not claimed here.
- ATR's strongest C10 alignment is C10.4 (schema/message/input validation), where
  the CVE-mapped MCP rule set provides directly testable detections.

---

## 5. C13 — Monitoring, Logging & Anomaly Detection

AISVS C13 source: `1.0/en/0x10-C13-Monitoring-and-Logging.md`.

C13 is ATR's most natural home: every ATR Rule match emits a structured,
analyzed security event (SPEC.md §7), and the corpus supplies the signature- and
trajectory-based detections C13.2 asks for. ATR supplies detection *content*;
the logging pipeline, schema, and tamper-resistance are the consuming platform's
responsibility.

| AISVS Req | Verbatim requirement (abridged where noted) | ATR Rule(s) as verification method | Method | Coverage |
|-----------|---------------------------------------------|------------------------------------|--------|----------|
| v1.0-C13.2.1 | "Verify that the system detects and alerts on known jailbreak patterns, prompt injection attempts, and adversarial inputs using signature-based detection." | ATR-2026-00001 "Direct Prompt Injection via User Input"; ATR-2026-00002 "Indirect Prompt Injection via External Content"; ATR-2026-00452 "Direct PWNED Payload Injection in User Input" | pattern | Strong — these are the canonical signature-based prompt-injection detections this requirement names |
| v1.0-C13.2.4 | "Verify that custom rules detect AI-specific threat patterns, including coordinated jailbreak attempts, prompt injection campaigns, system prompt extraction attempts, and model extraction attacks." | ATR-2026-00574 "Paraphrased System-Prompt / Context Extraction (Semantic)"; ATR-2026-00002 "Indirect Prompt Injection via External Content" | semantic (00574), pattern (00002) | Strong — system-prompt-extraction detection (incl. paraphrase-robust semantic rule) directly satisfies the "system prompt extraction attempts" clause |
| v1.0-C13.2.7 | "Verify that session-level conversation trajectory analysis detects multi-turn jailbreak patterns where no single turn looks overtly malicious on its own, but the conversation as a whole shows attack indicators." | ATR-2026-00552 "Agent goal drift after environmental pressure injection" | trace | Strong — 00552 correlates pressure-injection spans with later goal-change spans across the session DAG — exactly the multi-turn-no-single-bad-turn pattern this requirement targets |
| v1.0-C13.2.8 | "Verify that LLM API traffic is monitored for covert channel indicators, including Base64-encoded payloads, structured non-human query patterns, and communication signatures consistent with malware command-and-control activity using LLM endpoints." | ATR-2026-00152 "Obfuscated Credential Exfiltration via Encoding"; ATR-2026-00261 "Markdown Image URL Data Exfiltration" | pattern | Partial — ATR detects encoded-payload / covert-exfil channel indicators in content; full network C2 telemetry is the platform's |
| v1.0-C13.6.5 | "Verify that behavioral anomaly detection identifies deviations in proactive agent patterns that may indicate compromise." | ATR-2026-00552 "Agent goal drift after environmental pressure injection"; ATR-2026-00553 "Runaway tool-call loop within a single session" | trace | Partial — ATR's trace rules surface specific compromise-indicative deviations (goal drift, runaway loops); broader statistical baselining is the platform's |

### 5.1 C13 notes

- C13.1 (logging schema/telemetry), C13.3 (drift detection), C13.5 (IR planning)
  are platform/process requirements; ATR feeds them content (each match is a
  structured event) but does not implement the logging or IR pipeline.
- Every ATR match carries `rule_id`, `severity`, category, and matched selectors
  (SPEC.md §7), which directly supports the "enriched security events …
  AI-specific context" intent of 13.2.2 when emitted into the consuming SIEM.

---

## 6. Implementation guidance (for an org using ATR toward AISVS)

1. Deploy an ATR-conformant engine (reference: `npm:agent-threat-rules`).
2. For C9/C13 trajectory requirements (9.2.1, 9.9.6, 13.2.7), enable the `trace`
   method (assisted runtime profile, atr-method-v1.1.md §4.1) and feed the agent's
   OpenInference/OpenTelemetry spans to the engine.
3. For C10 and C13 signature requirements, the default deterministic profile
   (`pattern` + `signature`) covers the MCP and prompt-injection rule sets in the
   in-line hot path.
4. Emit each match as an analyzed event into the platform that owns the AISVS
   logging (C13.1) and enforcement (C9 gates) controls. ATR provides detection
   content; it does not replace the platform's logging, identity, sandbox, or
   approval-enforcement machinery.

## 7. Open items

- Behavioral-method rules (statistical thresholds over windows) are a normative
  placeholder in atr-method-v1.1.md §7; several C9.1 budget and C13.3 drift
  requirements would map to behavioral rules once that plane is fully specified.
- This mapping covers C9/C10/C13 only. C1–C8, C11, C12 are out of scope for this
  draft.
- Requirement text and IDs were re-verified verbatim against the AISVS `main`
  branch chapter files on 2026-06-12 (C9: 9.1.3/9.2.1/9.6.3/9.6.4/9.8.4/9.9.6;
  C10: 10.1.1/10.4.1/10.4.4/10.4.5/10.4.8/10.6.2; C13: 13.2.1/13.2.4/13.2.7/13.2.8/
  13.6.5 — all present, text matches). OWASP AISVS has published **no tagged
  release** (the repo's Releases page is empty as of 2026-06-12), so `main` is the
  canonical source. Because there is no frozen tag, IDs can still renumber as the
  living standard evolves — re-verify against `main` before any external
  submission.
- **Requirements freeze.** The AISVS CONTRIBUTING guide states a requirements
  freeze of **2026-04-30**: after that date "no new requirements will be accepted
  for v1.0", though "editorial fixes and clarifications remain welcome." This
  mapping does NOT propose any new or modified requirement, so it is not blocked by
  the freeze; but it also means the upstream path here is NOT a requirement edit —
  at most an Informative-Reference / Appendix-B-References pointer, or simply
  ATR-side documentation that AISVS contributors can discover. Confirm the current
  freeze posture before proposing anything upstream.
- **Observed contribution shape (2026-06-12).** The ~24 most recent merged AISVS
  PRs are exclusively internal refinement — plain-English readability passes,
  run-on-sentence splits, Oxford-comma / grammar fixes, levels reviews. None added
  an external-standard mapping or third-party informative reference. There is no
  precedent in the merged history for an external project's crosswalk being merged
  into the AISVS repo, which lowers the probability that an upstream PR of this file
  would be accepted as-is and raises the bar for how any approach is framed.
- **Contribution channel.** Per CONTRIBUTING, contributors "first log ideas,
  issues, or questions" as a GitHub issue before any PR ("We may also ask you to
  open a pull request … based on the discussion in the issue"). The correct first
  move — if pursued at all — is a scoped issue, not an unsolicited PR. AISVS also
  states "AI tools are welcome … [but] every contribution must reflect the
  contributor's own security judgment" and rejects "large blocks of AI-generated
  text" / "thin idea wrapped in generated prose" — so any issue must be short,
  human-authored, and lead with the concrete testability angle.
- Project leadership is publicly listed in the AISVS README (founder Jim Manico;
  current leaders Jim Manico, Otto Sulin, Rico Komenda, Russ Memisyazici, Raza
  Sharif). Named here only as public project facts; do not address or cite
  individuals beyond what the repo publishes.
- No OWASP maintainer has reviewed this mapping. It is a draft basis for a future
  issue/Informative-Reference discussion, gated on human review.

## 8. References

- OWASP AISVS 1.0 — C9: `1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md`
- OWASP AISVS 1.0 — C10: `1.0/en/0x10-C10-MCP-Security.md`
- OWASP AISVS 1.0 — C13: `1.0/en/0x10-C13-Monitoring-and-Logging.md`
- AISVS repository (CC BY-SA 4.0): https://github.com/OWASP/AISVS
- AISVS README (referencing format, "What AISVS is NOT" / vendor-neutrality,
  complements-other-standards table): https://github.com/OWASP/AISVS/blob/main/README.md
- AISVS CONTRIBUTING (issue-first process, 2026-04-30 requirements freeze,
  AI-assisted-contribution standards): https://github.com/OWASP/AISVS/blob/main/CONTRIBUTING.md
- ATR SPEC.md (Core v1.0.0) · atr-method-v1.1.md (Method Extensions v1.1.0)
- Cross-reference convention: per-rule `references.<framework>` fields
  (atr-method-v1.1.md §9.3); this file is an Informative Reference per
  spec/mappings/README.md.
