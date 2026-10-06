# ATR → CSA MAESTRO Layer Mapping

Last updated: 2026-08-11
ATR corpus: v3.5.12, 777 effective rules (784 files, 10 categories)
> Rule counts are a dated snapshot and move daily (auto-crystallize + ecosystem PRs); for the live figure see stats.json on the ATR repo.
Source framework: **MAESTRO — Multi-Agent Environment, Security, Threat, Risk & Outcome**,
Cloud Security Alliance (2025). A layered threat-modeling framework for agentic AI that
decomposes an agent system into seven architectural layers, each with its own threat
surface. Reference: https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro

> **What this mapping is.** MAESTRO is an *architectural* threat-modeling framework, not a
> numbered attack taxonomy (unlike MITRE ATLAS or MCP-38). It asks "which layer of the agent
> stack does a threat live in, and how do threats cross layers?" This crosswalk therefore maps
> at the **ATR-category → MAESTRO-layer** granularity: for each of MAESTRO's seven layers, it
> lists the ATR detection categories that produce runtime evidence for threats at that layer.
> A single ATR category can serve more than one layer (e.g. prompt-injection is a Foundation-
> Model threat when direct, a Data-Operations threat when indirect via retrieved content, and
> an Agent-Frameworks threat when injected through tool output). Rule counts are the size of
> each contributing category, not a claim that every rule in it is layer-exclusive.

> **Relationship.** MAESTRO is a *modeling* framework; ATR is the *detection* layer beneath it.
> MAESTRO Layer 5 (Evaluation & Observability) and the cross-cutting Layer 6 (Security &
> Compliance) explicitly call for runtime controls and continuous evidence — ATR rules are
> that evidence, mapped to EU AI Act / NIST AI RMF / ISO 42001 in each rule's `compliance:`
> block. CSA's 2026 guidance frames the threat model as a continuous property regenerated on
> every commit; ATR is detection-as-code that runs in that same pipeline.

## Coverage summary

| MAESTRO layer | Threat surface | Primary ATR categories | Rules |
|---|---|---|---|
| **L1 Foundation Models** | The LLM itself: jailbreak, model manipulation, behavior extraction | model-abuse, model-security, prompt-injection (direct) | 44 + PI |
| **L2 Data Operations** | RAG, memory, embeddings, training/ingested data | data-poisoning, context-exfiltration, prompt-injection (indirect) | 134 + PI |
| **L3 Agent Frameworks** | Tool-calling, planning, skill/plugin runtime | tool-poisoning, excessive-autonomy, skill-compromise | 189 |
| **L4 Deployment & Infrastructure** | Hosting, sandboxing, host privileges, persistence | privilege-escalation | 60 |
| **L5 Evaluation & Observability** | Detection, monitoring, runtime evidence | *(ATR is this layer)* — all 777 | 777 |
| **L6 Security & Compliance** *(cross-cutting)* | Regulatory obligation + control evidence across all layers | *(ATR compliance block)* — all 777 | 777 |
| **L7 Agent Ecosystem** | Multi-agent interaction, inter-agent trust, marketplace/supply chain | agent-manipulation, skill-compromise (supply chain) | 156 |

Every ATR rule maps to at least one horizontal layer (L1–L4, L7) **and** contributes to the two
cross-cutting layers (L5 detection, L6 compliance), which is MAESTRO's intended shape: the
security/observability layers are vertical concerns that intersect every functional layer.

---

## Detailed mapping

### L1 — Foundation Models
The model's own attack surface: adversarial prompts that alter model behavior, jailbreaks that
defeat safety training, and extraction of model behavior or system configuration.
- **model-abuse** (41) — jailbreak, safety-bypass, adversarial output shaping
- **model-security** (3) — model tampering / deserialization / weight-level threats
- **prompt-injection** (direct subset of 249) — instruction-override delivered straight to the model input

### L2 — Data Operations
Threats in the data plane the agent reads and writes: RAG corpora, long-term memory, embeddings,
and any ingested content the model treats as trusted context.
- **data-poisoning** (9) — RAG / knowledge-base / memory contamination
- **context-exfiltration** (125) — credential/secret/PII leaving through the agent's context
- **prompt-injection** (indirect subset) — payloads embedded in retrieved documents, tool output, or memory

### L3 — Agent Frameworks
The agent runtime itself: tool/function calling, planning loops, and the skill/plugin extension
surface where MCP tools and skills execute.
- **tool-poisoning** (97) — malicious tool descriptions, MCP tool-response manipulation, command injection via tool args
- **excessive-autonomy** (33) — runaway loops, unauthorized high-blast-radius actions, missing human-in-the-loop
- **skill-compromise** (45) — MCP skill impersonation, hidden capability, description-behavior mismatch

### L4 — Deployment & Infrastructure
The host the agent runs on: sandbox escape, privilege boundaries, and startup/persistence.
- **privilege-escalation** (51) — scope escalation, sandbox escape, autostart/persistence, host-level RCE

### L5 — Evaluation & Observability *(cross-cutting)*
MAESTRO's detection and monitoring layer. **ATR is a realization of this layer**: 777 deterministic
rules that run over SKILL.md files, MCP tool descriptions, tool arguments, agent I/O, and behavioral
traces, emitting rule-ID-tagged findings suitable for SIEM ingestion (MISP taxonomy, Sigma).

### L6 — Security & Compliance *(cross-cutting)*
MAESTRO's vertical security/governance concern. Every ATR rule carries a `compliance:` block mapping
its detection to **EU AI Act** (Articles 9/10/12/13/14/15), **NIST AI RMF** (GV/MP/MS/MG), and
**ISO 42001** (clauses 6.2, 8.1–8.4, 9.1) — turning a MAESTRO-layer threat into auditor-readable
evidence. Coverage is CI-enforced at 100% with 0 fabricated identifiers.

### L7 — Agent Ecosystem
The multi-agent / ecosystem layer: inter-agent communication, delegation-chain trust, human-agent
trust, and the skill/tool marketplace supply chain.
- **agent-manipulation** (108) — cross-agent attacks, goal hijacking, inter-agent comms abuse, human-agent trust exploitation, Sybil/consensus attacks
- **skill-compromise** (supply-chain subset of 45) — marketplace poisoning, compromised tool distribution, malicious skill updates

---

## Notes & caveats
- This is a first-pass architectural mapping produced against ATR v3.5.12 (777 effective rules). MAESTRO layer
  names follow the CSA 2025 framework; MAESTRO V2 (expected 2026) may refine per-layer threat detail,
  at which point this crosswalk should be re-validated.
- "Rules" counts are the size of each contributing ATR category, not a per-rule layer-exclusivity claim.
  Prompt-injection (246 rules) deliberately spans L1/L2/L3 because injection is a cross-layer attack class.
- This crosswalk is a community-authored alignment, not a CSA endorsement or a MAESTRO adoption of ATR.
