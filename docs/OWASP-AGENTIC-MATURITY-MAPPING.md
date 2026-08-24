# ATR → OWASP Agentic AI Maturity Model Alignment

Version: 0.1.0 (INTERNAL DRAFT — not published)
Status: Draft alignment note for the OWASP Agentic adoption maturity model
Date: 2026-06-14
Editor: Adam Lin (林冠辛) <adam@agentthreatrule.org>
Mapped corpus: Agent Threat Rules v3.5.8 (793 rules / 10 categories)
Reference: "State of Agentic AI Security and Governance" (v2.01), OWASP GenAI Security Project, June 2026 — https://genai.owasp.org/resource/state-of-agentic-ai-security-and-governance/

---

## 1. Purpose

The OWASP GenAI Security Project's June 2026 report includes an **enterprise adoption
maturity model** for agentic AI — a posture assessment that plots an organisation's
agent deployment against its governance maturity. This note states where the Agent
Threat Rules (ATR) detection corpus supplies the *runtime-detection controls* that the
model associates with higher governance maturity.

This is an **alignment / informative-reference note**, not a claim of OWASP adoption or
endorsement. OWASP names no products. The honest claim is narrow: ATR rules are an
example of the executable detection control that an organisation needs in place to
substantiate — rather than merely assert — a mature agentic-governance posture.

## 2. Source-fidelity caveat (read before citing)

The full report PDF is access-gated (OWASP serves a "No Access" page on the direct
download URL — it requires a registration/download form), so the granular structure
below is drawn from OWASP's public resource page and reputable secondary coverage,
**not** from the primary PDF. Verified 2026-06-14 that the direct download is gated;
primary-source confirmation is therefore pending access. Two specifics could not be
reconciled across public sources and **must be confirmed against the PDF before any
external citation**:

- the exact publication day (sources give both 1 and 3 June 2026 — cite "June 2026");
- the top of the deployment axis (sources give both AT5 and AT8).

The governance-tier *names* below are consistent across two independent outlets but are
secondary-sourced; verify wording against the PDF figure before quoting them verbatim.

## 3. Where ATR supplies evidence

The report frames mature agentic governance as requiring **continuous, real-time
oversight** rather than point-in-time review — specifically real-time drift detection,
behavioural baselines, and kill-switch/containment triggers operating at agent speed.
These are detection controls. ATR is the open, executable rule layer that implements
them, mapped through the OWASP Top 10 for Agentic Applications (ASI01–ASI10, Dec 2025):

| Maturity control the model calls for | OWASP ASI threat | ATR evidence (example rules) |
|---|---|---|
| Real-time goal/behaviour **drift detection** | ASI01 Agent Goal Hijack | ATR-2026-00552 (goal drift after pressure injection, trace), ATR-2026-00032 (goal hijacking) |
| **Kill-switch / containment** for runaway autonomy | ASI08 Cascading Failures, ASI10 Rogue Agents | ATR-2026-00050 (runaway agent loop), ATR-2026-00051 (resource exhaustion), ATR-2026-00549 (destructive tool without human approval, trace) |
| **Behavioural baselines** for tool/memory abuse | ASI02 Tool Misuse, ASI06 Memory & Context Poisoning | tool-poisoning corpus (65 rules), ATR-2026-00551 (cross-conversation memory write, trace) |
| Monitoring **at agent speed** | ASI01–ASI03 broadly | the full corpus runs on a regex engine (sub-100 ms), i.e. machine-speed inline detection |

Per-ASI rule counts are maintained in [OWASP-AGENTIC-MAPPING.md](OWASP-AGENTIC-MAPPING.md)
and regenerated from rule metadata.

## 4. Claim discipline

- The report is a "State of…" report, **not a standard** (no RFC 2119, not certifiable). Cite the parent report, not "the maturity model" as a standalone normative document.
- **Do not** claim OWASP adopted, endorsed, or recommends ATR.
- Governance maturity is an **organisational** posture; ATR supplies *evidence toward* a maturity claim (the detection controls), not the maturity itself — an organisation still needs the policies, dashboards, and human processes around the rules.
- Do not pin the exact publication day or the top of the deployment axis (see §2).
