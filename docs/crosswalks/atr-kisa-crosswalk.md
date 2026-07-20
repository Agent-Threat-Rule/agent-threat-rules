# ATR -> KISA/MSIT AI Security Threat Mitigation Manual crosswalk

This document maps the threat taxonomy from the Republic of Korea's national
*AI Security Threat Mitigation Manual* (AI 보안 위협 대응 매뉴얼) onto Agent
Threat Rules (ATR) detection content, and -- just as importantly -- states
clearly which threat classes ATR **does not** cover because they are build-time
supply-chain or model-training concerns rather than a runtime attack *pattern*.

- **Source:** *AI 보안 위협 대응 매뉴얼* (AI Security Threat Mitigation Manual),
  published 2026-07 by the Ministry of Science and ICT (MSIT) and the Korea
  Internet & Security Agency (KISA), badge "KISA AI Security Red Team 2026-01".
  The manual's Appendix 1 (LLM security threats and international framework
  mapping table) assigns each threat an OWASP LLM, NIST AML, and MITRE ATLAS
  reference.
- **Method:** this crosswalk is a mechanical join on the MITRE ATLAS technique
  IDs that the manual itself assigns in Appendix 1. Because both sides reference
  the same ATLAS techniques, the join is reproducible and auditable rather than
  a subjective interpretation. An ATLAS technique mapping is still interpretive
  by nature, so treat the class sizes below as coverage indicators, not exact
  equivalences.
- **This mapping:** hand-authored, 2026-07-20. Class sizes are read from the
  ATR rule directories at authoring time (**768 rules** total). Verify counts
  against `data/stats.json` before any external citation.
- **Status:** community, unofficial. This document does **not** cite, and must
  not be read to imply, any endorsement by MSIT, KISA, or the Korea AI Safety
  Institute. It is an independent crosswalk contributed by the ATR maintainers.
- **Companion documents:**
  [`atr-attack-crosswalk.md`](atr-attack-crosswalk.md),
  [`atr-ast-crosswalk.md`](atr-ast-crosswalk.md),
  [`atr-unit42-biv-crosswalk.md`](atr-unit42-biv-crosswalk.md).

## Where ATR sits in the manual's model (read first)

The manual classifies AI security threats into model/data threats (M0x), agent
threats (A0x), supply-chain threats (S0x), and high-performance-model threats
(H0x), then gives sector scenarios and response measures. ATR is a runtime,
content-layer detection ruleset: its strength is the agent and LLM-interaction
threats (agent hijacking, improper tool design, jailbreak), and it deliberately
does **not** attempt the build-time supply-chain classes (training-data or
model poisoning, vulnerable inference engines), which are addressed before
runtime by provenance, signing, and dependency controls.

## Mapping

| Manual threat | ATLAS anchor(s) from Appendix 1 | ATR rules | Coverage |
|---|---|---|---|
| A02 Agent Hijacking (indirect prompt injection) | AML.T0051.001, AML.T0085.001 | 82 | Strong -- ATR's core agent-layer fit |
| A01 Improper Tool Design (over-privilege) | AML.T0053, AML.T0081-T0086 | 68 | Strong |
| M06 Jailbreak | AML.T0054 | 163 | Strongest overall |
| H01 Advanced cyber-attack support | AML.T0048 | 18 | Partial |
| M03 System Prompt Leakage | AML.T0056 | 8 | Partial |
| S04 Vulnerable Agent Extension | AML.T0010.005 | 4 | Emerging (sub-technique tagged 2026-07) |
| A04 Agent Memory Poisoning | AML.T0080.001, AML.T0020 | 4 | Thin |
| A03 Agent DoS | AML.T0029, AML.T0034 | 2 | Thin |
| S01-S03 Data/model poisoning, vulnerable inference engine | AML.T0010.001-.004, AML.T0020 | -- | Out of scope (build-time supply chain) |
| H02 Loss of control (autonomy) | OWASP LLM06 only; no ATLAS anchor | -- | No ATLAS anchor to join on |

Representative rules: A02 -> ATR-2026-00417 (MCP argument injection, CVE-backed),
ATR-2026-00074 (cross-agent privilege escalation); A01 -> ATR-2026-01928,
ATR-2026-02023; A04 -> ATR-2026-01774 (RAG and memory poisoning); S04 ->
ATR-2026-00096 (skill registry poisoning), ATR-2026-00060 (skill impersonation).

## Honest coverage boundary

ATR covers the runtime content layer well (A01, A02, M06). It is thin on agent
DoS (A03) and memory poisoning (A04), and it does not attempt data or model
poisoning or vulnerable inference engines (S01-S03) -- those are build-time
supply-chain controls outside a content-detection ruleset. The
high-performance autonomy class (H02) has no ATLAS anchor in the manual to join
on, so it is listed for completeness rather than mapped.
