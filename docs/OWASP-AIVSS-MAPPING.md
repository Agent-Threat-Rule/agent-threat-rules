# ATR -> OWASP AIVSS (AI Vulnerability Scoring System) Mapping

Last updated: 2026-07-12
ATR version: v3.5.8 (793 rules)
OWASP framework: AIVSS v0.8 (March 2026) — OWASP Agentic AI Core Security Risks

## What this maps, and what it does not

AIVSS scores how severe an agentic-AI vulnerability is. It pairs a CVSS-style base
with an Agentic AI Risk Score built from five amplification factors. ATR does not
compute AIVSS scores, and AIVSS does not depend on ATR. What ATR provides is the
executable detection layer: for each AIVSS core risk, ATR rules supply the runtime
observation that the risk is actually occurring, and the matched-rule evidence that
informs the amplification factors.

Scope notes (kept honest):

- The AIVSS v0.8 scoring formula and factor weights are not published, so this document
  maps ATR detections to AIVSS risks and factors, not to numeric score values.
- This is a crosswalk by an independent open project. It does not imply AIVSS adopts or
  endorses ATR.
- Two of the ten AIVSS risks are under-covered by ATR today; they are marked GAP below
  rather than overstated.

## Coverage by AIVSS core risk

Strength tiers: STRONG >= 40 mapped rules, MODERATE 10-39, LIMITED 1-9, GAP 0.

| # | AIVSS core risk | Primary ATR categories | Rules | Strength |
|---|---|---|---|---|
| 1 | Agentic AI Tool Misuse | tool-poisoning, excessive-autonomy | 94 | STRONG |
| 2 | Agent Access Control Violation | privilege-escalation | 35 | MODERATE |
| 3 | Agent Data Exfiltration | context-exfiltration | 104 | STRONG |
| 4 | Agent Memory and Context Manipulation | data-poisoning, agent-manipulation (memory) | 18 | MODERATE |
| 5 | Multi-Agent Orchestration Attacks | agent-manipulation (cross-agent / inter-agent) | 24 | MODERATE |
| 6 | Agent Goal Manipulation | prompt-injection, agent-manipulation | 329 | STRONG |
| 7 | Context Amnesia Exploitation | agent-manipulation (context reset / drop) | 6 | LIMITED |
| 8 | Agent Supply Chain and Dependency Attacks | skill-compromise, tool-poisoning | 110 | STRONG |
| 9 | Agent Untraceability | (trace tampering — documented as ATD-T0022) | 0 | GAP |
| 10 | Agent Goal and Instruction Manipulation | prompt-injection, agent-manipulation | 329 | STRONG |

Notes. Risks 6 and 10 overlap in AIVSS v0.8 (goal manipulation vs goal-and-instruction
manipulation); ATR covers both through the same prompt-injection and agent-manipulation
clusters, so the rule counts repeat rather than add. Counts are the size of the primary
ATR categories at v3.5.0 and are indicative of coverage breadth, not a per-rule audit.

## Per-risk detail

1. Agentic AI Tool Misuse. tool-poisoning (65) detects poisoned tool descriptions,
   malicious MCP responses, and command injection through tool I/O; excessive-autonomy
   (29) detects destructive tool calls without human approval and runaway tool loops.

2. Agent Access Control Violation. privilege-escalation (35) detects confused-deputy
   token passthrough, scope escalation, and unauthorized capability acquisition.

3. Agent Data Exfiltration. context-exfiltration (104) detects context, credential, and
   system-prompt leakage through tool channels and crafted outputs.

4. Agent Memory and Context Manipulation. data-poisoning (5) plus the memory-write and
   cross-conversation rules inside agent-manipulation detect persistent memory poisoning
   and context tampering. Coverage is moderate; long-horizon memory remains an open area.

5. Multi-Agent Orchestration Attacks. the cross-agent, inter-agent-message-spoofing and
   cascading-failure rules inside agent-manipulation detect injection propagation and
   consensus/sybil manipulation across an agent swarm.

6 and 10. Agent Goal (and Instruction) Manipulation. prompt-injection (223) plus
   agent-manipulation (106) detect direct and indirect injection, persona hijack,
   encoding/multilingual evasion, and casual-authority goal redirection.

7. Context Amnesia Exploitation. partially covered by context-reset and trust-after-reset
   rules in agent-manipulation. Marked LIMITED; this is a candidate area for new rules.

8. Agent Supply Chain and Dependency Attacks. skill-compromise (45) detects malicious
   skills and rug-pulls (grounded in the 552 confirmed-malicious-skill corpus);
   tool-poisoning (65) covers compromised MCP servers and dependency injection.

9. Agent Untraceability. GAP. ATR is runtime content detection and does not currently
   assert on audit-trail completeness or tamper-evidence. The technique is catalogued as
   ATD-T0022 (trace tampering / non-tamper-evident agent audit logs); a detection rule
   would need a trace-integrity signal ATR does not yet model. Stated as a gap, not coverage.

## Amplification factors

AIVSS amplifies a base score by five agentic factors. ATR detections inform four of them;
non-determinism is outside ATR's deterministic-detection scope.

| AIVSS factor | How ATR detections inform it |
|---|---|
| Autonomy level | excessive-autonomy rules flag destructive actions taken without human approval and runaway loops — direct evidence the autonomy factor is live |
| Tool use scope | tool-poisoning and privilege-escalation rules observe the breadth and sensitivity of tools the agent invokes |
| Multi-agent interactions | agent-manipulation cross-agent / inter-agent rules observe agent-to-agent message flows being exploited |
| Self-modification capacity | memory-write (data-poisoning) and goal-drift (agent-manipulation) rules observe an agent altering its own instructions or persisted state |
| Non-determinism | not covered. ATR is deterministic content detection and does not measure output variance; this factor is left to the AIVSS assessor |

## References

- OWASP AIVSS: https://aivss.owasp.org/
- OWASP Agentic Top 10 mapping (companion): docs/OWASP-AGENTIC-MAPPING.md
- ATD technique catalogue: https://agentthreatrule.org/atd
