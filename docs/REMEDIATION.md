# ATR Remediation Guide

What to do when ATR detects a threat.

## Quick Reference: Severity to Action

| Severity | Action | Timeline |
|----------|--------|----------|
| CRITICAL | Stop the agent immediately. Revoke credentials. Investigate before resuming. | Now |
| HIGH | Isolate the agent. Review logs. Block the offending input/tool before resuming. | Within 1 hour |
| MEDIUM | Log the event. Review the flagged content. Apply targeted mitigation. | Within 24 hours |
| LOW | Monitor for recurrence. Schedule a fix in your next sprint. | Within 1 week |
| INFO | No immediate action. Review periodically for pattern escalation. | As needed |

---

## 1. Prompt Injection (30 rules)

**What was detected:** An attempt to override, hijack, or manipulate the agent's instructions through crafted input — either directly from user text or indirectly via external content (documents, web pages, tool outputs).

**Risk level:** The agent executes attacker-chosen actions instead of legitimate ones. This can lead to data exfiltration, unauthorized tool calls, or complete loss of agent control.

**Immediate action:**
- Halt the agent session that triggered the alert.
- Do NOT re-run the same input. Inspect the raw payload to identify the injected instructions.
- If the agent executed any tool calls after the injection point, audit every action it took. Assume those actions were attacker-directed.
- Check if any data was sent to external endpoints during the compromised session.

**Long-term fix:**
- Enforce strict input/output boundaries: user content must never be interpreted as system instructions.
- Use structured tool call interfaces (typed schemas) instead of free-text command parsing.
- Implement a prompt firewall that scans all external content before it enters the agent's context.
- Apply least-privilege: even if injection succeeds, the agent should lack permissions to cause serious harm.
- Add multi-turn context tracking to detect gradual injection across conversation turns.

---

## 2. Tool Poisoning (11 rules)

**What was detected:** A tool description, tool response, or MCP server output contains hidden instructions, exfiltration payloads, or manipulative content designed to alter agent behavior.

**Risk level:** The agent trusts poisoned tool output as factual data, leading it to execute hidden commands, leak context to attacker-controlled endpoints, or make decisions based on fabricated information.

**Immediate action:**
- Disconnect the flagged MCP server or tool immediately.
- Review the tool's description and recent responses for embedded instructions (look for base64, invisible unicode, or natural-language directives).
- Audit all agent actions that occurred after consuming the poisoned tool output.
- If the tool is third-party, check its source repository for recent suspicious commits.

**Long-term fix:**
- Pin tool versions and audit tool descriptions on every update. Diff descriptions before accepting changes.
- Run tool responses through ATR scanning before the agent processes them.
- Maintain an allowlist of verified tools. Block unverified tools by default.
- Implement tool response validation: schema-check outputs and reject responses containing instruction-like patterns.
- Never grant tools the ability to modify their own permissions or descriptions.

---

## 3. Context Exfiltration (14 rules)

**What was detected:** An attempt to extract sensitive data (API keys, credentials, system prompts, internal configuration, PII) from the agent's context and transmit it externally.

**Risk level:** Credentials or secrets are stolen and used to access your systems. System prompts are leaked, revealing business logic and security controls. User PII is exfiltrated, creating compliance liability.

**Immediate action:**
- Rotate any credentials that were present in the agent's context during the flagged session. Do this before further investigation.
- Block the destination URL/IP if an exfiltration attempt reached an external endpoint.
- Review agent logs for any HTTP requests, tool calls, or file writes that occurred during the session.
- Check if system prompts or internal configuration were included in any agent output.

**Long-term fix:**
- Never put raw secrets in agent context. Use secret references that resolve at execution time with scoped, short-lived tokens.
- Implement output filtering: scan all agent outputs (including tool call arguments) for credential patterns before they leave the system.
- Restrict network access: agents should only reach pre-approved domains.
- Apply egress monitoring on all agent-initiated requests.
- Redact sensitive fields from context before they enter the agent's working memory.

---

## 4. Skill Compromise (17 rules)

**What was detected:** A malicious or tampered SKILL.md file or MCP skill definition containing hidden commands, privilege escalation directives, or exfiltration logic disguised as legitimate skill instructions.

**Risk level:** The agent loads attacker-controlled instructions as trusted skill definitions, giving the attacker persistent influence over agent behavior across sessions. Compromised skills can instruct the agent to exfiltrate data, modify files, or bypass safety controls.

**Immediate action:**
- Remove or quarantine the flagged skill file immediately.
- If the skill was already loaded, terminate all active agent sessions using it.
- Audit what the skill instructed the agent to do. Check for file modifications, network requests, or credential access.
- Review the skill's installation source (npm package, git repo, marketplace) for tampering.

**Long-term fix:**
- Verify skill integrity using checksums or signatures before loading.
- Scan all SKILL.md and MCP skill definitions with ATR before the agent consumes them.
- Implement a skill allowlist. Only load skills from verified publishers.
- Use read-only skill mounting: skills should not be able to modify themselves or other skills.
- Monitor skill files for unexpected changes (file integrity monitoring).
- Review skill permissions: a skill that needs to read files should not have network access.

---

## 5. Agent Manipulation (12 rules)

**What was detected:** Social engineering tactics targeting the agent — urgency fabrication, false authority claims, emotional manipulation, or persona hijacking designed to override the agent's safety boundaries.

**Risk level:** The agent is persuaded to bypass its own safety controls, execute unauthorized actions, or disclose restricted information. Unlike prompt injection (which exploits parsing), manipulation exploits the agent's instruction-following behavior.

**Immediate action:**
- Flag the session for human review. Do not let the agent continue autonomously.
- Check if the agent deviated from its defined behavior policy during the session.
- Review the full conversation history for escalating manipulation patterns (single messages may look benign in isolation).
- If the agent took real-world actions (sent emails, called APIs, modified data), verify each action was legitimate.

**Long-term fix:**
- Define explicit behavioral boundaries that the agent cannot override regardless of conversational pressure.
- Implement a "safety boundary" that requires human approval for sensitive actions, even if the agent is "convinced" it should proceed.
- Add manipulation detection to your agent's pre-processing pipeline.
- Train or configure agents to recognize and reject authority claims, urgency pressure, and emotional appeals that conflict with policy.
- Log and review sessions where the agent's confidence in safety was low.

---

## 6. Privilege Escalation (10 rules)

**What was detected:** An attempt to gain elevated permissions — accessing admin functions, modifying access controls, escalating from user to system roles, or bypassing authorization checks through the agent.

**Risk level:** An unprivileged user gains admin-level access through the agent. This can lead to full system compromise, data destruction, unauthorized configuration changes, or lateral movement to connected systems.

**Immediate action:**
- Revoke any permissions that were granted during the flagged session.
- Check if the agent's service account or API keys have broader permissions than intended.
- Audit access logs for the affected systems. Look for actions performed with escalated privileges.
- If escalation succeeded, treat it as a security incident: isolate affected systems and begin incident response.

**Long-term fix:**
- Apply least-privilege to all agent service accounts. Agents should have the minimum permissions required for their task.
- Implement permission boundaries that cannot be modified by the agent itself or through conversational requests.
- Use separate service accounts for different privilege levels. Never use a single admin-level account for general agent operations.
- Add runtime authorization checks: verify permissions on every tool call, not just at session start.
- Implement privilege escalation detection in your monitoring stack, independent of ATR.

---

## 7. Excessive Autonomy (5 rules)

**What was detected:** An agent operating beyond its intended scope — making decisions without required human approval, executing high-impact actions autonomously, or accumulating capabilities beyond its defined role.

**Risk level:** The agent causes unintended real-world consequences (financial transactions, data deletion, system changes) without human oversight. Even without malicious intent, an over-autonomous agent can cause significant damage through compounding errors.

**Immediate action:**
- Pause the agent. Review what actions it took beyond its approved scope.
- Check if any high-impact actions (financial, destructive, or irreversible) were executed without human approval.
- Revert any unauthorized changes if possible.
- Verify that the agent's approval workflow is correctly configured and was not bypassed.

**Long-term fix:**
- Define a clear action classification: which actions require human approval, which are auto-approved, and which are blocked entirely.
- Implement hard guardrails (not just soft prompts) that enforce human-in-the-loop for destructive or high-value operations.
- Set rate limits and scope boundaries: cap the number of tool calls per session, restrict accessible resources, and time-box autonomous operation.
- Add a "dead man's switch": if the agent cannot reach a human approver, it should stop rather than proceed.
- Regularly audit agent autonomy levels as capabilities expand.

---

## 8. Data Poisoning (2 rules)

**What was detected:** An attempt to corrupt the agent's knowledge base, training data, RAG sources, or persistent memory with false, biased, or malicious information.

**Risk level:** The agent's future decisions are silently corrupted. Poisoned data persists across sessions, affecting all users and all subsequent interactions. This is particularly dangerous because the damage is not immediately visible.

**Immediate action:**
- Identify which data source was flagged (RAG index, vector store, knowledge base, agent memory).
- Quarantine the affected data. Do not allow agents to query it until verified.
- If the poisoned data was already consumed, identify all sessions and outputs that may have been influenced.
- Check the data ingestion pipeline for unauthorized writes or unexpected sources.

**Long-term fix:**
- Implement write access controls on all agent knowledge sources. The agent should not be able to modify its own training data without review.
- Add integrity checks on data ingestion: validate sources, check for anomalous content, and require approval for bulk updates.
- Version your knowledge bases so you can roll back to a known-good state.
- Monitor for data drift: compare current knowledge base content against baselines to detect gradual poisoning.
- Separate the data plane from the control plane: the agent that reads data should not be the same principal that writes it.

---

## 9. Model Security (1 rule)

**What was detected:** An attempt to extract the model's behavior patterns, system configuration, fine-tuning details, or safety boundaries through systematic probing.

**Risk level:** An attacker maps out the agent's safety controls and behavioral boundaries, then uses this knowledge to craft targeted attacks that bypass those controls. Model extraction can also reveal proprietary business logic embedded in system prompts.

**Immediate action:**
- Review the flagged session for systematic probing patterns (repetitive edge-case queries, boundary testing, prompt reflection requests).
- Check if any system prompt content or safety configuration was disclosed in agent responses.
- Rate-limit or block the source if probing is ongoing.

**Long-term fix:**
- Implement response filtering that detects and blocks system prompt leakage.
- Add rate limiting and anomaly detection for sessions with unusually high query volumes or repetitive patterns.
- Avoid embedding sensitive business logic directly in system prompts. Use server-side logic that the agent calls but cannot inspect.
- Monitor for and rotate system prompts periodically if extraction is a concern.
- Use canary tokens in system prompts to detect when they have been extracted and shared.

---

## General Incident Response

Regardless of category, when ATR fires a CRITICAL or HIGH alert:

1. **Contain** — Stop the agent. Kill the session. Block the input source.
2. **Assess** — What did the agent do after the threat appeared? Audit every action.
3. **Remediate** — Rotate credentials, revert unauthorized changes, quarantine poisoned data.
4. **Report** — Document the incident. What was the attack vector? What was the blast radius?
5. **Harden** — Update rules, tighten permissions, add the attack pattern to your monitoring.

## Resources

- [ATR Core Specification](../SPEC.md) — Understanding rule definitions
- [Quick Start](quick-start.md) — Setting up ATR scanning
- [Rule Writing Guide](rule-writing-guide.md) — Contributing new detection rules
- [OWASP Agentic Top 10 Mapping](OWASP-MAPPING.md) — How ATR maps to OWASP categories
