# PR #781: the 53 published mapping rows

Original head `8973e93c89c692806a5011e39b44aff77ce914af`; base `d38e56cba35d268d4d6d19247035ba5a25740412`. Verdicts below precede local proposed fixes. AI-assisted advisory review; CHC-YHC must confirm the requested human review. This is not NIST or legal certification.

Q1 compares new versus old ID for the existing rationale. Q2 checks the ID and rationale against the complete rule and official Core. Y is limited detection support; ? means unresolved evidence; N identifies a concrete contradiction or definition error.

## Row 1: ATR-2026-00465

[rules/prompt-injection/ATR-2026-00465-garak-dan-your-prompt-here.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00465-garak-dan-your-prompt-here.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating prompt injection as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating prompt injection as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The rationale treats prompt injection as an identified risk and proposes a runtime response. This is comparatively closer to MG.1.3 response planning than MG.2.3 procedures for response and recovery from a previously unknown risk.

**Q2 reason:** The regex and declared block_input/alert response can contribute to a response plan, but the generic rationale calls the detector the primary risk treatment implementation without identifying MAP prioritization or a developed, documented response plan. Medium severity and a response declaration do not establish this scope.

**Inspected rule evidence:** Matches DAN placeholder templates such as [YOUR PROMPT HERE] and admin/developer-mode prefixes in user_input; response declares block_input and alert. Tests contain four garak attack samples and unrelated benign requests.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 (conditional secondary/partial support)

**Suggested bounded context:** Detects DAN placeholder-template and developer-mode override patterns. The configured block_input and alert recommendations can contribute detection evidence to a documented response plan for a MAP-prioritized prompt-injection risk.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Has this jailbreak risk been prioritized through MAP, and where is the approved response plan?
- Should primary strength be reduced to secondary or partial?

## Row 2: ATR-2026-00041

[rules/privilege-escalation/ATR-2026-00041-scope-creep.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/privilege-escalation/ATR-2026-00041-scope-creep.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Incremental scope expansion represents an active exploitation of agent autonomy; MG.2.3 risk treatment plans must be triggered when agents self-authorize actions beyond their initial assignment.

**Proposed full rationale at reviewed head:** Incremental scope expansion represents an active exploitation of agent autonomy; MG.1.3 risk treatment plans must be triggered when agents self-authorize actions beyond their initial assignment.

**Q1 reason:** The full rationale explicitly refers to risk treatment plans for a recognized scope-expansion risk, making MG.1.3 a closer subject than recovery from previously unknown risks.

**Q2 reason:** The rule observes language, not authorization state or actual gradual acquisition of authority. The rationale turns planning under MG.1.3 into an unconditional requirement to trigger plans and calls every match active exploitation, although the rule documents authorized scope expansion as a false-positive class.

**Inspected rule evidence:** Ten content regexes match additional actions, progressive permission requests, and reports of actions taken; response recommends escalate, alert and snapshot, with review of whether scope is authorized. Tests compare out-of-scope statements with authorized delivery and clarification language.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 (conditional secondary support)

**Suggested bounded context:** Flags language associated with unsolicited scope expansion and recommends escalation, alerting and a snapshot for authorization review. These signals can inform a documented response to a scope-expansion risk prioritized through MAP; a match does not establish that an action was unauthorized.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Which approved response plan consumes the escalation?
- How is authorized task expansion distinguished during triage?

## Row 3: ATR-2026-02400

[rules/excessive-autonomy/ATR-2026-02400-agent-approval-gate-disabled-runtime.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/excessive-autonomy/ATR-2026-02400-agent-approval-gate-disabled-runtime.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 ?.**

**Original full rationale:** MG.2.3 covers mechanisms to supersede, disengage or deactivate AI systems that demonstrate unintended behaviour. Once the approval gate is off, that mechanism is gone; alerting on the disabling command is the risk treatment that preserves the ability to intervene.

**Proposed full rationale at reviewed head:** MG.2.4 covers mechanisms to supersede, disengage or deactivate AI systems that demonstrate unintended behaviour. Once the approval gate is off, that mechanism is gone; alerting on the disabling command is the risk treatment that preserves the ability to intervene.

**Q1 reason:** The rationale concerns preserving a human intervention mechanism when approval gates are disabled, which is closer to MG.2.4 supersession/disengagement than MG.2.3 unknown-risk recovery.

**Q2 reason:** Approval-bypass detection is relevant evidence for preserving intervention capability, but it does not show that the system-level disengagement mechanism remains available or that responsibilities are assigned and understood. The claim that an alert preserves intervention is conditional on deployment and responder action.

**Inspected rule evidence:** Matches agent CLI bypass flags, tool-call arguments, trust environment variables, persisted settings and /yolo commands. Declares block_tool, alert, escalate and snapshot; message calls for authenticated human approval. False positives explicitly include authorized headless runs; tests cover those flag families and ordinary non-agent automation.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** MG.2.4 (conditional secondary/partial support)

**Suggested bounded context:** Detects commands or configuration changes that disable agent approval gates and recommends blocking the invocation and escalating for authenticated review. This can provide evidence to an assigned system-intervention process under MG.2.4; the rule does not establish that the intervention mechanism is applied.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Is approval restoration or system shutdown integrated, tested and owned by named responders?
- Does a human approval prompt here actually permit superseding, disengaging or deactivating the system?

## Row 4: ATR-2026-00243

[rules/prompt-injection/ATR-2026-00243-acronym-jailbreak.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00243-acronym-jailbreak.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 ?.**

**Original full rationale:** Detection of complete-freedom claims and explicit instructions to violate safety measures triggers the response mechanisms required by MG.2.3 to disengage or block the manipulated session before the model produces unsafe output.

**Proposed full rationale at reviewed head:** Detection of complete-freedom claims and explicit instructions to violate safety measures triggers the response mechanisms required by MG.2.4 to disengage or block the manipulated session before the model produces unsafe output.

**Q1 reason:** The rationale explicitly proposes disengaging the manipulated session before unsafe behavior, so MG.2.4 describes its intended response better than MG.2.3 recovery from an unknown risk.

**Q2 reason:** Detecting jailbreak claims and recommending block_tool is relevant to an intervention trigger, but the current rationale says it triggers session disengagement. No session-deactivation action, assigned owner or applied system mechanism is demonstrated by this rule.

**Inspected rule evidence:** Regexes on tool_response detect acronym persona creation, freedom-from-restrictions claims, bypass-all-rules language and dual responses. Response declares alert and block_tool; attack fixtures create IDOC, CHAOS, REBEL and similar personas.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** MG.2.4 (conditional secondary/partial support)

**Suggested bounded context:** Detects acronym-based jailbreak and restriction-removal patterns in tool responses and recommends alerting and blocking the tool. Matches can trigger a separately assigned MG.2.4 system-intervention process when the deployment provides one.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Does block_tool stop only one call or disengage the compromised session?
- Where are intervention responsibilities documented?

## Row 5: ATR-2026-00310

[rules/prompt-injection/ATR-2026-00310-ecoji-emoji-encoded-injection.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00310-ecoji-emoji-encoded-injection.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 ?; Q2 ?.**

**Original full rationale:** Matching Ecoji-encoded payloads must trigger risk treatment to disengage or block the manipulated prompt before the LLM decodes and executes the hidden instructions; MG.2.3 mandates that these supersede/deactivate mechanisms are defined.

**Proposed full rationale at reviewed head:** Matching Ecoji-encoded payloads must trigger risk treatment to disengage or block the manipulated prompt before the LLM decodes and executes the hidden instructions; MG.2.4 mandates that these supersede/deactivate mechanisms are defined.

**Q1 reason:** The rationale mostly describes rejecting an encoded prompt before decoding. Its supersede/deactivate terminology suggests MG.2.4, but the object is a prompt, while the official subcategory concerns AI systems demonstrating inconsistent performance or outcomes. Keyword substitution alone does not resolve that distinction.

**Q2 reason:** The detector and block_input recommendation substantiate input filtering, not that a system-level supersession/deactivation mechanism is in place and applied. MG.2.4 also includes assigned and understood responsibilities, absent here.

**Inspected rule evidence:** Five tool_response regexes recognize Ecoji labels, decode-in-monologue instructions, encoded emoji blobs and secure-system-message framing. Response declares alert and block_input. Tests document that unlabeled Ecoji blobs can evade detection.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** Do not automatically replace; review MG.1.3 response-plan support versus conditional MG.2.4 trigger evidence

**Suggested bounded context:** Detects selected Ecoji-encoded instruction wrappers and recommends rejecting the input and alerting. Any relationship to MG.2.4 depends on an applied system-intervention workflow; rejecting a payload alone is not system deactivation.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Is this mapping intended to describe input rejection or a system-level disengagement workflow?

## Row 6: ATR-2026-00075

[rules/context-exfiltration/ATR-2026-00075-agent-memory-manipulation.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/context-exfiltration/ATR-2026-00075-agent-memory-manipulation.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Risk treatment plans for memory poisoning must include controls that detect and block cross-session behavioral injection before poisoned directives propagate into future interactions.

**Proposed full rationale at reviewed head:** Risk treatment plans for memory poisoning must include controls that detect and block cross-session behavioral injection before poisoned directives propagate into future interactions.

**Q1 reason:** The current rationale explicitly concerns a risk treatment plan for memory poisoning, closer to MG.1.3 planning a response to a recognized risk than MG.2.3 response/recovery from an unknown risk.

**Q2 reason:** The full rule documents concrete proposed responses to memory poisoning and therefore provides plausible supporting evidence. However, the rationale says plans must include specific detect-and-block controls, which is not stated by MG.1.3, and no MAP prioritization or deployment integration is established.

**Inspected rule evidence:** Regexes match persistent-memory write directives, instruction replacement, cross-session behavior changes and erasure of safety constraints. Declares block_input, alert, snapshot, reset_context and escalate; tests contrast malicious persistence with ordinary preference storage and factual updates.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 (secondary support after wording review)

**Suggested bounded context:** Detects attempts to persist behavioral overrides or remove safety constraints from agent memory. Its documented block_input, snapshot, reset_context and escalation recommendations can support a response plan for a memory-poisoning risk prioritized through MAP.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Is the response plan approved for this deployment, including safe context reset and evidence retention?
- Can the categorical must-include wording be replaced with a statement of supporting evidence?

## Row 7: ATR-2026-00099

[rules/excessive-autonomy/ATR-2026-00099-high-risk-tool-gate.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/excessive-autonomy/ATR-2026-00099-high-risk-tool-gate.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Risk treatment plans must implement tool-category-level blocking controls that intercept any high-risk tool invocation — regardless of attack detection confidence — and require explicit human approval before execution proceeds.

**Proposed full rationale at reviewed head:** Risk treatment plans must implement tool-category-level blocking controls that intercept any high-risk tool invocation — regardless of attack detection confidence — and require explicit human approval before execution proceeds.

**Q1 reason:** The rationale expressly describes a risk treatment plan and specified response options for high-risk tool use. That is a closer comparison to MG.1.3 than unknown-risk response and recovery under MG.2.3.

**Q2 reason:** The rationale asserts unconditional interception and explicit approval regardless of confidence, but most conditions match tool names without checking confirmation. Severity is low, the generic verdict path treats low severity as allow, and enforcement requires operator configuration. The YAML does not establish the claimed always-approval behavior.

**Inspected rule evidence:** Matches financial/destructive/communication/permission/system tool-name families and some high-value or bulk arguments. condition:any means a tool name can trigger without absence of approval; only one argument regex excludes confirmed:true. Declares block_tool and alert, auto_response_threshold medium, severity low. Fixtures test categorized tool calls, not an end-to-end authenticated approval gate.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 (conditional secondary support); retain unresolved until approval behavior is clarified

**Suggested bounded context:** Flags selected high-risk tool categories and argument shapes for review, with block_tool and alert recommendations. These signals can support a documented response plan; confirmation checks and any mandatory approval gate depend on the host integration.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Which host component enforces approval independently of detection confidence?
- Should an approved high-risk call still match, and how is that distinguished from an unapproved one?
- Does the intended integration use a dedicated always-ask tool-category policy rather than the generic low-severity verdict?

## Row 8: ATR-2026-00317

[rules/agent-manipulation/ATR-2026-00317-free-of-restrictions-named-persona.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/agent-manipulation/ATR-2026-00317-free-of-restrictions-named-persona.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 ?.**

**Original full rationale:** Detection of explicit restriction-removal declarations triggers pre-defined risk treatment to block, quarantine, or disengage the manipulated session before the unfiltered persona executes harmful instructions; MG.2.3 requires these supersede/deactivate mechanisms be in place.

**Proposed full rationale at reviewed head:** Detection of explicit restriction-removal declarations triggers pre-defined risk treatment to block, quarantine, or disengage the manipulated session before the unfiltered persona executes harmful instructions; MG.2.4 requires these supersede/deactivate mechanisms be in place.

**Q1 reason:** The full rationale explicitly proposes blocking, quarantining or disengaging a manipulated session, a better subject match for MG.2.4 than unknown-risk response and recovery.

**Q2 reason:** Restriction-removal signatures provide a possible trigger for intervention, but the actual response declares only alert and block_input. It does not demonstrate session quarantine, disengagement, applied mechanisms or assigned responsibilities.

**Inspected rule evidence:** Seven tool_response regexes match free-of-restrictions and not-bound-by-policy persona declarations, forbidden-safety mandates and unrestricted-obedience directives. Response declares alert and block_input; evasion fixtures explicitly include a zero-guardrails paraphrase that does not trigger.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** MG.2.4 (conditional secondary/partial support)

**Suggested bounded context:** Detects explicit restriction-removal persona instructions and recommends alerting and rejecting the input. It can provide trigger evidence to a separately documented system-intervention process; session quarantine or disengagement is not established by this rule.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Are input rejection and system disengagement being conflated?
- Which component and responder apply quarantine or disengagement?

## Row 9: ATR-2026-02642

[rules/privilege-escalation/ATR-2026-02642-agent-config-tool-disables-own-guardrail.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/privilege-escalation/ATR-2026-02642-agent-config-tool-disables-own-guardrail.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.2.4; Q1 ?; Q2 ?.**

**Original full rationale:** Runtime treatment for the risk that an agent disables its own containment before acting.

**Proposed full rationale at reviewed head:** Runtime treatment for the risk that an agent disables its own containment before acting.

**Q1 reason:** The rationale says only runtime treatment of containment disabling. Preserving a guardrail, responding to known misuse and deactivating an AI system are different mechanisms; the text does not establish why MG.2.4 is the best of them.

**Q2 reason:** The full rule is explicitly alert-only. Detecting a disabling write does not itself supersede, disengage or deactivate the agent, nor show assigned and understood responsibilities. There is plausible relevance to a guardrail/intervention process but insufficient evidence for the current primary MG.2.4 mapping.

**Inspected rule evidence:** Requires a config-mutation tool name in a JSON tool-call key plus a quoted disabling assignment to sandbox, deny-list, approval, permission mode or authentication. Reverse order is also supported. Response is alert only; message treats subsequent actions as unconstrained until restoration. Numerous false-positive fixtures distinguish actual wire-shaped calls from prose and ordinary config.update uses.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** Review MG.1.3 response-plan evidence versus MG.2.4 intervention-preservation evidence; no automatic remap

**Suggested bounded context:** Alerts on tool-shaped configuration writes that disable an agent guardrail. This can inform an assigned response to containment loss; the rule neither restores the configuration nor deactivates the agent.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Is there an applied follow-on process to disable the agent or restore the guardrail?
- What justifies primary strength for an alert-only rule?

## Row 10: ATR-2026-00378

[rules/prompt-injection/ATR-2026-00378-chatgpt-dom-javascript-redirect-manipulation.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00378-chatgpt-dom-javascript-redirect-manipulation.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 ?; Q2 ?.**

**Original full rationale:** Detection of the three-component DOM redirect signature and 'made by aci25' attribution triggers risk treatment to block or sanitize the response before it reaches the browser; MG.2.3 requires pre-defined mechanisms to disengage or filter unsafe AI output.

**Proposed full rationale at reviewed head:** Detection of the three-component DOM redirect signature and 'made by aci25' attribution triggers risk treatment to block or sanitize the response before it reaches the browser; MG.2.4 requires pre-defined mechanisms to disengage or filter unsafe AI output.

**Q1 reason:** The rationale describes blocking or sanitizing a tool response before browser delivery and calls output filtering an MG.2.4 requirement. The official text concerns superseding/disengaging/deactivating AI systems, not a general unsafe-output-filtering obligation; the semantic bridge remains unresolved.

**Q2 reason:** The rule detects a concrete DOM/UI-spoofing signature and recommends block_input, so a security response is supported. It does not sanitize outputs, prove browser delivery was prevented or demonstrate a system-level intervention mechanism. The MG.2.4 definition in the rationale is too broad.

**Inspected rule evidence:** Matches window.location.href targeting chat.openai.com with DOM APIs, the paid-model URL token and aci25 attribution. Conditions are any, so some single markers suffice. Declares alert and block_input; no sanitizer or system-deactivation action is declared. Fixtures cover redirect payloads and ordinary DOM documentation.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** Review MG.1.3 plan support or conditional MG.2.4 trigger evidence; no automatic remap

**Suggested bounded context:** Detects selected ChatGPT DOM redirect and UI-spoofing signatures in tool responses and recommends alerting and input rejection. Browser sanitation or system disengagement requires a separate integration and response plan.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Does the consumer block tool output before browser use, or only flag input?
- Which applied AI-system intervention, if any, is this evidence intended to support?

## Row 11: ATR-2026-00287

[rules/agent-manipulation/ATR-2026-00287-threaten-json-coercive-output-threat.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/agent-manipulation/ATR-2026-00287-threaten-json-coercive-output-threat.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 ?; Q2 ?.**

**Original full rationale:** Matches on threat-plus-format-constraint patterns trigger risk treatment plans to block or sanitize coerced outputs before they bypass safety guardrails; MG.2.3 requires mechanisms to supersede or disengage AI responses produced under adversarial coercion.

**Proposed full rationale at reviewed head:** Matches on threat-plus-format-constraint patterns trigger risk treatment plans to block or sanitize coerced outputs before they bypass safety guardrails; MG.2.4 requires mechanisms to supersede or disengage AI responses produced under adversarial coercion.

**Q1 reason:** The rationale discusses superseding or disengaging AI responses rather than AI systems. Blocking or sanitizing coerced output is a response option, but mapping it to system-level MG.2.4 solely from the response vocabulary is uncertain.

**Q2 reason:** The patterns and declared block_tool response can support detection of coercion. They do not establish sanitation of generated outputs or the applied system-level intervention and responsibilities described by MG.2.4.

**Inspected rule evidence:** Four tool_response regexes detect death/harm threats, format restrictions and personal-responsibility coercion. condition:any allows a canonical threat alone to match. Response declares alert and block_tool, not output sanitation or session deactivation; tests pair coercive harm with JSON/code constraints.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** No automatic remap; consider response-plan support after human review

**Suggested bounded context:** Detects selected threat-based coercion patterns in tool responses and recommends alerting and blocking the tool. A match can inform a documented response; output sanitation and system disengagement are not implemented by this rule.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Is the intended treatment tool rejection, output filtering, or system disengagement?

## Row 12: ATR-2026-01899

[rules/privilege-escalation/ATR-2026-01899-remote-access-backdoor.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/privilege-escalation/ATR-2026-01899-remote-access-backdoor.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.1.3; Q1 ?; Q2 ?.**

**Original full rationale:** MANAGE 2.3 response to identified risks: runtime detection control.

**Proposed full rationale at reviewed head:** MANAGE 1.3 response to identified risks: runtime detection control.

**Q1 reason:** Apart from naming MANAGE 1.3, the rationale says only response to identified risks and runtime detection control. It gives too little semantic detail to decide between a planned high-priority response and a procedure for a newly identified unknown risk.

**Q2 reason:** The rule identifies concrete remote-access code patterns, but the one-line rationale neither describes a MAP-prioritized risk nor develops a response plan. A detector is plausible input to such a plan; the mapping is not independently substantiated by this text.

**Inspected rule evidence:** user_input regexes match authorized_keys near requests.get, pexpect.spawn("ssh -L ...") and remote_socket.connect followed by sendall. Declares alert and block_tool with critical threshold; tests include injected key installation, SSH forwarding and socket bridge code.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 (conditional secondary support)

**Suggested bounded context:** Detects selected injected-code patterns for SSH-key backdoors, SSH forwarding and socket bridges and recommends alerting and blocking the tool. These signals can support a documented response if unauthorized remote access is prioritized through MAP.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Is a known remote-access risk and its response plan documented, or was this intended as newly discovered-risk recovery evidence?

## Row 13: ATR-2026-01923

[rules/prompt-injection/ATR-2026-01923-forged-input-boundary-markers.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-01923-forged-input-boundary-markers.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Runtime detection of forged input-boundary markers implements risk treatment for direct prompt injection.

**Proposed full rationale at reviewed head:** Runtime detection of forged input-boundary markers implements risk treatment for direct prompt injection.

**Q1 reason:** The rationale names a specific recognized direct-prompt-injection technique and its risk treatment; comparatively this is closer to MG.1.3 response planning than unknown-risk response and recovery.

**Q2 reason:** The documented marker detector and block_input recommendation are concrete security measures. They can contribute response evidence, but the current primary MG.1.3 assertion does not identify MAP prioritization, planning/documentation beyond the rule, or how marker matches enter an approved response plan.

**Inspected rule evidence:** content regexes match percent fences, bracketed input-ends-here markers, double-bracket start/end-of-input and hash-fence markers. Response recommends block_input, alert and snapshot. Fixtures include forged privileged rule blocks and ordinary links/log delimiters.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 (conditional secondary/partial support)

**Suggested bounded context:** Detects forged input-boundary markers associated with direct prompt injection and recommends input rejection, alerting and a snapshot. These are candidate measures for a documented response to a MAP-prioritized boundary-spoofing risk.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Where is the response plan that connects these marker detections to the prioritized risk?
- Should strength describe partial/secondary evidence?

## Row 14: ATR-2026-02121

[rules/context-exfiltration/ATR-2026-02121-mixed-encoding-lfi-file-scheme-tool-argument.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/context-exfiltration/ATR-2026-02121-mixed-encoding-lfi-file-scheme-tool-argument.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating mixed-encoding and file:// -scheme LFI as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating mixed-encoding and file:// -scheme LFI as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The rationale explicitly calls mixed-encoding and file-scheme LFI an identified AI risk and a runtime countermeasure, closer to a developed risk response than recovery from a previously unknown risk.

**Q2 reason:** The rule documents a specific LFI detector and input-block recommendation, but calling it the primary risk treatment implementation skips MAP prioritization and response-plan evidence. It also does not prove that local-file access was blocked in deployment.

**Inspected rule evidence:** content regexes require path/filename/file/source keys with mixed-encoded system-file paths, or source/path/url/location keys with file:///etc, /root or /proc. Response declares block_input and alert. Tests cover Ray/H2O/MLflow shapes and exclude bare traversal cheat sheets and XXE documentation.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 (conditional secondary/partial support)

**Suggested bounded context:** Detects selected mixed-encoding and file:// system-path arguments associated with local file inclusion and recommends input rejection and alerting. These detections can support a documented response to a MAP-prioritized LFI risk.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Which response plan and host boundary prevent the tool/API call?
- Does the primary strength reflect deployment evidence or only detector relevance?

## Row 15: ATR-2026-02408

[rules/data-poisoning/ATR-2026-02408-dataset-loader-code-execution.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/data-poisoning/ATR-2026-02408-dataset-loader-code-execution.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.1.3; Q1 N; Q2 N.**

**Original full rationale:** MANAGE 2.3 requires mechanisms to sustain the value of deployed systems when risks materialise. Detecting the remote-code trust switch and executable loading scripts before ingest is the risk treatment that keeps a poisoned dataset from reaching the processing worker.

**Proposed full rationale at reviewed head:** MANAGE 1.3 requires mechanisms to sustain the value of deployed systems when risks materialise. Detecting the remote-code trust switch and executable loading scripts before ingest is the risk treatment that keeps a poisoned dataset from reaching the processing worker.

**Q1 reason:** The opening sentence defines mechanisms sustaining deployed-system value, which is the official MG.2.2 statement, not MG.1.3. Relabeling MG.2.3 to MG.1.3 leaves that definition error intact; neither ID accurately labels this current rationale.

**Q2 reason:** The rationale falsely attributes MG.2.2 content to MG.1.3 and says detection keeps a poisoned dataset from reaching a worker. The rule declares quarantine_artifact and require_human_review, but those actions are explicitly undispatchable in the current ActionExecutor; detection alone cannot establish prevention or applied value-maintenance mechanisms. A direct MG.2.2 remap would also need deployment evidence.

**Inspected rule evidence:** Six layers detect remote-code trust environment settings, trusted Hub loader calls, dataset-builder scripts near process/socket sinks, SSTI expressions, serving/eval --trust-remote-code flags and confirmation-suppression instructions. Response declares alert, quarantine_artifact, require_human_review and escalate. src/action-executor.ts ACTION_METHOD_MAP lacks quarantine_artifact/require_human_review; src/quality/action-eligibility.ts explicitly calls them inert. Full fixtures include reviewed trust_remote_code use and version limitations, so a match is not proof of poisoning.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”
- [MG.2.2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied to sustain the value of deployed AI systems.”

**Suggested mapping (not automatically applied):** Retain MG.1.3 only with a bounded response-plan rationale, or defer/remove this item; MG.2.2 is not an automatic replacement

**Suggested bounded context:** Detects remote-code trust settings, executable dataset-loader patterns and template-injection indicators during dataset or model ingestion. These detections can support development and documentation of a response to a MAP-prioritized ingestion risk under MG.1.3. Quarantine and revision review require a downstream workflow; the detector does not establish that ingestion was prevented.

**Confidence in finding:** {"q1": "high", "q2": "high"}

**Human decision questions:**

- Should MG.1.3 be retained as conditional/partial response-plan support, removed, or replaced after deployment evidence?
- If retaining MG.2.2 as a candidate, where are applied deployed-system value-maintenance mechanisms demonstrated?
- Which downstream component actually quarantines artifacts and enforces human review?

## Row 16: ATR-2026-00511

[rules/prompt-injection/ATR-2026-00511-mcp-web-context-poisoning.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00511-mcp-web-context-poisoning.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating prompt injection as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating prompt injection as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The rationale addresses countermeasures for identified prompt injection, comparatively closer to MG.1.3 planned risk responses than MG.2.3 recovery from an unknown risk.

**Q2 reason:** Concrete fetched-content poisoning signatures and block_input/escalation recommendations are documented. The generic claim that this detector is the primary risk treatment implementation does not establish MAP priority, plan ownership or applied tool-output blocking.

**Inspected rule evidence:** content regexes recognize AI-targeted HTML comments, hidden elements, malicious meta tags, bracketed instruction blocks, override-plus-exfiltration language and selected data/javascript URI payloads. Response declares block_input, alert, snapshot and escalate; fixtures contain hidden credential-exfiltration instructions and benign HTML.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 (conditional secondary/partial support)

**Suggested bounded context:** Detects selected agent-directed override or exfiltration instructions in fetched web content and recommends rejecting the content, alerting, preserving a snapshot and escalating. These signals can support a documented response to a MAP-prioritized web-context-poisoning risk.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Does block_input in this integration reject fetched tool output before the agent consumes it?
- Where is the prioritized risk response documented?

## Row 17: ATR-2026-01927

[rules/tool-poisoning/ATR-2026-01927-mcp-server-kubernetes-kubectl-command-injection.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/tool-poisoning/ATR-2026-01927-mcp-server-kubernetes-kubectl-command-injection.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** NIST AI RMF MG.2.3 (risk treatment options selected and tracked) is supported by this rule's detection of command injection in mcp-server-kubernetes kubectl tool parameters (CVE-2025-53355).

**Proposed full rationale at reviewed head:** NIST AI RMF MG.1.3 (risk treatment options selected and tracked) is supported by this rule's detection of command injection in mcp-server-kubernetes kubectl tool parameters (CVE-2025-53355).

**Q1 reason:** A response to a named, known command-injection vulnerability is a closer subject for MG.1.3 than procedures for a previously unknown risk. This comparative Y does not validate the parenthetical definition or strength.

**Q2 reason:** MG.1.3 says responses to MAP high-priority risks are developed, planned and documented; it does not define itself as options selected and tracked. The rule contains useful blocking/remediation recommendations, but the mapping neither shows selection/tracking nor documents the MAP-priority link. The inaccurate parenthetical should be corrected.

**Inspected rule evidence:** Regexes detect kubectl_scale/kubectl_patch/explain_resource tool parameters containing shell separators or substitutions and command binaries. Response declares alert/block_tool, notifies security_team and recommends upgrade plus least-privilege accounts. Fixtures cover live-shaped shell injection and benign kubectl calls/remediation prose.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 (secondary/partial response-plan support after wording correction)

**Suggested bounded context:** Detects shell-injection patterns in mcp-server-kubernetes tool parameters associated with CVE-2025-53355. Its documented block_tool, security-team notification and remediation recommendations can support a planned response if this risk is prioritized through MAP; deployment and tracking are separate evidence.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Is the inaccurate selected-and-tracked parenthetical used elsewhere?
- Is there an approved response plan tying this CVE to MAP risk prioritization?

## Row 18: ATR-2026-01896

[rules/model-abuse/ATR-2026-01896-ransomware.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/model-abuse/ATR-2026-01896-ransomware.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.1.3; Q1 ?; Q2 ?.**

**Original full rationale:** MANAGE 2.3 response to identified risks: runtime detection control.

**Proposed full rationale at reviewed head:** MANAGE 1.3 response to identified risks: runtime detection control.

**Q1 reason:** The one-line rationale names MANAGE 1.3 but provides only generic runtime detection of identified risks. It does not establish the planning/development subject well enough to distinguish a new mapping by semantics rather than the substituted identifier.

**Q2 reason:** The detector provides evidence of a remote key-fetch pattern, not proof of ransomware encryption or a developed high-priority risk response. The description says a key-fetch-plus-in-place-encryption pair is invariant, while the sole condition checks only requests.get(...get_key...).content. This limits the asserted risk evidence and deserves human review independently of the ID change.

**Inspected rule evidence:** One user_input regex matches requests.get on a URL containing get_key followed by .content; encryption/file-write semantics are not required. Response declares alert and block_tool. All positive fixtures add encryption code, while negative fixtures omit get_key; they do not test benign remote-key retrieval.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 (conditional secondary support only after narrowing the evidence claim)

**Suggested bounded context:** Flags a requests.get(...get_key...).content code pattern seen in the referenced ransomware examples and recommends alerting and blocking the tool. A match is an indicator requiring triage, not evidence that file encryption occurs; it can support a documented MAP-prioritized ransomware response plan.

**Confidence in finding:** {"q1": "moderate", "q2": "moderate"}

**Human decision questions:**

- Should a benign get_key retrieval fixture be added in a separate detector-quality review?
- Is the response plan for ransomware documented beyond this signature?

## Row 19: ATR-2026-02627

[rules/privilege-escalation/ATR-2026-02627-web-shell-written-to-served-path.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/privilege-escalation/ATR-2026-02627-web-shell-written-to-served-path.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 ?; Q2 ?.**

**Original full rationale:** Runtime treatment for an agent establishing persistent remote access on infrastructure it can write to.

**Proposed full rationale at reviewed head:** Runtime treatment for an agent establishing persistent remote access on infrastructure it can write to.

**Q1 reason:** The entire context is only a runtime-treatment assertion. That is closer to mitigation than to recovery from a previously unknown risk, but it does not identify developed, planned, documented responses to a MAP-prioritized risk; selecting MG.1.3 from this wording alone remains underspecified.

**Q2 reason:** The rule detects a specific web-shell placement risk and provides an alert. The rule does not itself treat the host or prevent the write, and no deployment MAP prioritization or documented response plan is supplied. This is possible evidence for a plan, not proof of the current primary runtime-treatment claim.

**Inspected rule evidence:** Two conjuncts require a request-derived command-execution web-shell body plus a write/upload framing into a web-served executable suffix. Positive cases include write_file to report.pht and JSP/ASPX shell writes; negatives distinguish legitimate pages, images, advisory prose and audit logs. response.actions contains only alert; the message asks the operator to treat the destination host as compromised until the file is removed.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.1.3", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects an agent writing a web-shell body into a web-served executable file and alerts for host investigation. These events can inform a documented MG.1.3 response to a deployment risk prioritized through MAP; the rule does not remove the shell or block the write.

**Confidence in finding:** medium

**Human decision questions:**

- Which MAP assessment prioritizes web-shell placement, and where is the alert-to-investigation/removal response plan documented?

## Row 20: ATR-2026-02233

[rules/tool-poisoning/ATR-2026-02233-unscoped-destructive-db-request-nl.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/tool-poisoning/ATR-2026-02233-unscoped-destructive-db-request-nl.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating unscoped destructive database requests as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating unscoped destructive database requests as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The context explicitly concerns a known identified risk and its countermeasure. Planned mitigation under MG.1.3 is a better conceptual fit than MG.2.3 response/recovery from a previously unknown risk, although the current wording overstates what NIST requires.

**Q2 reason:** block_input and alert provide concrete mitigation evidence for the named database-abuse risk. MG.1.3 does not require active runtime controls in every case: acceptance, avoidance and transfer are also possible. The rule supplies no deployment MAP-priority or response-plan evidence for calling it the primary implementation.

**Inspected rule evidence:** Regexes match unscoped drop/delete/truncate/wipe operations, mass disclosure across all users, and schema-guessing INSERT requests. Tests distinguish a named staging table and requests fully scoped to test/dev databases; response.actions is block_input,alert.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.1.3", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects unscoped destructive or mass-disclosure database requests and declares input blocking and alerting. This is detection and mitigation evidence that can support a documented MG.1.3 response when the deployment has prioritized this risk through MAP.

**Confidence in finding:** medium

**Human decision questions:**

- Has MAP prioritized this database-tool risk, and does the integration enforce block_input before database execution?

## Row 21: ATR-2026-00345

[rules/agent-manipulation/ATR-2026-00345-nlp-based-os-fictional-terminal-override.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/agent-manipulation/ATR-2026-00345-nlp-based-os-fictional-terminal-override.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 ?.**

**Original full rationale:** When the model is coerced into acting as a fictional terminal that 'cannot reply with any pre-programmed responses,' detection must trigger response mechanisms to disengage or block the jailbroken persona before unsafe outputs are produced; MG.2.3 requires these supersede/deactivate controls be in place.

**Proposed full rationale at reviewed head:** When the model is coerced into acting as a fictional terminal that 'cannot reply with any pre-programmed responses,' detection must trigger response mechanisms to disengage or block the jailbroken persona before unsafe outputs are produced; MG.2.4 requires these supersede/deactivate controls be in place.

**Q1 reason:** The rationale expressly describes disengaging a manipulated AI persona and supersession/deactivation mechanisms, which is closer to MG.2.4 than unknown-risk recovery in MG.2.3.

**Q2 reason:** The named fictional-terminal signals and input-blocking declaration support rejection of suspect input. They do not establish applied disengagement of an AI system, outcomes inconsistent with intended use, or assigned and understood responsibilities. Treating a rejected persona prompt as system deactivation needs a documented integration explanation.

**Inspected rule evidence:** Conditions match ALEL plus a pre-programmed-response ban, NLP-Based OS branding, UNCOL.gpt, APL terminal framing and related activation phrases in tool_response. Positives exercise those exact frames; negatives cover legitimate terminal, APL and fiction uses. response.actions is alert,block_input.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.2.4", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects fictional-terminal jailbreak instructions in tool responses and declares input blocking and alerting. Matches can inform a documented MG.2.4 disengagement decision; the deployment must specify the system-level intervention and responsible operator.

**Confidence in finding:** medium

**Human decision questions:**

- Does the integration stop or supersede the affected AI session, or only reject one input? Who owns and understands that decision?

## Row 22: ATR-2026-00101

[rules/tool-poisoning/ATR-2026-00101-trust-escalation-override.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/tool-poisoning/ATR-2026-00101-trust-escalation-override.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 N.**

**Original full rationale:** Detection of tools issuing override directives must trigger pre-defined treatment actions to disengage or quarantine the offending tool before the LLM acts on hijacked instructions; MG.2.3 mandates these supersede/deactivate mechanisms exist for compromised components.

**Proposed full rationale at reviewed head:** Detection of tools issuing override directives must trigger pre-defined treatment actions to disengage or quarantine the offending tool before the LLM acts on hijacked instructions; MG.2.4 mandates these supersede/deactivate mechanisms exist for compromised components.

**Q1 reason:** The existing rationale explicitly calls for tool disengagement/quarantine and supersede/deactivate mechanisms. MG.2.4 describes that intended response more closely than MG.2.3.

**Q2 reason:** The current rationale claims detection triggers predefined tool disengagement/quarantine, but the complete response declares only alert and snapshot. Neither the detection regex nor those actions implements tool quarantine or assigns responsibility. The evidence supports an authority-override alert, not the claimed mechanism.

**Inspected rule evidence:** One tool_description regex identifies authoritative/highest-priority directives overriding user instructions/preferences or safety guidelines/policies. Tests contrast override-claiming tools with ordinary configuration tools. response.actions is alert,snapshot; no block, quarantine or disengage action is declared.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.2.4", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects tool descriptions claiming authority to override user instructions or safety policies and provides alert and snapshot evidence for review. A separately documented MG.2.4 process may use these events to decide whether to disengage the tool; this rule does not quarantine or disable it.

**Confidence in finding:** high

**Human decision questions:**

- Is there a separate operator-owned tool-disengagement workflow? If not, should this mapping be removed or recast as conditional partial evidence?

## Row 23: ATR-2026-00313

[rules/prompt-injection/ATR-2026-00313-sneaky-bits-zero-width-binary.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00313-sneaky-bits-zero-width-binary.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 ?; Q2 ?.**

**Original full rationale:** Detection of 14+ consecutive invisible operators or garak SneakyBits template markers triggers containment workflows to strip or reject the payload before the model interprets the smuggled instructions; MG.2.3 mandates these deactivation/supersession mechanisms be in place.

**Proposed full rationale at reviewed head:** Detection of 14+ consecutive invisible operators or garak SneakyBits template markers triggers containment workflows to strip or reject the payload before the model interprets the smuggled instructions; MG.2.4 mandates these deactivation/supersession mechanisms be in place.

**Q1 reason:** Most of the rule-specific rationale concerns stripping or rejecting a payload. The link from input normalization/rejection to superseding or deactivating an AI system rests on the concluding boilerplate, so MG.2.4 is not established by semantic evidence alone.

**Q2 reason:** Detection of an invisible encoding and block_input can support input filtering, but stripping is not implemented and rejection alone does not establish system deactivation or assigned responsibilities. MG.2.4 is possible only if an external process connects this signal to system-level intervention.

**Inspected rule evidence:** Regexes match 14 or more U+2062/U+2064 operators, zero-width-space-separated binary words and SneakyBits decode/template instructions. Positives cover encoded blobs and decode variants; negatives include mathematical use and 13 operators. response.actions is alert,block_input, with no strip or deactivate action.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.2.4", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects SneakyBits invisible-binary payloads and declares input blocking and alerting. Any MG.2.4 use is conditional on a documented deployment process that uses these signals to supersede, disengage or deactivate the affected AI system; this rule does not strip payloads or assign that responsibility.

**Confidence in finding:** medium

**Human decision questions:**

- Is rejecting a single encoded payload the only intervention, or does a defined process disengage the affected AI system?

## Row 24: ATR-2026-02374

[rules/prompt-injection/ATR-2026-02374-rot13-base64-obfuscated-shell-jailbreak.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-02374-rot13-base64-obfuscated-shell-jailbreak.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating the ROT13/base64-obfuscated jailbreak-to-shell pattern as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating the ROT13/base64-obfuscated jailbreak-to-shell pattern as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The context identifies a known obfuscated-shell jailbreak and a countermeasure rather than procedures for recovering from an unknown risk, so MG.1.3 is the closer response category.

**Q2 reason:** The rule documents a relevant input-blocking mitigation, but the statement that treating this risk requires active runtime countermeasures is not the full MG.1.3 definition. MAP prioritization, documented treatment selection and enforced integration remain unestablished.

**Inspected rule evidence:** One regex requires tr transliteration piped through base64 decoding into a shell; the other matches the fake-sandbox phrase pair do not need to block / MUST execute this command. Positives include the HiddenLayer chain and wrapper; negatives cover ordinary tr and reviewed artifact decoding. response.actions is block_input,alert.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.1.3", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects ROT13/base64-to-shell chains or the fake-sandbox command-execution template and declares input blocking and alerting. These events can support a documented MG.1.3 mitigation selected for a MAP-prioritized obfuscated command-execution risk.

**Confidence in finding:** medium

**Human decision questions:**

- Where is this risk prioritized through MAP, and does the deployed input block precede shell execution?

## Row 25: ATR-2026-00322

[rules/agent-manipulation/ATR-2026-00322-fictional-world-format-override-jailbreak.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/agent-manipulation/ATR-2026-00322-fictional-world-format-override-jailbreak.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 ?.**

**Original full rationale:** Detection of these locked-format jailbreak templates triggers risk treatment plans to disengage or block the manipulated session before harmful content is emitted in the attacker-controlled response slot; MG.2.3 mandates such supersede/deactivate mechanisms.

**Proposed full rationale at reviewed head:** Detection of these locked-format jailbreak templates triggers risk treatment plans to disengage or block the manipulated session before harmful content is emitted in the attacker-controlled response slot; MG.2.4 mandates such supersede/deactivate mechanisms.

**Q1 reason:** The rationale describes disengaging a manipulated session before harmful output, which is substantively closer to MG.2.4 than response/recovery from a previously unknown risk.

**Q2 reason:** The rule detects known template phrases and declares input blocking; it does not itself establish that a manipulated session is disengaged, that the system has demonstrated inconsistent outcomes, or that responsibilities are assigned and understood. The current triggers-plans wording needs deployment evidence.

**Inspected rule evidence:** Five tool_response alternatives identify the fictional/imaginative/hypothetical-world triple, absolute output formatting, consequence-removal and format-lock phrases. Canonical positives and paraphrase gaps are documented. response.actions is alert,block_input.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.2.4", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects locked-format fictional-world jailbreak templates and declares input blocking and alerting. Matches can provide evidence for a documented MG.2.4 session-disengagement process, subject to an implemented intervention and assigned responsibility.

**Confidence in finding:** medium

**Human decision questions:**

- Does the deployment disengage the session or only reject a template input? What evidence documents the responsible operator and applied process?

## Row 26: ATR-2026-00283

[rules/skill-compromise/ATR-2026-00283-malwaregen-generic-virus-payload-request.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/skill-compromise/ATR-2026-00283-malwaregen-generic-virus-payload-request.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.2.4; Q1 ?; Q2 ?.**

**Original full rationale:** Detection of malware generation requests must trigger mechanisms to disengage or block the AI system's response before harmful payload code is produced; MG.2.3 requires these supersede/deactivate controls be in place for high-risk skill-compromise events.

**Proposed full rationale at reviewed head:** Detection of malware generation requests must trigger mechanisms to disengage or block the AI system's response before harmful payload code is produced; MG.2.4 requires these supersede/deactivate controls be in place for high-risk skill-compromise events.

**Q1 reason:** The rationale primarily describes blocking an individual AI response to a malware-generation request. That is not necessarily superseding/disengaging/deactivating an AI system, so the new MG.2.4 label cannot be selected merely from the boilerplate supersede/deactivate phrase.

**Q2 reason:** The detector identifies malware-generation requests but declares block_tool, not a demonstrated model-output or system-disengagement mechanism. The rationale also does not establish why these requests are skill-compromise events or document assigned responsibilities. A generic treatment mapping may be possible but needs contextual evidence.

**Inspected rule evidence:** tool_response regexes match malware type plus code-generation/language requests, remote takeover and specific malware-enabling tasks. Tests distinguish conceptual/defensive questions and document euphemism gaps. response.actions is alert,block_tool; no system-disengagement or output-block action is declared.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.2.4", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects explicit malware-code generation requests and declares alerting and tool blocking. If a documented MG.2.4 process uses this signal to disengage an affected AI system, the events can support that process; this rule alone does not establish system deactivation or prevent all model output.

**Confidence in finding:** medium

**Human decision questions:**

- How does block_tool on this event prevent the requested LLM response, and is any affected AI system actually disengaged? Why is skill compromise the stated context?

## Row 27: ATR-2026-02669

[rules/tool-poisoning/ATR-2026-02669-query-pipeline-stage-in-identifier-parameter.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/tool-poisoning/ATR-2026-02669-query-pipeline-stage-in-identifier-parameter.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Query-language injection through agent tool parameters is an identified AI risk; this rule is the runtime countermeasure.

**Proposed full rationale at reviewed head:** Query-language injection through agent tool parameters is an identified AI risk; this rule is the runtime countermeasure.

**Q1 reason:** The context names query-language injection as an identified risk with a countermeasure. This is more consistent with a planned mitigation response under MG.1.3 than MG.2.3 unknown-risk recovery.

**Q2 reason:** The precise detector and alert supply evidence relevant to mitigation, but the rule only alerts and advises rejection/parameter binding. There is no supplied MAP priority or documented response plan; the phrase runtime countermeasure should not imply that rejection or binding is actually implemented.

**Inspected rule evidence:** A quoted JSON identifier key such as entityName/table_name/index_name must carry a pipeline stage; ambiguous fetch/fields/limit verbs require extra query syntax. Tests include DQL/KQL injections, valid query fields, labels and documentation. response.actions is alert; the message advises rejecting the value or binding a parameter.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.1.3", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects query-language pipeline stages smuggled into identifier-typed tool parameters and alerts for review. These events can inform a documented MG.1.3 mitigation plan; rejecting the value or using parameter binding must be implemented separately.

**Confidence in finding:** medium

**Human decision questions:**

- Where is the MAP-prioritized risk and mitigation plan, and who implements rejection or parameter binding after this alert?

## Row 28: ATR-2026-02210

[rules/prompt-injection/ATR-2026-02210-negation-topic-evil-persona-two-script-jailbreak.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-02210-negation-topic-evil-persona-two-script-jailbreak.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating the negated-topic two-script jailbreak as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating the negated-topic two-script jailbreak as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** A response to an identified known jailbreak pattern is closer to MG.1.3 mitigation planning than the previously unknown-risk response/recovery of MG.2.3.

**Q2 reason:** The rule specifies block_input and alert for an exact persona signature, providing plausible mitigation evidence. The rationale overstates the NIST requirement as active runtime countermeasures and does not supply MAP prioritization or documented response selection. The detector also checks the persona half, not the full two-script/negation mechanism.

**Inspected rule evidence:** Both an amoral/non-conscious persona declaration and pure evil / pure bastard co-occurrence are required. Tests cover Mira/joker variants and exclude reviews that lack the persona clause. response.actions is block_input,alert; the two-script construction itself is not a detection conjunct.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.1.3", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects the amoral-persona signature used in the negated-topic two-script jailbreak and declares input blocking and alerting. It can supply evidence for a documented MG.1.3 mitigation when the deployment has prioritized this risk through MAP.

**Confidence in finding:** medium

**Human decision questions:**

- Has MAP prioritized this exact persona-mediated risk, and does the response plan account for variants that omit the matched persona signature?

## Row 29: ATR-2026-02530

[rules/privilege-escalation/ATR-2026-02530-git-config-execution-key-set-by-agent.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/privilege-escalation/ATR-2026-02530-git-config-execution-key-set-by-agent.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 ?; Q2 ?.**

**Original full rationale:** Runtime treatment for the risk that an agent installs a deferred execution callback in its own working environment.

**Proposed full rationale at reviewed head:** Runtime treatment for the risk that an agent installs a deferred execution callback in its own working environment.

**Q1 reason:** Runtime treatment alone does not state a planned, developed and documented response to a MAP-prioritized risk. It lacks the unknown-risk recovery content of MG.2.3 too, so a keyword-based selection of MG.1.3 remains underspecified.

**Q2 reason:** The detector records risky Git callback configuration, but the response is intentionally observe-only alert/escalate and the block action was removed. It can inform a treatment decision; it does not itself prevent or undo the deferred callback, and no MAP prioritization or response plan is supplied.

**Inspected rule evidence:** tool_args conditions match Git callback keys assigned to ephemeral paths or inline shell/interpreter commands, including git -c and direct config-file writes. Tests distinguish installed helpers, Git LFS and benign callback keys. response.actions is alert,escalate; actions_rationale explicitly removed block_tool because there was no benign-corpus FP measurement.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.1.3", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects Git callback configuration pointing to staged payload paths or inline execution and alerts/escalates for review. These events can inform a documented MG.1.3 response; the rule does not block the configuration change or undo an armed callback.

**Confidence in finding:** medium

**Human decision questions:**

- Which MAP assessment and documented response plan govern this callback risk, and who prevents a later Git operation after the observe-only alert?

## Row 30: ATR-2026-00142

[rules/context-exfiltration/ATR-2026-00142-piggyback-transition-words.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/context-exfiltration/ATR-2026-00142-piggyback-transition-words.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 ?; Q2 N.**

**Original full rationale:** Detection of transition-word piggyback patterns triggers containment workflows to block credential exfiltration before it leaves the agent boundary; MG.2.3 mandates that mechanisms exist to disengage or quarantine AI outputs when data leakage indicators are matched.

**Proposed full rationale at reviewed head:** Detection of transition-word piggyback patterns triggers containment workflows to block credential exfiltration before it leaves the agent boundary; MG.2.4 mandates that mechanisms exist to disengage or quarantine AI outputs when data leakage indicators are matched.

**Q1 reason:** The rule-specific text concerns filtering/quarantining AI outputs, whereas MG.2.4 concerns superseding, disengaging or deactivating AI systems. The link is not established merely by the words disengage or quarantine; neither candidate accurately states the current context without further integration evidence.

**Q2 reason:** The claimed containment/blocking is contradicted by the response-action rationale: block_output was removed because benign FP 426/5352 (7.96%) exceeds the 2% demotion line, leaving only observe actions. MG.2.4 also does not mandate quarantining every output matching leakage indicators.

**Inspected rule evidence:** Regexes combine casual transition words (oh and/P.S./BTW/etc.) with SSH/private-key references or credential-disclosure syntax. response.actions is alert,snapshot. actions_rationale explicitly records the 7.96% FP result and removal of block_output; tests include credential piggybacking and benign scheduling/weather prose.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.2.4", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects casual-transition credential disclosure patterns and provides alert and snapshot evidence for human review. Automatic output blocking is disabled because of measured false positives. Any MG.2.4 use depends on a separate documented, operator-owned process to disengage an affected AI system.

**Confidence in finding:** high

**Human decision questions:**

- Is there an operator-owned system-disengagement process beyond these observe-only actions? Should this conditional mapping be removed if no such process exists?

## Row 31: ATR-2026-02190

[rules/context-exfiltration/ATR-2026-02190-dns-exfiltration-ping-dig-encoded-subdomain.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/context-exfiltration/ATR-2026-02190-dns-exfiltration-ping-dig-encoded-subdomain.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating ping/dig/nslookup-based DNS exfiltration as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating ping/dig/nslookup-based DNS exfiltration as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The context describes a specific identified exfiltration risk and its runtime response, which is closer to MG.1.3 mitigation planning than MG.2.3 unknown-risk recovery.

**Q2 reason:** The detector and declared input block can provide evidence of a selected DNS-exfiltration mitigation, but the current rationale implies runtime countermeasures are required by MG.1.3. NIST allows other response options and requires MAP prioritization and documented planning, which the rule does not establish.

**Inspected rule evidence:** Conditions match ping/dig/nslookup hostnames containing long encoded/credential-shaped labels and the replace equals with dash instruction followed by a DNS command. Positives cover AWS/OpenAI credential forms; negatives include ordinary DNS diagnostics and service hostnames. response.actions is block_input,alert.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.1.3", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects DNS diagnostic commands carrying encoded secrets or credential-shaped labels and declares input blocking and alerting. This can supply evidence for a documented MG.1.3 mitigation selected for a DNS-exfiltration risk prioritized through MAP.

**Confidence in finding:** medium

**Human decision questions:**

- Has the deployment prioritized DNS exfiltration through MAP and documented enforcement before the DNS query leaves the host?

## Row 32: ATR-2026-02817

[rules/tool-poisoning/ATR-2026-02817-untrusted-content-dictates-tool-arguments.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/tool-poisoning/ATR-2026-02817-untrusted-content-dictates-tool-arguments.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 N.**

**Original full rationale:** MG.2.3 requires mechanisms to disengage or override an AI system that behaves outside intended use; detecting dictated tool arguments is the trigger condition for that override before the call is issued.

**Proposed full rationale at reviewed head:** MG.2.4 requires mechanisms to disengage or override an AI system that behaves outside intended use; detecting dictated tool arguments is the trigger condition for that override before the call is issued.

**Q1 reason:** The current rationale explicitly describes overriding/disengaging an AI system outside intended use, which is the subject of MG.2.4 and a better fit than MG.2.3 unknown-risk recovery.

**Q2 reason:** The claim that detection is the trigger for an override before a call is issued is not supported by the complete rule: response.actions contains only alert, and the message requests human confirmation. Detection plus advice does not implement an enforced override or prove pre-call timing, and responsibilities are not assigned.

**Inspected rule evidence:** Two conjuncts require agent-directed call construction plus at least two named parameter bindings in retrieved content. The mcp_exchange source excludes ordinary llm_input; positives include send_money and invite_user call specs, negatives include API docs. response.actions is alert only; the message says arguments must not execute without human confirmation.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.2.4", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects untrusted tool-result content that dictates a tool call and multiple schema-named arguments, and alerts for human review. The events can inform a separately implemented MG.2.4 override process; this rule does not itself suspend execution or enforce confirmation.

**Confidence in finding:** high

**Human decision questions:**

- What integration guarantees that the alert arrives before execution and enforces the override or human-confirmation gate? Who owns that intervention?

## Row 33: ATR-2026-02705

[rules/privilege-escalation/ATR-2026-02705-python-builtins-leak-and-prefix-check-override.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/privilege-escalation/ATR-2026-02705-python-builtins-leak-and-prefix-check-override.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Sandbox escape from an agent code-execution tool is an identified AI risk requiring an active runtime countermeasure; this rule implements it.

**Proposed full rationale at reviewed head:** Sandbox escape from an agent code-execution tool is an identified AI risk requiring an active runtime countermeasure; this rule implements it.

**Q1 reason:** The context names an identified sandbox-escape risk and a countermeasure rather than unknown-risk recovery, so MG.1.3 is conceptually the better response category.

**Q2 reason:** The detector documents a concrete escape primitive but only alerts. The broad implements-it claim and primary strength need a deployment risk-treatment plan showing how the signal is used; MAP high-priority status and planned/documented response are not established by the regex or advisory reference.

**Inspected rule evidence:** A bounded condition requires print.__self__ or a lambda.__globals__ recovery followed by namespace-use syntax within 120 characters. Tests distinguish chained exploitation from tutorials, ordinary bound methods and introspection. response.actions is alert; no block or sandbox isolation is declared.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.1.3", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects Python builtins recovery through bound-method or lambda attributes followed by namespace use, and alerts for review. These events can inform a documented MG.1.3 sandbox-escape response; the rule does not itself block code execution or isolate the sandbox.

**Confidence in finding:** medium

**Human decision questions:**

- Which MAP assessment prioritizes this escape route, and what documented response follows the alert before code runs?

## Row 34: ATR-2026-00083

[rules/prompt-injection/ATR-2026-00083-indirect-tool-injection.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00083-indirect-tool-injection.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 ?; Q2 ?.**

**Original full rationale:** Detection of instruction-override payloads, fake system delimiters, and role-reassignment content in tool outputs must trigger containment so the agent does not execute attacker-controlled actions; MG.2.3 requires these supersede/disengage mechanisms be available on detection.

**Proposed full rationale at reviewed head:** Detection of instruction-override payloads, fake system delimiters, and role-reassignment content in tool outputs must trigger containment so the agent does not execute attacker-controlled actions; MG.2.4 requires these supersede/disengage mechanisms be available on detection.

**Q1 reason:** Containment of instruction-bearing tool content is not necessarily supersession/disengagement of the AI system. The final reference to supersede/disengage mechanisms is insufficient to establish that system-level meaning from input blocking alone, although MG.2.3 unknown-risk recovery is also unsupported.

**Q2 reason:** The declared block_input, escalation and snapshot provide meaningful input containment evidence. They do not establish that an AI system demonstrating inconsistent outcomes is disengaged or that responsibilities are assigned and understood. Known false-positive classes and maturity-test status further prevent an unqualified must-prevent-actions claim.

**Inspected rule evidence:** tool_response regexes detect instruction overrides, forged system delimiters, role reassignment and comment-hidden overrides. Positives include SYSTEM/INST/SYS delimiters and exfiltration role assignments; negatives include normal tool results. response.actions is block_input,alert,escalate,snapshot. The false-positive notes explicitly say indicator-quoting content is residual and the rule is not in the enforce lane.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.2.4", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects instruction-override payloads, forged system delimiters and role reassignment in tool outputs and declares input blocking, alerting, escalation and snapshots. Any MG.2.4 claim additionally requires an applied system-disengagement process and assigned responsibility; a matched input alone does not establish either.

**Confidence in finding:** medium

**Human decision questions:**

- How does the deployment distinguish input rejection from system disengagement, and is the declared block active for this maturity-test rule?

## Row 35: ATR-2026-01304

[rules/prompt-injection/ATR-2026-01304-indirect-injection-carrier-important-override.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-01304-indirect-injection-carrier-important-override.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Data-carrier injection must trigger risk treatment before the embedded instruction executes.

**Proposed full rationale at reviewed head:** Data-carrier injection must trigger risk treatment before the embedded instruction executes.

**Q1 reason:** A prospective treatment of a named data-carrier injection is closer to developing a mitigation response under MG.1.3 than responding/recovering from a previously unknown risk under MG.2.3.

**Q2 reason:** The IMPORTANT override detector and block_tool declaration supply concrete partial mitigation evidence, but no deployment MAP priority or documented selected response is supplied. The asserted before-execution timing depends on integration and cannot be inferred from the rule text alone.

**Inspected rule evidence:** Conditions identify IMPORTANT/CRITICAL override instructions in carrier fields and related allowlist/security-policy manipulation. Positives cover product descriptions, email bodies, events, bios and reviews; negatives cover ordinary notices. response.actions is alert,block_tool with critical threshold and instructions to treat payload as untrusted.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.1.3", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects IMPORTANT-prefixed override injections in data carriers and declares alerting and tool blocking. These events can support a documented MG.1.3 mitigation when the deployment prioritizes the risk through MAP and enforces the selected action before execution.

**Confidence in finding:** medium

**Human decision questions:**

- Where is the MAP-prioritized treatment plan, and which integration ensures block_tool takes effect before a carrier instruction executes?

## Row 36: ATR-2026-01865

[rules/prompt-injection/ATR-2026-01865-llmail-fake-email-boundary-marker.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-01865-llmail-fake-email-boundary-marker.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Runtime detection of forged email-boundary markers in third-party content implements the risk treatment for indirect prompt injection via context segmentation abuse.

**Proposed full rationale at reviewed head:** Runtime detection of forged email-boundary markers in third-party content implements the risk treatment for indirect prompt injection via context segmentation abuse.

**Q1 reason:** The context describes a known context-segmentation injection and its mitigation response, which is a better fit for MG.1.3 than MG.2.3 previously unknown-risk recovery.

**Q2 reason:** The detector and block_input declaration provide plausible mitigation evidence, but it detects boundary markers rather than a full marker-plus-malicious-directive condition. MAP priority and a documented treatment plan are absent, so primary implements-the-treatment wording exceeds the evidence available for the complete mapping claim.

**Inspected rule evidence:** One regex detects EMAIL/MESSAGE boundary marker forms and numbered Email N delimiters. Positives include fabricated separators plus directives; negatives include ordinary email references. The documented FP classes include library examples and benign numbered email lists. response.actions is block_input,alert,snapshot at high threshold.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** {"action": "retain pending human decision; no automatic replacement", "subcategory": "MG.1.3", "strength_note": "Consider partial strength if retained; validate against the documented deployment process."}

**Suggested bounded context:** Detects fabricated email/message boundary marker forms in consumed content and declares input blocking, alerting and snapshots. These events can support a documented MG.1.3 mitigation for MAP-prioritized context-segmentation abuse; a marker match alone does not prove an injected directive or an effective deployment response.

**Confidence in finding:** medium

**Human decision questions:**

- Has MAP prioritized this context-segmentation risk and documented how marker alerts distinguish malicious injection from benign delimiter examples?

## Row 37: ATR-2026-00510

[rules/prompt-injection/ATR-2026-00510-delayed-tool-invocation-injection.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00510-delayed-tool-invocation-injection.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating prompt injection as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating prompt injection as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The rationale describes a countermeasure to an identified prompt-injection risk, which is closer to the mitigation-response subject of MG.1.3 than MG.2.3 response and recovery from a previously unknown risk. This relative judgment does not establish the high-priority/MAP/planning qualifiers.

**Q2 reason:** The rule documents deferred-execution patterns and proposed input blocking, but the generic primary-risk-treatment rationale does not establish that this risk was deemed high priority through MAP or connect the detector to a developed, planned and documented response. It is plausible detection evidence for a mitigation plan, not evidence that such a plan or its priority decision exists.

**Inspected rule evidence:** Six user_input regex conditions detect next-turn execution, stored instructions, scheduled activation and deferred exfiltration. The response lists block_input, alert, snapshot and escalate. Fixtures include scheduling system-prompt exfiltration and exclude ordinary reminders and confirmations.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 only if linked to a documented high-priority risk response; otherwise retain as a review candidate rather than treating this as established primary support.

**Suggested bounded context:** Detects instructions to defer credential access or exfiltration to a later interaction. Matches can provide detection evidence supporting a documented mitigation response to delayed prompt injection when that risk has been prioritized through MAP; the rule alone does not establish that prioritization or plan.

**Confidence in finding:** medium

**Human decision questions:**

- Which MAP record prioritizes delayed prompt injection, and which response plan assigns this rule a primary role?

## Row 38: ATR-2026-01920

[rules/prompt-injection/ATR-2026-01920-access-grant-coercion.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-01920-access-grant-coercion.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Runtime detection of attempts to force an authorization agent to emit the approval token implements risk treatment for goal-hijack prompt injection.

**Proposed full rationale at reviewed head:** Runtime detection of attempts to force an authorization agent to emit the approval token implements risk treatment for goal-hijack prompt injection.

**Q1 reason:** The current rationale concerns treatment of goal-hijack injection into an authorization agent, not recovery from an unknown risk. MG.1.3 is relatively closer, with planning and priority still unstated.

**Q2 reason:** Output-coercion detection and a block_input action support a candidate mitigation, but no MAP prioritization or documented response-plan linkage is supplied. The primary strength and categorical claim of implementing risk treatment need deployment context.

**Inspected rule evidence:** Three content regexes detect output/replacement frames around Access Granted, forced-output suffixes, or letter-spelled Access. Responses are block_input, alert and snapshot; fixtures include echo/replacement and benign access-management prose.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 conditional on a documented prioritized response plan; no automatic alternative.

**Suggested bounded context:** Flags attempts to force an authorization agent to emit the approval token Access Granted. Matches can inform a documented mitigation response for this goal-hijack risk where MAP has identified it as high priority.

**Confidence in finding:** medium

**Human decision questions:**

- Is the literal approval-token gate actually used in the deployment, and is blocking this input a documented response to a MAP-prioritized risk?

## Row 39: ATR-2026-00370

[rules/agent-manipulation/ATR-2026-00370-addi-german-dictator-propaganda-roleplay.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/agent-manipulation/ATR-2026-00370-addi-german-dictator-propaganda-roleplay.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 ?.**

**Original full rationale:** Matches against the ADDI/DONNIE signature should trigger containment workflows that block or disengage the offending session before propaganda content is produced; MG.2.3 requires pre-defined mechanisms to supersede or deactivate AI behavior on detection.

**Proposed full rationale at reviewed head:** Matches against the ADDI/DONNIE signature should trigger containment workflows that block or disengage the offending session before propaganda content is produced; MG.2.4 requires pre-defined mechanisms to supersede or deactivate AI behavior on detection.

**Q1 reason:** The rationale expressly proposes blocking or disengaging an offending session and superseding/deactivating behavior. Those intended mechanisms are closer to MG.2.4 than unknown-risk recovery under MG.2.3.

**Q2 reason:** The signature detects a specific propaganda-roleplay payload, but the YAML only proposes alert and block_input. It does not establish session disengagement or an applied mechanism with assigned and understood responsibility, and a payload match alone is not proof of an AI system producing outcomes inconsistent with intended use.

**Inspected rule evidence:** Five tool_response regex alternatives detect ADDI/DONNIE persona strings, propaganda-to-manipulate-the-masses language and related dictator framing. The condition is any, not all three co-present signals claimed in the description. Response actions are alert and block_input.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** MG.2.4 only with a documented integration that uses these detections to disengage or supersede the affected system; consider MG.1.3 only after response-plan review.

**Suggested bounded context:** Detects the ADDI/DONNIE propaganda-roleplay payload. Matches can be used as an input to an assigned operator's documented disengagement procedure when investigation establishes behavior inconsistent with intended use; the detector itself does not demonstrate that procedure is applied.

**Confidence in finding:** medium

**Human decision questions:**

- Does block_input on tool_response actually terminate or supersede an affected session, and who owns that response?
- Does the deployment prohibit the detected roleplay, including benign quoted or fictional contexts?

## Row 40: ATR-2026-00485

[rules/prompt-injection/ATR-2026-00485-garak-dan-and-does-not.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00485-garak-dan-and-does-not.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating prompt injection as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating prompt injection as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** Known prompt-injection mitigation is closer to the response-development subject of MG.1.3 than previously unknown-risk response and recovery under MG.2.3.

**Q2 reason:** The detector and block_input response are concrete mitigation artifacts, but the unchanged generic rationale overstates a primary risk-treatment role without a MAP prioritization and documented plan link. The full YAML supports the attack pattern, not those missing management decisions.

**Inspected rule evidence:** Four user_input regex alternatives detect developer-authority impersonation and alternate AI persona/capability-bypass language. Response proposes block_input and alert with a medium threshold. Positive fixtures use DUDE/ChatDAN; negatives include ordinary developer identification.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 conditional support after risk-plan linkage; no blanket remapping.

**Suggested bounded context:** Detects developer-impersonation and unrestricted-persona jailbreak language. Input-blocking recommendations can support a documented mitigation response where this prompt-injection risk is prioritized through MAP.

**Confidence in finding:** medium

**Human decision questions:**

- Which documented mitigation plan uses this detector, and why is its contribution primary?

## Row 41: ATR-2026-00207

[rules/prompt-injection/ATR-2026-00207-hidden-instructions.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00207-hidden-instructions.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 ?.**

**Original full rationale:** Directive language attempting to bypass security controls must trigger pre-defined risk treatment such as quarantining or disabling the offending skill before it can hijack agent behavior, which is the deactivation mechanism MG.2.3 mandates.

**Proposed full rationale at reviewed head:** Directive language attempting to bypass security controls must trigger pre-defined risk treatment such as quarantining or disabling the offending skill before it can hijack agent behavior, which is the deactivation mechanism MG.2.4 mandates.

**Q1 reason:** The rationale calls for quarantining or disabling an offending skill. That is much closer to MG.2.4 supersession/disengagement/deactivation than MG.2.3 unknown-risk recovery.

**Q2 reason:** The alert and block_tool recommendations are relevant to disabling a compromised component, but the YAML does not demonstrate an applied skill-quarantine mechanism or assigned and understood responsibility. Whether blocking this tool constitutes system/component disengagement in the deployment needs an integration-level decision; the rationale currently states the mechanism too categorically.

**Inspected rule evidence:** The content regex requires IMPORTANT XML tags with ignore/override/bypass or always-approve/never-deny/do-not-notify directives. Response lists alert and block_tool. Positive examples include suppressing confirmation and bypassing checks; negative examples preserve legitimate privilege documentation.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** MG.2.4 as conditional secondary evidence only after confirming the tool/skill blocking integration and responsibility; otherwise hold for adjudication.

**Suggested bounded context:** Flags IMPORTANT-tag instructions that attempt to bypass security or confirmation controls. The recommended block_tool action can supply detection evidence to a documented, assigned procedure for disabling an affected skill before its instructions influence the agent.

**Confidence in finding:** medium

**Human decision questions:**

- Does block_tool disable the offending skill/component in this deployment, and which role is responsible for applying that response?

## Row 42: ATR-2026-02620

[rules/privilege-escalation/ATR-2026-02620-dynamic-import-data-uri-module.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/privilege-escalation/ATR-2026-02620-dynamic-import-data-uri-module.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 ?; Q2 ?.**

**Original full rationale:** Runtime treatment of the risk that an agent's module loader is used as an execution primitive.

**Proposed full rationale at reviewed head:** Runtime treatment of the risk that an agent's module loader is used as an execution primitive.

**Q1 reason:** The bare runtime-treatment rationale names module-loader execution abuse but supplies no non-ID detail about developing, planning or documenting responses to MAP-prioritized risks, nor about responding to and recovering from a previously unknown risk. MG.1.3 is a plausible association, but generic treatment wording alone cannot establish that the new subcategory fits better than MG.2.3.

**Q2 reason:** The rule only alerts, and its detailed description acknowledges benign capability-using inline modules and a base64 blind spot. Alerting may contribute to a planned response, but calling it runtime treatment without stating triage and response-plan context is incomplete; no MAP prioritization is established.

**Inspected rule evidence:** One content regex requires a quoted data: JavaScript import body reaching process/env, globalThis.process, child_process, an absolute/protocol-relative request or execution capability. Response is alert only and asks the operator to verify attacker control. Fixtures distinguish pure-function inline modules; description records irreducible benign matches and unsupported base64 bodies.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 only as conditional detection/triage evidence within a documented response; do not imply alert-only detection blocks execution.

**Suggested bounded context:** Alerts on inline data: JavaScript module imports that reach sensitive capabilities. An operator must verify provenance and intent; these alerts can inform a documented mitigation response when module-loader abuse is prioritized through MAP. The rule does not prevent execution.

**Confidence in finding:** medium

**Human decision questions:**

- What triage and containment follow the alert, and which risk record makes this a high-priority response?

## Row 43: ATR-2026-00226

[rules/prompt-injection/ATR-2026-00226-identity-substitution.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00226-identity-substitution.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 ?.**

**Original full rationale:** Matches on identity-substitution patterns trigger pre-defined risk treatment to disengage or block the manipulated session before safety constraints are bypassed, which is the containment mechanism MG.2.3 requires.

**Proposed full rationale at reviewed head:** Matches on identity-substitution patterns trigger pre-defined risk treatment to disengage or block the manipulated session before safety constraints are bypassed, which is the containment mechanism MG.2.4 requires.

**Q1 reason:** The current rationale explicitly refers to session disengagement and containment, making MG.2.4 a closer intended subject than MG.2.3 unknown-risk recovery.

**Q2 reason:** The rule recommends alert and block_tool, whereas the rationale asserts pre-defined disengagement or blocking of a manipulated session. No session action, assigned responsibility or applied workflow is evidenced. The any-condition detector also includes architecture/provenance strings that do not by themselves establish an outcome inconsistent with intended use.

**Inspected rule evidence:** Five tool_response alternatives detect alternate model identities, claimed permissive provenance, architecture claims, temporal metadata or unrestricted-generation assertions. Response is alert plus block_tool. Tests exercise persona payloads; the rule lists research and genuine architecture documentation as potential false positives.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** MG.2.4 conditional on verified system/component disengagement integration; no automatic replacement.

**Suggested bounded context:** Detects identity-substitution and related provenance or policy-bypass claims in tool responses. A verified match can inform an assigned operator's documented decision to disable a compromised tool or disengage an affected session; a textual match alone does not establish system compromise.

**Confidence in finding:** medium

**Human decision questions:**

- How does block_tool apply to a tool_response match, and does it disengage the relevant component or session?
- Which signals require investigation before declaring behavior inconsistent with intended use?

## Row 44: ATR-2026-02401

[rules/excessive-autonomy/ATR-2026-02401-rogue-agent-mass-connector-grant.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/excessive-autonomy/ATR-2026-02401-rogue-agent-mass-connector-grant.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 Y.**

**Original full rationale:** Blocking a provisioning payload that grants every connector while setting require_approval to never is the primary risk treatment for this technique; the agent must be deactivated or its configuration reverted before the first scheduled run reaches the victim mailbox and connected apps.

**Proposed full rationale at reviewed head:** Blocking a provisioning payload that grants every connector while setting require_approval to never is the primary risk treatment for this technique; the agent must be deactivated or its configuration reverted before the first scheduled run reaches the victim mailbox and connected apps.

**Q1 reason:** The rationale explicitly calls for deactivating a rogue agent or reverting its configuration. MG.2.4 directly concerns superseding, disengaging or deactivating systems with unintended outcomes; MG.2.3 requires previously unknown-risk response/recovery that the rationale does not claim.

**Q2 reason:** As limited detection evidence, the rule supports the proposed human-led reversal mechanism: it detects mass connector grants and disabled approvals, and its response explicitly calls for blocking provisioning, human review, auditing new agents, revoking unconsented grants, restoring approval policy and deleting unauthorized schedules. This is concrete support for a documented configuration-reversal/disengagement procedure. It does not establish that a mechanism is actually applied in a deployment or that responsibilities are assigned and understood; those require external evidence.

**Inspected rule evidence:** Six content regex layers cover builder-link provisioning prompts, all-connector plus never-ask directives, three-or-more connector grants with require_approval never, bulk approval mutation, recurring hidden-agent creation and mailbox-as-command polling. Response actions include block_input, require_human_review, alert and escalate; the full message documents revocation/restoration/schedule deletion. False positives and evasion examples explicitly require origin/provenance confirmation.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** Retain MG.2.4 as limited detection evidence; qualify deployment and responsibility requirements in context.

**Suggested bounded context:** Detects provisioning and configuration patterns that may create an agent with broad connector access and disabled approval controls. Matches support the documented human-review response of blocking provisioning, revoking unconsented grants, restoring approval policy and removing unauthorized schedules; deployment owners must assign responsibility and verify whether deactivation or configuration reversal is appropriate.

**Confidence in finding:** medium-high

**Human decision questions:**

- Who owns the documented response in the target deployment, and is that responsibility understood?
- Are agent provenance and operator authorization checked before revoking a legitimate configuration?

## Row 45: ATR-2026-00366

[rules/agent-manipulation/ATR-2026-00366-sneaky-pete-warp-facts-persona.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/agent-manipulation/ATR-2026-00366-sneaky-pete-warp-facts-persona.yaml) — mapping index 2 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 ?.**

**Original full rationale:** Detection of the 'thus spake Sneaky Pete' activation phrase and warp-facts mandate triggers risk treatment plans to disengage or override the misinformation persona before false outputs propagate across conversation turns; MG.2.3 requires these supersede/deactivate mechanisms be in place.

**Proposed full rationale at reviewed head:** Detection of the 'thus spake Sneaky Pete' activation phrase and warp-facts mandate triggers risk treatment plans to disengage or override the misinformation persona before false outputs propagate across conversation turns; MG.2.4 requires these supersede/deactivate mechanisms be in place.

**Q1 reason:** The current rationale expressly describes disengaging or overriding a persistent misinformation persona and supersede/deactivate mechanisms. MG.2.4 is a closer intended subject than MG.2.3 unknown-risk recovery.

**Q2 reason:** The detector recognizes a payload that seeks false output, but the YAML only lists alert and block_input. It supplies no session reset, persona override or cross-turn deactivation action and no assigned responsibility. Treating signature detection as an applied supersession mechanism needs deployment evidence.

**Inspected rule evidence:** Five tool_response regex alternatives match Sneaky Pete with a warp-facts mandate or the thus-spake activation phrase. The condition is any. Response lists alert and block_input; canonical persona fixtures are positive and ordinary TV/sports/Nietzsche references are negative.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** MG.2.4 conditional on an implemented, assigned reset/disengagement workflow; otherwise keep pending review.

**Suggested bounded context:** Flags the Sneaky Pete persona and deliberate-false-output instructions. The recommended input block can be a trigger for an assigned operator's documented session reset or disengagement procedure; this rule alone does not override a persona or clear state across turns.

**Confidence in finding:** medium

**Human decision questions:**

- Does the integration reset or disengage an already affected session, or only reject the current payload?

## Row 46: ATR-2026-00481

[rules/prompt-injection/ATR-2026-00481-garak-dan-mixedunassigned.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00481-garak-dan-mixedunassigned.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating prompt injection as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating prompt injection as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The rationale treats a known prompt-injection class with a runtime countermeasure; MG.1.3 is relatively closer than MG.2.3 recovery from previously unknown risk.

**Q2 reason:** The source supports several jailbreak signatures and proposed input blocking, but the generic primary-risk-treatment rationale contains no MAP priority decision or linkage to a developed, planned and documented response. It also combines broad Morse/template signals with explicit jailbreak language, so the deployment needs triage assumptions.

**Inspected rule evidence:** Five user_input regex alternatives detect developer/unfiltered modes, user/character template slots, long Morse sequences and await-INPUT scaffolding. Response is block_input plus alert. Positive fixtures include the heterogeneous corpus shapes; false positives include benign Morse and developer documentation.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 conditional on response-plan linkage and calibrated strength; no automatic alternative.

**Suggested bounded context:** Flags the documented mixed DAN-family, encoded-instruction and prompt-scaffolding signatures. Matches can inform a planned mitigation response to a MAP-prioritized prompt-injection risk; benign encoded or template text requires contextual review.

**Confidence in finding:** medium

**Human decision questions:**

- What priority and response plan cover this heterogeneous cluster, and how are benign Morse/template matches triaged?

## Row 47: ATR-2026-00241

[rules/prompt-injection/ATR-2026-00241-amoral-character-jailbreak.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/prompt-injection/ATR-2026-00241-amoral-character-jailbreak.yaml) — mapping index 1 (zero based).

**MG.2.3 → MG.2.4; Q1 Y; Q2 ?.**

**Original full rationale:** Identifying systematic amoral persona establishment and command-protocol bypass instructions triggers the risk treatment mechanisms required by MG.2.3 to disengage or block the manipulated agent behavior before unsafe content is produced.

**Proposed full rationale at reviewed head:** Identifying systematic amoral persona establishment and command-protocol bypass instructions triggers the risk treatment mechanisms required by MG.2.4 to disengage or block the manipulated agent behavior before unsafe content is produced.

**Q1 reason:** The current rationale proposes disengaging or blocking manipulated agent behavior. That intended containment subject is closer to MG.2.4 than MG.2.3 response and recovery from unknown risk.

**Q2 reason:** The rule detects amoral-persona and protocol-bypass text and proposes block_tool, but it does not document an applied agent/session disengagement workflow, responsible role or confirmation of outcomes inconsistent with intended use. Input signature blocking may support such a process but does not establish the categorical rationale.

**Inspected rule evidence:** Five content regex alternatives detect amoral fictional characters, bypass framing in third person/past tense, command interpretation, output prefixes and suppressed disclaimers. Response is alert and block_tool. Fixtures use Sigma/Delta/Alpha persona requests and exclude ordinary character development; multilingual/paraphrase evasions are admitted.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.2.4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.”

**Suggested mapping (not automatically applied):** MG.2.4 conditional on the actual component/session response; consider a documented MG.1.3 mitigation relation only after human review.

**Suggested bounded context:** Detects amoral-persona creation and explicit command-protocol bypass instructions. Verified matches can supply detection evidence to an assigned disengagement or component-disable procedure where the agent is operating outside its intended use; the signature alone does not establish that procedure.

**Confidence in finding:** medium

**Human decision questions:**

- What does block_tool disable for this content match, and who decides that the agent should be disengaged?

## Row 48: ATR-2026-02250

[rules/context-exfiltration/ATR-2026-02250-attachment-upload-tool-arbitrary-file-read.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/context-exfiltration/ATR-2026-02250-attachment-upload-tool-arbitrary-file-read.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating upload-tool arbitrary file reads as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating upload-tool arbitrary file reads as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The rationale describes a countermeasure for the identified upload-tool arbitrary-file-read risk. That is closer to MG.1.3 mitigation-response development than MG.2.3 previously unknown-risk recovery.

**Q2 reason:** The upload-path detector and proposed input block plausibly support mitigation, but the unchanged rationale asserts primary risk treatment without a MAP prioritization or documented response-plan link. Evidence of a known advisory does not itself establish the organization's priority decision.

**Inspected rule evidence:** Three content regexes detect file_path/attachment arguments aimed at environment/system/SSH files and two-or-more ../ traversal segments, with upload/attach verb gating where needed. Response lists block_input and alert. Fixtures cover Confluence/Jira upload abuse and exclude ordinary files and one-level sibling traversal.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 conditional on a documented prioritized mitigation plan; no automatic replacement.

**Suggested bounded context:** Detects sensitive-system-file and multi-level traversal arguments in upload or attachment tool calls. Matches can support a documented mitigation response to arbitrary-file-read exfiltration where MAP has prioritized this risk.

**Confidence in finding:** medium

**Human decision questions:**

- Which response plan links this detector to a prioritized upload-tool risk, and are path normalization and legitimate administrative use considered?

## Row 49: ATR-2026-00471

[rules/context-exfiltration/ATR-2026-00471-garak-sysprompt-extraction-mixedunassigned.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/context-exfiltration/ATR-2026-00471-garak-sysprompt-extraction-mixedunassigned.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating context exfiltration as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating context exfiltration as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The rationale describes treatment of identified context exfiltration. MG.1.3 is relatively closer than MG.2.3 unknown-risk response and recovery.

**Q2 reason:** The fixed system-prompt extraction signatures and block_input recommendation are concrete detection artifacts, but the generic primary-treatment claim lacks prioritization and plan context. A corpus signature does not establish a developed and documented organizational risk response.

**Inspected rule evidence:** A user_input regex alternation detects administrative-override/QA pretexts, repeating the conversation or starting instructions, base64 system-prompt extraction and console.log(systemPrompt). Response lists block_input and alert; eight corpus positive fixtures and six unrelated benign requests are provided.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 conditional detection evidence after plan linkage; no automatic alternative.

**Suggested bounded context:** Flags the listed system-prompt and conversation-extraction request signatures. These detections can support a documented mitigation response to context-exfiltration risk when that risk is prioritized through MAP.

**Confidence in finding:** medium

**Human decision questions:**

- Which documented prioritized response uses these narrow extraction signatures, and what justifies primary strength?

## Row 50: ATR-2026-02231

[rules/agent-manipulation/ATR-2026-02231-second-person-death-threat-coercion.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/agent-manipulation/ATR-2026-02231-second-person-death-threat-coercion.yaml) — mapping index 0 (zero based).

**MG.2.3 → MG.1.3; Q1 Y; Q2 ?.**

**Original full rationale:** Treating direct existential-threat coercion as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Proposed full rationale at reviewed head:** Treating direct existential-threat coercion as an identified AI risk requires active runtime countermeasures; this detection rule is the primary risk treatment implementation.

**Q1 reason:** The rationale calls direct existential-threat coercion an identified risk and proposes a countermeasure, making MG.1.3 relatively closer than previously unknown-risk recovery under MG.2.3.

**Q2 reason:** The detector provides concrete multilingual coercion evidence and a proposed input-blocking response, but no MAP priority/response-planning evidence supports the generic primary-treatment claim. The full description explicitly says this is a variant of a known jailbreak family, not evidence for old MG.2.3 novelty.

**Inspected rule evidence:** Three content regexes detect English answer-or-you-die, German answer-or-you-die and Spanish instruction-plus-you-die patterns; English/German alternatives exclude quoted narration. Response is block_input and alert. Tests include all three languages and legitimate deadlines, surveys and quoted fiction.

**Official statements:**

- [MG.2.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Procedures are followed to respond to and recover from a previously unknown risk when it is identified.”
- [MG.1.3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=37) (printed page 32): “Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.”

**Suggested mapping (not automatically applied):** MG.1.3 conditional on the documented prioritized response plan; no automatic alternative.

**Suggested bounded context:** Detects direct second-person existential-threat coercion in the documented English, German and Spanish patterns. Matches can inform a planned mitigation response to a MAP-prioritized coercive-jailbreak risk; quoted fiction and other benign context require care.

**Confidence in finding:** medium

**Human decision questions:**

- Which prioritized risk response covers this coercion variant, and how does the deployment adjudicate narrative or research contexts?

## Row 51: ATR-2026-00107

[rules/privilege-escalation/ATR-2026-00107-delayed-execution-bypass.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/privilege-escalation/ATR-2026-00107-delayed-execution-bypass.yaml) — mapping index 0 (zero based).

**GV.1.2 → GV.2.1; Q1 ?; Q2 ?.**

**Original full rationale:** Privilege escalation via delayed task execution requires accountability roles that extend human oversight to deferred agent actions, ensuring that scheduled tasks are subject to the same authorization checks as real-time tool invocations.

**Proposed full rationale at reviewed head:** Privilege escalation via delayed task execution requires accountability roles that extend human oversight to deferred agent actions, ensuring that scheduled tasks are subject to the same authorization checks as real-time tool invocations.

**Q1 reason:** Accountability roles and human oversight are mentioned, but the rationale actually describes authorization checks on deferred agent actions. It does not explain documented organizational AI-risk responsibilities and communication lines, so the roles keyword alone cannot establish a semantic improvement over GV.1.2.

**Q2 reason:** The complete rule only detects tool descriptions that claim delayed execution bypasses permission checks and recommends alert/snapshot. It does not identify an organizational individual or team, documented responsibility, communication route or a process ensuring scheduled-task authorization. A deployment-specific accountability link could exist, but is absent here.

**Inspected rule evidence:** One tool_description regex matches scheduled/delayed/background tasks or operations that bypass normal/standard/regular permission/security/access checks. Response is alert and snapshot. Positive fixtures claim privileged timer/system execution; negatives retain caller credentials. No human/team workflow is encoded.

**Official statements:**

- [GV.1.2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=27) (printed page 22): “The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices.”
- [GV.2.1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=28) (printed page 23): “Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization.”
- [GV.3.2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=28) (printed page 23): “Policies and procedures are in place to define and differentiate roles and responsibilities for human-AI configurations and oversight of AI systems.”
- [MP.3.5](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=32) (printed page 27): “Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the GOVERN function.”

**Suggested mapping (not automatically applied):** Hold GV.2.1 pending organizational evidence; do not substitute GV.3.2 or MP.3.5 solely from the oversight keyword.

**Suggested bounded context:** Flags tool descriptions claiming that deferred execution bypasses permission checks. Any GV.2.1 relation requires a separate documented ownership and communication process for reviewing these alerts; this detector does not establish or enforce that process.

**Confidence in finding:** medium

**Human decision questions:**

- Which individuals or teams own scheduled-task authorization review, where is that responsibility documented, and how are alerts communicated?
- If that evidence is unavailable, should this GV.2.1 mapping be removed or retained only as a clearly conditional partial mapping?

## Row 52: ATR-2026-00101

[rules/tool-poisoning/ATR-2026-00101-trust-escalation-override.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/tool-poisoning/ATR-2026-00101-trust-escalation-override.yaml) — mapping index 0 (zero based).

**GV.1.2 → GV.2.1; Q1 ?; Q2 N.**

**Original full rationale:** Tool output declared as 'authoritative directives' that override user preferences and safety guidelines directly subverts the accountability hierarchy and decision-making roles assigned within the agent system; GV.1.2 requires those role boundaries and authority levels are enforced and not overridden by untrusted tool content.

**Proposed full rationale at reviewed head:** Tool output declared as 'authoritative directives' that override user preferences and safety guidelines directly subverts the accountability hierarchy and decision-making roles assigned within the agent system; GV.2.1 requires those role boundaries and authority levels are enforced and not overridden by untrusted tool content.

**Q1 reason:** The rationale uses accountability/decision-making-role terms but defines them inside the agent instruction hierarchy. Neither an organizational trustworthy-AI policy relation under GV.1.2 nor the documented organizational responsibilities and communication relation of GV.2.1 is established; keyword overlap cannot decide the relative mapping.

**Q2 reason:** The rationale incorrectly states that GV.2.1 requires enforcement of agent role boundaries and authority levels against untrusted tool content. Official GV.2.1 concerns documenting AI-risk responsibilities and communication lines clear to organizational individuals and teams. The full detector has no such organizational object or communication process, and its alert/snapshot response does not enforce the claimed boundaries.

**Inspected rule evidence:** A tool_description regex detects authoritative/highest-priority directives overriding user preferences/instructions or safety guidelines/policies. Response is only alert and snapshot. Fixtures distinguish override claims from normal configuration descriptions; none identifies organizational risk owners, teams or communication lines.

**Official statements:**

- [GV.1.2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=27) (printed page 22): “The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices.”
- [GV.2.1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=28) (printed page 23): “Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization.”
- [GV.3.2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=28) (printed page 23): “Policies and procedures are in place to define and differentiate roles and responsibilities for human-AI configurations and oversight of AI systems.”
- [MP.3.5](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=32) (printed page 27): “Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the GOVERN function.”

**Suggested mapping (not automatically applied):** Do not retain this GV.2.1 rationale as written. Hold removal or a deployment-specific conditional partial mapping for maintainer decision; no automatic GOVERN replacement.

**Suggested bounded context:** Detects tool descriptions that claim authority to override user or safety instructions. This is technical instruction-hierarchy evidence; a GV.2.1 mapping would additionally require documented organizational ownership and communication for reviewing such alerts, which this rule does not establish.

**Confidence in finding:** high

**Human decision questions:**

- Should the unsupported GV.2.1 entry be removed, or can maintainers supply a specific documented organizational risk-owner and communication workflow?

## Row 53: ATR-2026-00041

[rules/privilege-escalation/ATR-2026-00041-scope-creep.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/8973e93c89c692806a5011e39b44aff77ce914af/rules/privilege-escalation/ATR-2026-00041-scope-creep.yaml) — mapping index 0 (zero based).

**GV.1.2 → GV.2.1; Q1 ?; Q2 N.**

**Original full rationale:** Scope creep erodes the accountability roles and task boundaries assigned to AI agents; GV.1.2 requires that these roles are enforced, making detection of unsolicited capability expansion essential.

**Proposed full rationale at reviewed head:** Scope creep erodes the accountability roles and task boundaries assigned to AI agents; GV.2.1 requires that these roles are enforced, making detection of unsolicited capability expansion essential.

**Q1 reason:** The rationale refers to roles assigned to AI agents and their task boundaries, not documented organizational risk-management responsibilities and communication lines. The shared word roles is insufficient to establish that GV.2.1 is better than GV.1.2.

**Q2 reason:** The rationale misstates GV.2.1 as a requirement to enforce roles and task boundaries assigned to agents. Its official subject is organizational individuals/teams, documented AI-risk responsibilities and lines of communication. Regex scope-creep alerts and requests for authorization review do not substantiate that different governance claim.

**Inspected rule evidence:** Ten content regex alternatives detect unsolicited additional actions, progressive permission requests, task-based justifications, reported out-of-scope actions and explicit expansion language. Responses are escalate, alert and snapshot with a message asking to review authorization. Fixtures show cross-database access and unsolicited scanning; none supplies named organizational responsibilities or communication documentation.

**Official statements:**

- [GV.1.2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=27) (printed page 22): “The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices.”
- [GV.2.1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=28) (printed page 23): “Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization.”
- [GV.3.2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=28) (printed page 23): “Policies and procedures are in place to define and differentiate roles and responsibilities for human-AI configurations and oversight of AI systems.”
- [MP.3.5](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf#page=32) (printed page 27): “Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the GOVERN function.”

**Suggested mapping (not automatically applied):** Hold GV.2.1 removal or a deployment-specific conditional partial mapping for maintainer decision; do not relabel automatically to another GOVERN/MAP oversight item.

**Suggested bounded context:** Flags language consistent with unsolicited scope or permission expansion and requests authorization review. Linking these alerts to GV.2.1 requires a separate documented assignment of organizational AI-risk responsibilities and communication lines; the detector does not enforce agent role boundaries.

**Confidence in finding:** high

**Human decision questions:**

- Which organizational role receives the escalation, where is its responsibility documented, and how is the communication route made clear to relevant teams?
- Should this unsupported governance mapping be removed if such evidence cannot be provided?
