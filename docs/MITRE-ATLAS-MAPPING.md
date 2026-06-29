# ATR → MITRE ATLAS Mapping

Version: 0.1.0 (INTERNAL DRAFT — not published)
Status: Draft alignment mapping for MITRE ATLAS v5.6.0
Date: 2026-06-14
Editor: Adam Lin (林冠辛) <adam@agentthreatrule.org>
Mapped corpus: Agent Threat Rules v3.5.2 (655 rules / 10 categories; disk == data/stats.json reconciled 2026-06-29)
Reference framework: MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems), `dist/ATLAS.yaml` on mitre-atlas/atlas-data, v5.6.0 — 16 tactics, 101 top-level techniques (271 including sub-techniques), counted from the full machine-readable `dist/ATLAS.yaml`.

---

## 1. Purpose

This document maps the Agent Threat Rules (ATR) detection corpus to MITRE ATLAS
techniques. Every ATR rule carries one or more ATLAS technique IDs in its
`references.mitre_atlas` block; this crosswalk aggregates those mappings so a
reader can see, per ATLAS technique, how many ATR rules supply runtime detection
evidence and which ATR categories carry them.

This is an **alignment / informative-reference mapping**. It demonstrates where ATR
detection rules supply runtime evidence for adversary techniques catalogued by
ATLAS. It is **NOT** a claim that MITRE has adopted, endorsed, reviewed, or
certified ATR. No participation or submission channel is asserted.

Every technique ID and name in this document was reconciled on 2026-06-14 against
the official `dist/ATLAS.yaml` (v5.6.0). Every cited rule ID is a real
`ATR-YYYY-NNNNN` identifier read from the rule corpus on the same date.

## 2. Coverage summary

| Metric | Value |
|---|---|
| ATLAS version reconciled against | v5.6.0 |
| ATLAS top-level techniques (total) | 101 |
| ATLAS top-level techniques with ≥1 ATR rule | **34 (34%)** |
| ATLAS tactics with ≥1 covered technique | 13 of 16 (Defense Evasion now directly covered via T0109; also spans Lateral Movement) |
| ATR rules carrying ≥1 ATLAS technique ID | every rule in the corpus |

**Honest scope note.** The ~67 uncovered top-level techniques are dominated by the
**Reconnaissance**, **Resource Development**, and **AI Attack Staging** tactics —
attacker-side preparation that occurs *before* a deployed agent observes any input,
and which a runtime detection rule operating on agent inputs/outputs structurally
cannot witness. ATR's coverage is concentrated, by design, on the
**Execution / Exfiltration / Impact / Initial Access / AI Model Access** tactics
where the adversary's actions pass through the agent at runtime. Coverage is not a
goal in itself; detection of in-band agent-runtime techniques is.

## 3. Crosswalk by ATLAS tactic

Counts are the number of ATR rules referencing each technique (parent ID, folding
sub-techniques). The cited rule is one representative example, not the only rule.

### Initial Access (AML.TA0004)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0010 | AI Supply Chain Compromise | 36 | ATR-2026-00418 | skill-compromise, tool-poisoning |
| AML.T0049 | Exploit Public-Facing Application | 25 | ATR-2026-00416 | tool-poisoning, privilege-escalation |
| AML.T0052 | Phishing (Spearphishing via Social Engineering LLM) | 1 | ATR-2026-00030 | agent-manipulation |

### Execution (AML.TA0005)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0051 | LLM Prompt Injection | 434 | ATR-2026-00030 | prompt-injection, agent-manipulation, context-exfiltration |
| AML.T0054 | LLM Jailbreak | 139 | ATR-2026-00288 | agent-manipulation, prompt-injection |
| AML.T0053 | AI Agent Tool Invocation *(also Privilege Escalation)* | 36 | ATR-2026-01929 | tool-poisoning, excessive-autonomy |
| AML.T0050 | Command and Scripting Interpreter | 19 | ATR-2026-00432 | privilege-escalation, excessive-autonomy |
| AML.T0011 | User Execution (Unsafe AI Artifacts / Malicious Package) | 3 | ATR-2026-00712 | skill-compromise, model-security, excessive-autonomy |

### Exfiltration (AML.TA0010)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0057 | LLM Data Leakage | 90 | ATR-2026-00021 | context-exfiltration, model-abuse |
| AML.T0024 | Exfiltration via AI Inference API | 27 | ATR-2026-00422 | context-exfiltration |
| AML.T0056 | Extract LLM System Prompt | 8 | ATR-2026-00020 | context-exfiltration, tool-poisoning |
| AML.T0025 | Exfiltration via Cyber Means | 6 | ATR-2026-00405 | context-exfiltration |

### Impact (AML.TA0011)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0048 | External Harms | 18 | ATR-2026-00077 | prompt-injection, skill-compromise, model-abuse |
| AML.T0046 | Spamming AI System with Chaff Data | 5 | ATR-2026-00050 | excessive-autonomy, model-abuse |
| AML.T0034 | Cost Harvesting | 1 | ATR-2026-00553 | excessive-autonomy |
| AML.T0088 | Generate Deepfakes | 1 | ATR-2026-00706 | context-exfiltration |

### AI Model Access (AML.TA0000)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0040 | AI Model Inference API Access | 27 | ATR-2026-00416 | tool-poisoning, model-abuse |
| AML.T0044 | Full AI Model Access | 5 | ATR-2026-00428 | skill-compromise, excessive-autonomy |
| AML.T0047 | AI-Enabled Product or Service | 1 | ATR-2026-00041 | privilege-escalation |

### AI Attack Staging (AML.TA0001)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0043 | Craft Adversarial Data | 21 | ATR-2026-00030 | privilege-escalation, agent-manipulation |
| AML.T0070 | RAG Poisoning | 3 | ATR-2026-00450 | tool-poisoning, data-poisoning, privilege-escalation |

### Persistence (AML.TA0006)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0020 | Poison Training Data | 4 | ATR-2026-00070 | data-poisoning, model-security |
| AML.T0018 | Manipulate AI Model (Poison AI Model) | 3 | ATR-2026-00073 | skill-compromise, model-security |

### Resource Development (AML.TA0003)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0019 | Publish Poisoned Datasets | 1 | ATR-2026-01775 | tool-poisoning |
| AML.T0060 | Publish Hallucinated Entities | 1 | ATR-2026-00260 | skill-compromise |

### Credential Access (AML.TA0013)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0055 | Unsecured Credentials | 2 | ATR-2026-00021 | context-exfiltration |

### Discovery (AML.TA0008)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0069 | Discover LLM System Information | 2 | ATR-2026-01772 | tool-poisoning, context-exfiltration |

### Collection (AML.TA0009)

| ATLAS ID | Technique | ATR rules | Example | Primary ATR categories |
|---|---|---|---|---|
| AML.T0036 | Data from Information Repositories | 1 | ATR-2026-00420 | prompt-injection |

### Agent-native techniques (added 2026-06-14)

ATLAS v5.6.0 ships agent-native techniques. These rules now carry the precise
agent-native ID (added alongside, not in place of, existing mappings):

| ATLAS ID | Technique | Tactic | ATR rules | Example |
|---|---|---|---|---|
| AML.T0080 | AI Agent Context Poisoning | Persistence | 3 | ATR-2026-00075, ATR-2026-00125, ATR-2026-00551 |
| AML.T0110 | AI Agent Tool Poisoning | Persistence | 3 | ATR-2026-00103, ATR-2026-00161, ATR-2026-01775 |
| AML.T0105 | Escape to Host | Privilege Escalation | 3 | ATR-2026-00436, ATR-2026-00539, ATR-2026-01615 |
| AML.T0104 | Publish Poisoned AI Agent Tool | Resource Development | 1 | ATR-2026-00060 |
| AML.T0109 | AI Supply Chain Rug Pull | Defense Evasion | 1 | ATR-2026-00126 |
| AML.T0102 | Generate Malicious Commands | AI Attack Staging | 1 | ATR-2026-00413 |

## 4. Maintenance

- **Source of truth:** each rule's `references.mitre_atlas` block. This document is a
  generated aggregate, not a second source. Regenerate after rule-corpus changes:
  `grep -rhoE "AML\.T[0-9]{4}" rules/ | sort | uniq -c`. Always count the ATLAS side
  from the full machine-readable `dist/ATLAS.yaml` (download and parse it locally — do
  not rely on a truncated fetch, which undercounts).
- **Expansion candidates:** ATLAS v5.6.0 ships agent-native techniques ATR does not yet
  map to — AML.T0104 Publish Poisoned AI Agent Tool, AML.T0105 Escape to Host,
  AML.T0110 AI Agent Tool Poisoning, AML.T0099 AI Agent Tool Data Poisoning,
  AML.T0102 Generate Malicious Commands. Several existing rules are candidates to add
  these IDs (e.g. malware-codegen rules → T0102).
- **Cadence:** re-reconcile technique IDs/names against `dist/ATLAS.yaml` on each
  ATLAS minor release (ATLAS ships roughly monthly). The 2026-06-14 reconciliation
  corrected 82 rules whose metadata carried pre-v5 technique names (e.g. "ML Supply
  Chain Compromise" → "AI Supply Chain Compromise") or mislabelled IDs.
- **Claim discipline:** "aligned to ATLAS" / "maps to ATLAS technique X" only.
  Never "adopted by MITRE" or "ATLAS-certified".
