# ATR → MITRE ATLAS Mapping

Version: 0.1.0 (INTERNAL DRAFT — not published)
Status: Draft alignment mapping for MITRE ATLAS content v2026.06 (data-format 6.0.0)
Date: 2026-07-14 (re-reconciled to v2026.06; prior 2026-06-14, and a 2026-07-14 pass that mis-read the version — see note below)
Editor: Adam Lin (林冠辛) <adam@agentthreatrule.org>
Mapped corpus: Agent Threat Rules v3.5.8 (793 rules / 10 categories; disk == data/stats.json reconciled 2026-07-14)
Reference framework: MITRE ATLAS (Adversarial Threat Landscape for AI Systems). Since content release **v2026.05** MITRE split versioning: **content** follows a date-based `YYYY.MM` scheme stored in the Collection object (current: **v2026.06**, 2026-06-30), while the **data format** follows semver (current: **6.0.0**). The current machine-readable file is `dist/v6/ATLAS-2026.06.yaml` (reached via the `dist/ATLAS-latest.yaml` → `dist/v6/ATLAS-latest.yaml` pointer chain) — **16 tactics, 103 top-level techniques (173 including sub-techniques)**, downloaded and parsed locally 2026-07-14. NOTE: the older flat `dist/ATLAS.yaml` is **deprecated and frozen** at the v5.6.0-format content (101 techniques) and must not be used — it is what an earlier 2026-07-14 pass wrongly reconciled against, incorrectly reporting "still v5.6.0". Corrected here.

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

Every technique ID and name in this document was reconciled against the official
MITRE ATLAS data: first on 2026-06-14, and re-reconciled on 2026-07-14 against
content **v2026.06** (`dist/v6/ATLAS-2026.06.yaml`, data-format 6.0.0). All 34
ATLAS techniques ATR references remain valid in v2026.06 (none renamed or retired).
Every cited rule ID is a real `ATR-YYYY-NNNNN` identifier read from the rule corpus
(751 rules) on the re-reconciliation date.

## 2. Coverage summary

| Metric | Value |
|---|---|
| ATLAS content version reconciled against | v2026.06 (data-format 6.0.0) |
| ATLAS top-level techniques (total) | 103 |
| ATLAS top-level techniques with ≥1 ATR rule | **34 (33%)** |
| ATLAS tactics with ≥1 covered technique | 13 of 16 (Defense Evasion covered via T0109; also spans Lateral Movement) |
| ATR rules carrying ≥1 ATLAS technique ID | every rule in the corpus |

**Honest scope note.** The 69 uncovered top-level techniques are dominated by the
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

### Agent-native techniques (added 2026-06-14; counts re-verified 2026-07-14)

ATLAS (content v2026.06) ships agent-native techniques. These rules now carry the
precise agent-native ID (added alongside, not in place of, existing mappings):

| ATLAS ID | Technique | Tactic | ATR rules | Example |
|---|---|---|---|---|
| AML.T0080 | AI Agent Context Poisoning | Persistence | 3 | ATR-2026-00075, ATR-2026-00125, ATR-2026-00551 |
| AML.T0110 | AI Agent Tool Poisoning | Persistence | 4 | ATR-2026-00103, ATR-2026-00161, ATR-2026-02025 |
| AML.T0105 | Escape to Host | Privilege Escalation | 3 | ATR-2026-00436, ATR-2026-00539, ATR-2026-01615 |
| AML.T0104 | Publish Poisoned AI Agent Tool | Resource Development | 5 | ATR-2026-00161, ATR-2026-00581, ATR-2026-01932 |
| AML.T0109 | AI Supply Chain Rug Pull | Defense Evasion | 1 | ATR-2026-00126 |
| AML.T0102 | Generate Malicious Commands | AI Attack Staging | 1 | ATR-2026-00413 |

## 4. Maintenance

- **Source of truth:** each rule's `references.mitre_atlas` block. This document is a
  generated aggregate, not a second source. Regenerate after rule-corpus changes:
  `grep -rhoE "AML\.T[0-9]{4}" rules/ | sort | uniq -c`. Always count the ATLAS side
  from the current machine-readable data — `dist/v6/ATLAS-<YYYY.MM>.yaml`, resolved
  via the `dist/ATLAS-latest.yaml` pointer chain (`scripts/atd/sync-atlas-allowlist.ts`
  does this and vendors the id→name map to `data/threat-frameworks/mitre-atlas.json`).
  Do **not** use the flat `dist/ATLAS.yaml` — it is deprecated and frozen at 101
  techniques, and a truncated web fetch undercounts.
- **New in content v2026.06 (added since the v5.6.0-era catalog), not yet ATR-tagged:**
  - **AML.T0113 Steal Web Session Cookie** and **AML.T0091.001 Use Alternate
    Authentication Material: Web Session Cookie** — session-token theft/replay; candidate
    overlap with the credential-exfil family, review before tagging.
  - **AML.T0114 AI Service Web Interface** — an access surface (the AI service's own web
    UI); mostly an access-vector rather than a runtime agent-I/O detection target.
- **Expansion candidates (re-verified 2026-07-14):** the agent-native techniques listed as
  candidates in the 2026-06-14 draft — T0104, T0105, T0110, T0102 — are now **tagged and
  covered** (see the Agent-native table above); that earlier bullet was stale. The
  agent-native techniques the catalog ships that ATR does **not** yet carry an ID for are:
  - **AML.T0098 AI Agent Tool Credential Harvesting** — ATR already has substantive
    detection (the whole context-exfiltration / credential-exfil family, e.g.
    ATR-2026-02261 code-surface credential-exfil chain, ATR-2026-00212 mcp-atlassian
    credential leak); these lack only the `AML.T0098` tag. **Highest-value tagging
    follow-up.**
  - **AML.T0101 Data Destruction via AI Agent Tool Invocation** — ATR has substantive
    detection (e.g. ATR-2026-02233 unscoped destructive DB request); lacks only the
    `AML.T0101` tag. Second-highest tagging follow-up.
  - **AML.T0099 AI Agent Tool Data Poisoning** — partial overlap with existing
    tool-poisoning rules; candidate for review, not a clean 1:1 map.
  - **AML.T0100 AI Agent Clickbait** — user-facing lure technique; largely out of ATR's
    runtime-agent-I/O scope by design.
  Adding a technique ID to a rule is a rule-corpus change (each addition must keep the
  rule's compliance blocks passing `npm run audit:mappings`), so it is tracked as a
  separate follow-up rather than folded into this doc-only reconciliation.
- **Cadence:** re-reconcile technique IDs/names against the current `dist/v6/` data on
  each monthly ATLAS content release (`YYYY.MM`). Since v2026.05, content version
  (date-based, in the Collection object) and data-format version (semver, now 6.0.0) are
  tracked separately — cite the **content** version (v2026.06) for "which techniques",
  and don't confuse the format-version field for the release. The 2026-06-14
  reconciliation corrected 82 rules whose metadata carried pre-v5 technique names
  (e.g. "ML Supply Chain Compromise" → "AI Supply Chain Compromise") or mislabelled IDs.
- **Claim discipline:** "aligned to ATLAS" / "maps to ATLAS technique X" only.
  Never "adopted by MITRE" or "ATLAS-certified".
