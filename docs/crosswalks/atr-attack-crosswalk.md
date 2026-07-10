# ATR -> MITRE ATT&CK / ATLAS Crosswalk

This document maps Agent Threat Rules (ATR) categories and rules to MITRE
technique ids, so any ruleset that tags with MITRE ATT&CK (for example a
Sigma ruleset using `tags: attack.txxxx`) can align with ATR on the shared
technique-id axis. It was produced in response to
agentshield-ai/sigma-ai#9.

All technique ids below are read verbatim from each rule's `references`
block. None are authored by hand. Regenerate with
`python3 scripts/generate-attack-crosswalk.py`.

## How to join against this crosswalk

The clean, machine-derivable key is the enterprise ATT&CK technique id.
ATR stores it as `references.mitre_attack: Txxxx`; a Sigma rule stores it
as `tags: attack.txxxx`. They line up after case folding (ATR upper-cases
and omits the prefix, Sigma lower-cases and prefixes `attack.`):

    ATR   references.mitre_attack: T1059
    Sigma tags: attack.t1059

MITRE ATLAS (`AML.Txxxx`) and OWASP Agentic (`ASIxx`) are the
agent-specific layer ATR carries that ATT&CK-tagged rulesets do not tag.
They are included as additional columns so this document is the place that
connects ATT&CK-tagged runtime rules to the agent frameworks. Those
columns are still extracted from ATR metadata, not authored here.

## Coverage

- ATR rules total: 716
- Rules carrying an enterprise ATT&CK id (`references.mitre_attack` Txxxx): 136
- Distinct enterprise ATT&CK techniques referenced: 55
- Rules carrying a MITRE ATLAS id (`references.mitre_atlas`): 716
- Distinct MITRE ATLAS techniques referenced: 40
- Rules carrying an OWASP Agentic id (`references.owasp_agentic`): 716
- ATR categories (distinct `tags.category` values): 9

Categories are keyed on each rule's `tags.category` metadata, not on its
directory. The repo has ten rule directories, but three rules under
`rules/model-security/` carry `tags.category` of `model-abuse` or
`data-poisoning`, so nine distinct categories appear in the metadata.

## ATT&CK techniques referenced by ATR (the join surface)

Every enterprise ATT&CK technique id present in ATR metadata, with the ATR
rules that reference it. This is the column a Sigma `attack.txxxx` tag joins
against.

| ATT&CK technique | Name | ATR rules | ATR categories |
|---|---|---|---|
| T1005 | Data from Local System | `ATR-2026-01988` | context-exfiltration |
| T1027 | Obfuscated Files or Information | `ATR-2026-00535`, `ATR-2026-02004`, `ATR-2026-02006`, `ATR-2026-02010`, `ATR-2026-02016`, `ATR-2026-02018` | prompt-injection |
| T1036 | Masquerading | `ATR-2026-00117`, `ATR-2026-00204`, `ATR-2026-00572`, `ATR-2026-01932` | agent-manipulation, privilege-escalation, tool-poisoning |
| T1041 | Exfiltration Over C2 Channel | `ATR-2026-00201`, `ATR-2026-00576`, `ATR-2026-00863` | context-exfiltration, tool-poisoning |
| T1046 | Network Service Discovery | `ATR-2026-01989` | excessive-autonomy |
| T1048 | Exfiltration Over Alternative Protocol | `ATR-2026-01609` | privilege-escalation |
| T1053 | Scheduled Task/Job | `ATR-2026-00107`, `ATR-2026-00204`, `ATR-2026-00441` | privilege-escalation |
| T1059 | Command and Scripting Interpreter | `ATR-2026-00010`, `ATR-2026-00012`, `ATR-2026-00110`, `ATR-2026-00204`, `ATR-2026-00209`, `ATR-2026-00210`, `ATR-2026-00415`, `ATR-2026-00416`, `ATR-2026-00417`, `ATR-2026-00418`, `ATR-2026-00419`, `ATR-2026-00432`, `ATR-2026-00433`, `ATR-2026-00434`, `ATR-2026-00436`, `ATR-2026-00440`, `ATR-2026-00451`, `ATR-2026-00523`, `ATR-2026-00531`, `ATR-2026-00535`, `ATR-2026-00538`, `ATR-2026-00540`, `ATR-2026-00541`, `ATR-2026-00542`, `ATR-2026-00543`, `ATR-2026-00545`, `ATR-2026-00572`, `ATR-2026-00575`, `ATR-2026-01610`, `ATR-2026-01611`, `ATR-2026-01930`, `ATR-2026-01931`, `ATR-2026-01980`, `ATR-2026-01982`, `ATR-2026-01983`, `ATR-2026-01985`, `ATR-2026-01986`, `ATR-2026-01987`, `ATR-2026-02019`, `ATR-2026-02041` | agent-manipulation, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning |
| T1059.003 | Windows Command Shell | `ATR-2026-00537` | tool-poisoning |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `ATR-2026-00111`, `ATR-2026-00532`, `ATR-2026-00536`, `ATR-2026-00863` | context-exfiltration, privilege-escalation, tool-poisoning |
| T1059.006 | Python | `ATR-2026-00432`, `ATR-2026-00440`, `ATR-2026-00539`, `ATR-2026-00544`, `ATR-2026-01935` | agent-manipulation, privilege-escalation, tool-poisoning |
| T1059.007 | JavaScript | `ATR-2026-00415`, `ATR-2026-00436` | privilege-escalation, tool-poisoning |
| T1068 | Exploitation for Privilege Escalation | `ATR-2026-00417`, `ATR-2026-01933`, `ATR-2026-01934`, `ATR-2026-01981` | agent-manipulation, privilege-escalation |
| T1070.004 | Indicator Removal on Host: File Deletion | `ATR-2026-00858` | context-exfiltration |
| T1071 | Application Layer Protocol | `ATR-2026-00010`, `ATR-2026-00013`, `ATR-2026-00212` | context-exfiltration, tool-poisoning |
| T1078 | Valid Accounts | `ATR-2026-00074`, `ATR-2026-00416`, `ATR-2026-00435`, `ATR-2026-00531`, `ATR-2026-00533`, `ATR-2026-00536`, `ATR-2026-00538`, `ATR-2026-00543`, `ATR-2026-01933`, `ATR-2026-01934`, `ATR-2026-01984` | agent-manipulation, context-exfiltration, privilege-escalation, tool-poisoning |
| T1082 | System Information Discovery | `ATR-2026-00115` | context-exfiltration |
| T1083 | File and Directory Discovery | `ATR-2026-00012`, `ATR-2026-00546`, `ATR-2026-01608`, `ATR-2026-01616` | context-exfiltration, privilege-escalation, tool-poisoning |
| T1090 | Proxy | `ATR-2026-00013`, `ATR-2026-00547`, `ATR-2026-01606` | context-exfiltration, privilege-escalation, tool-poisoning |
| T1098.004 | Account Manipulation: SSH Authorized Keys | `ATR-2026-02040` | privilege-escalation |
| T1111 | Multi-Factor Authentication Interception | `ATR-2026-00862` | context-exfiltration |
| T1129 | Shared Modules | `ATR-2026-00112` | privilege-escalation |
| T1190 | Exploit Public-Facing Application | `ATR-2026-00210`, `ATR-2026-00415`, `ATR-2026-00416`, `ATR-2026-00434`, `ATR-2026-00435`, `ATR-2026-00448`, `ATR-2026-00451`, `ATR-2026-00531`, `ATR-2026-00532`, `ATR-2026-00533`, `ATR-2026-00534`, `ATR-2026-00536`, `ATR-2026-00537`, `ATR-2026-00538`, `ATR-2026-00540`, `ATR-2026-00541`, `ATR-2026-00542`, `ATR-2026-00545`, `ATR-2026-01600`, `ATR-2026-01602`, `ATR-2026-01603`, `ATR-2026-01604`, `ATR-2026-01948`, `ATR-2026-01949`, `ATR-2026-01952`, `ATR-2026-01953`, `ATR-2026-01957`, `ATR-2026-01959`, `ATR-2026-01961`, `ATR-2026-01963`, `ATR-2026-01964`, `ATR-2026-01965`, `ATR-2026-01967`, `ATR-2026-01968`, `ATR-2026-01970`, `ATR-2026-01973`, `ATR-2026-01974`, `ATR-2026-01978`, `ATR-2026-01979`, `ATR-2026-01981`, `ATR-2026-01986` | agent-manipulation, context-exfiltration, privilege-escalation, tool-poisoning |
| T1195 | Supply Chain Compromise | `ATR-2026-00060`, `ATR-2026-00418`, `ATR-2026-01930` | agent-manipulation, skill-compromise, tool-poisoning |
| T1195.002 | Compromise Software Supply Chain | `ATR-2026-00419`, `ATR-2026-00433`, `ATR-2026-00523`, `ATR-2026-00524`, `ATR-2026-00572`, `ATR-2026-00575`, `ATR-2026-00576`, `ATR-2026-01932` | context-exfiltration, model-abuse, skill-compromise, tool-poisoning |
| T1204 | User Execution | `ATR-2026-00118` | agent-manipulation |
| T1204.001 | User Execution: Malicious Link | `ATR-2026-01968` | tool-poisoning |
| T1485 | Data Destruction | `ATR-2026-00858`, `ATR-2026-01601` | context-exfiltration, privilege-escalation |
| T1499 | Endpoint Denial of Service | `ATR-2026-00209` | tool-poisoning |
| T1528 | Steal Application Access Token | `ATR-2026-00114` | context-exfiltration |
| T1530 | Data from Cloud Storage Object | `ATR-2026-00449` | context-exfiltration |
| T1539 | Steal Web Session Cookie | `ATR-2026-00524` | context-exfiltration |
| T1543 | Create or Modify System Process | `ATR-2026-00204` | privilege-escalation |
| T1546 | Event Triggered Execution | `ATR-2026-00418`, `ATR-2026-00419`, `ATR-2026-00450`, `ATR-2026-00523`, `ATR-2026-00572`, `ATR-2026-00575` | agent-manipulation, data-poisoning, skill-compromise, tool-poisoning |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | `ATR-2026-02040` | privilege-escalation |
| T1546.016 | Boot or Logon Autostart Execution: .pth Files | `ATR-2026-00544` | tool-poisoning |
| T1547 | Boot or Logon Autostart Execution | `ATR-2026-00441` | privilege-escalation |
| T1547.001 | Registry Run Keys / Startup Folder | `ATR-2026-00441` | privilege-escalation |
| T1548 | Abuse Elevation Control Mechanism | `ATR-2026-00040` | privilege-escalation |
| T1550 | Use Alternate Authentication Material | `ATR-2026-00074` | agent-manipulation |
| T1552 | Unsecured Credentials | `ATR-2026-00212`, `ATR-2026-00431`, `ATR-2026-00524`, `ATR-2026-00534`, `ATR-2026-00546`, `ATR-2026-01931`, `ATR-2026-02002`, `ATR-2026-02007`, `ATR-2026-02017` | context-exfiltration, privilege-escalation, prompt-injection, tool-poisoning |
| T1552.001 | Credentials In Files | `ATR-2026-00113`, `ATR-2026-00201`, `ATR-2026-00524`, `ATR-2026-00576`, `ATR-2026-00863` | context-exfiltration, tool-poisoning |
| T1552.005 | Cloud Instance Metadata API | `ATR-2026-00547`, `ATR-2026-01605`, `ATR-2026-01607` | context-exfiltration, privilege-escalation |
| T1553 | Subvert Trust Controls | `ATR-2026-00539` | privilege-escalation |
| T1556 | Modify Authentication Process | `ATR-2026-01992` | privilege-escalation |
| T1557 | Adversary-in-the-Middle | `ATR-2026-00116` | agent-manipulation |
| T1562 | Impair Defenses | `ATR-2026-01993`, `ATR-2026-02001`, `ATR-2026-02013` | excessive-autonomy, prompt-injection |
| T1565 | Data Manipulation | `ATR-2026-00070`, `ATR-2026-00450`, `ATR-2026-02003` | data-poisoning, prompt-injection |
| T1565.001 | Data Manipulation: Stored Data Manipulation | `ATR-2026-00075`, `ATR-2026-00200`, `ATR-2026-01155` | context-exfiltration, data-poisoning, skill-compromise |
| T1566 | Phishing | `ATR-2026-00119`, `ATR-2026-00420` | agent-manipulation, prompt-injection |
| T1567 | Exfiltration Over Web Service | `ATR-2026-00420` | prompt-injection |
| T1573 | Encrypted Channel | `ATR-2026-01994` | excessive-autonomy |
| T1611 | Escape to Host | `ATR-2026-00040`, `ATR-2026-00436`, `ATR-2026-00441`, `ATR-2026-00539`, `ATR-2026-01615` | privilege-escalation |
| T1622 | Debugger Evasion | `ATR-2026-02005` | prompt-injection |
| T1657 | Financial Theft | `ATR-2026-00860`, `ATR-2026-00861` | context-exfiltration |

## Crosswalk by ATR category

For each ATR category: the enterprise ATT&CK techniques its rules reference
(the shared join key), plus the ATLAS and OWASP Agentic techniques ATR adds.

### agent-manipulation

Rules in category: 106

ATT&CK techniques (join key):

| ATT&CK technique | Name | ATR rules |
|---|---|---|
| T1036 | Masquerading | `ATR-2026-00117` |
| T1059 | Command and Scripting Interpreter | `ATR-2026-00416`, `ATR-2026-00417`, `ATR-2026-00418`, `ATR-2026-00432`, `ATR-2026-00440` |
| T1059.006 | Python | `ATR-2026-00432`, `ATR-2026-00440` |
| T1068 | Exploitation for Privilege Escalation | `ATR-2026-00417` |
| T1078 | Valid Accounts | `ATR-2026-00074`, `ATR-2026-00416` |
| T1190 | Exploit Public-Facing Application | `ATR-2026-00416` |
| T1195 | Supply Chain Compromise | `ATR-2026-00418` |
| T1204 | User Execution | `ATR-2026-00118` |
| T1546 | Event Triggered Execution | `ATR-2026-00418` |
| T1550 | Use Alternate Authentication Material | `ATR-2026-00074` |
| T1557 | Adversary-in-the-Middle | `ATR-2026-00116` |
| T1566 | Phishing | `ATR-2026-00119` |

ATLAS techniques ATR adds: AML.T0010, AML.T0040, AML.T0043, AML.T0048, AML.T0049, AML.T0050, AML.T0051, AML.T0051.000, AML.T0051.001, AML.T0052.000, AML.T0054

OWASP Agentic categories ATR adds: ASI01:2026, ASI02:2026, ASI03:2026, ASI04:2026, ASI05:2026, ASI06:2026, ASI07:2026, ASI09:2026, ASI10:2026

### context-exfiltration

Rules in category: 112

ATT&CK techniques (join key):

| ATT&CK technique | Name | ATR rules |
|---|---|---|
| T1005 | Data from Local System | `ATR-2026-01988` |
| T1041 | Exfiltration Over C2 Channel | `ATR-2026-00201`, `ATR-2026-00863` |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `ATR-2026-00863` |
| T1070.004 | Indicator Removal on Host: File Deletion | `ATR-2026-00858` |
| T1071 | Application Layer Protocol | `ATR-2026-00212` |
| T1078 | Valid Accounts | `ATR-2026-01984` |
| T1082 | System Information Discovery | `ATR-2026-00115` |
| T1083 | File and Directory Discovery | `ATR-2026-01608` |
| T1090 | Proxy | `ATR-2026-01606` |
| T1111 | Multi-Factor Authentication Interception | `ATR-2026-00862` |
| T1190 | Exploit Public-Facing Application | `ATR-2026-01948`, `ATR-2026-01957`, `ATR-2026-01961`, `ATR-2026-01964` |
| T1195.002 | Compromise Software Supply Chain | `ATR-2026-00524` |
| T1485 | Data Destruction | `ATR-2026-00858` |
| T1528 | Steal Application Access Token | `ATR-2026-00114` |
| T1530 | Data from Cloud Storage Object | `ATR-2026-00449` |
| T1539 | Steal Web Session Cookie | `ATR-2026-00524` |
| T1552 | Unsecured Credentials | `ATR-2026-00212`, `ATR-2026-00431`, `ATR-2026-00524`, `ATR-2026-02017` |
| T1552.001 | Credentials In Files | `ATR-2026-00113`, `ATR-2026-00201`, `ATR-2026-00524`, `ATR-2026-00863` |
| T1552.005 | Cloud Instance Metadata API | `ATR-2026-01605`, `ATR-2026-01607` |
| T1565.001 | Data Manipulation: Stored Data Manipulation | `ATR-2026-00075` |
| T1657 | Financial Theft | `ATR-2026-00860`, `ATR-2026-00861` |

ATLAS techniques ATR adds: AML.CS0036, AML.T0010, AML.T0024, AML.T0025, AML.T0040, AML.T0043, AML.T0048, AML.T0049, AML.T0051, AML.T0051.001, AML.T0053, AML.T0054, AML.T0055, AML.T0056, AML.T0057, AML.T0069, AML.T0080, AML.T0088

OWASP Agentic categories ATR adds: ASI01:2026, ASI02:2026, ASI03:2026, ASI04:2026, ASI05:2026, ASI06:2026, ASI07:2026, ASI08:2026, ASI09:2026

### data-poisoning

Rules in category: 6

ATT&CK techniques (join key):

| ATT&CK technique | Name | ATR rules |
|---|---|---|
| T1546 | Event Triggered Execution | `ATR-2026-00450` |
| T1565 | Data Manipulation | `ATR-2026-00070`, `ATR-2026-00450` |
| T1565.001 | Data Manipulation: Stored Data Manipulation | `ATR-2026-01155` |

ATLAS techniques ATR adds: AML.T0018.000, AML.T0020, AML.T0051, AML.T0051.001, AML.T0070

OWASP Agentic categories ATR adds: ASI01:2026, ASI04:2026, ASI06:2026

### excessive-autonomy

Rules in category: 33

ATT&CK techniques (join key):

| ATT&CK technique | Name | ATR rules |
|---|---|---|
| T1046 | Network Service Discovery | `ATR-2026-01989` |
| T1562 | Impair Defenses | `ATR-2026-01993` |
| T1573 | Encrypted Channel | `ATR-2026-01994` |

ATLAS techniques ATR adds: AML.T0011, AML.T0011.001, AML.T0034, AML.T0044, AML.T0046, AML.T0050, AML.T0051, AML.T0051.001, AML.T0053, AML.T0057

OWASP Agentic categories ATR adds: ASI01:2026, ASI02:2026, ASI03:2026, ASI04:2026, ASI05:2026, ASI06:2026, ASI07:2026, ASI08:2026, ASI09:2026, ASI10:2026

### model-abuse

Rules in category: 39

ATT&CK techniques (join key):

| ATT&CK technique | Name | ATR rules |
|---|---|---|
| T1059 | Command and Scripting Interpreter | `ATR-2026-00433` |
| T1195.002 | Compromise Software Supply Chain | `ATR-2026-00433` |

ATLAS techniques ATR adds: AML.T0010, AML.T0011.000, AML.T0024, AML.T0040, AML.T0044, AML.T0046, AML.T0048, AML.T0051, AML.T0057, AML.T0102

OWASP Agentic categories ATR adds: ASI01:2026, ASI04:2026, ASI05:2026, ASI08:2026

### privilege-escalation

Rules in category: 45

ATT&CK techniques (join key):

| ATT&CK technique | Name | ATR rules |
|---|---|---|
| T1036 | Masquerading | `ATR-2026-00204` |
| T1048 | Exfiltration Over Alternative Protocol | `ATR-2026-01609` |
| T1053 | Scheduled Task/Job | `ATR-2026-00107`, `ATR-2026-00204`, `ATR-2026-00441` |
| T1059 | Command and Scripting Interpreter | `ATR-2026-00110`, `ATR-2026-00204`, `ATR-2026-00436`, `ATR-2026-00451`, `ATR-2026-01610`, `ATR-2026-01611`, `ATR-2026-01986` |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `ATR-2026-00111` |
| T1059.006 | Python | `ATR-2026-00539` |
| T1059.007 | JavaScript | `ATR-2026-00436` |
| T1068 | Exploitation for Privilege Escalation | `ATR-2026-01933`, `ATR-2026-01934`, `ATR-2026-01981` |
| T1078 | Valid Accounts | `ATR-2026-01933`, `ATR-2026-01934` |
| T1083 | File and Directory Discovery | `ATR-2026-00546`, `ATR-2026-01616` |
| T1090 | Proxy | `ATR-2026-00547` |
| T1098.004 | Account Manipulation: SSH Authorized Keys | `ATR-2026-02040` |
| T1129 | Shared Modules | `ATR-2026-00112` |
| T1190 | Exploit Public-Facing Application | `ATR-2026-00451`, `ATR-2026-01600`, `ATR-2026-01602`, `ATR-2026-01603`, `ATR-2026-01604`, `ATR-2026-01949`, `ATR-2026-01974`, `ATR-2026-01981`, `ATR-2026-01986` |
| T1485 | Data Destruction | `ATR-2026-01601` |
| T1543 | Create or Modify System Process | `ATR-2026-00204` |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | `ATR-2026-02040` |
| T1547 | Boot or Logon Autostart Execution | `ATR-2026-00441` |
| T1547.001 | Registry Run Keys / Startup Folder | `ATR-2026-00441` |
| T1548 | Abuse Elevation Control Mechanism | `ATR-2026-00040` |
| T1552 | Unsecured Credentials | `ATR-2026-00546` |
| T1552.005 | Cloud Instance Metadata API | `ATR-2026-00547` |
| T1553 | Subvert Trust Controls | `ATR-2026-00539` |
| T1556 | Modify Authentication Process | `ATR-2026-01992` |
| T1611 | Escape to Host | `ATR-2026-00040`, `ATR-2026-00436`, `ATR-2026-00441`, `ATR-2026-00539`, `ATR-2026-01615` |

ATLAS techniques ATR adds: AML.T0024, AML.T0040, AML.T0043, AML.T0047, AML.T0049, AML.T0050, AML.T0051, AML.T0053, AML.T0054, AML.T0080, AML.T0105

OWASP Agentic categories ATR adds: ASI01:2026, ASI02:2026, ASI03:2026, ASI04:2026, ASI05:2026, ASI06:2026, ASI07:2026

### prompt-injection

Rules in category: 238

ATT&CK techniques (join key):

| ATT&CK technique | Name | ATR rules |
|---|---|---|
| T1027 | Obfuscated Files or Information | `ATR-2026-00535`, `ATR-2026-02004`, `ATR-2026-02006`, `ATR-2026-02010`, `ATR-2026-02016`, `ATR-2026-02018` |
| T1059 | Command and Scripting Interpreter | `ATR-2026-00535`, `ATR-2026-02019` |
| T1552 | Unsecured Credentials | `ATR-2026-02002`, `ATR-2026-02007` |
| T1562 | Impair Defenses | `ATR-2026-02001`, `ATR-2026-02013` |
| T1565 | Data Manipulation | `ATR-2026-02003` |
| T1566 | Phishing | `ATR-2026-00420` |
| T1567 | Exfiltration Over Web Service | `ATR-2026-00420` |
| T1622 | Debugger Evasion | `ATR-2026-02005` |

ATLAS techniques ATR adds: AML.CS0038, AML.T0010, AML.T0025, AML.T0036, AML.T0040, AML.T0043, AML.T0048, AML.T0050, AML.T0051, AML.T0051.000, AML.T0051.001, AML.T0054, AML.T0057

OWASP Agentic categories ATR adds: ASI01:2026, ASI03:2026, ASI04:2026, ASI05:2026, ASI06:2026, ASI07:2026, ASI08:2026, ASI09:2026, ASI10:2026

### skill-compromise

Rules in category: 41

ATT&CK techniques (join key):

| ATT&CK technique | Name | ATR rules |
|---|---|---|
| T1059 | Command and Scripting Interpreter | `ATR-2026-00523` |
| T1195 | Supply Chain Compromise | `ATR-2026-00060` |
| T1195.002 | Compromise Software Supply Chain | `ATR-2026-00523` |
| T1546 | Event Triggered Execution | `ATR-2026-00523` |
| T1565.001 | Data Manipulation: Stored Data Manipulation | `ATR-2026-00200` |

ATLAS techniques ATR adds: AML.T0010, AML.T0011.000, AML.T0018.000, AML.T0020, AML.T0024, AML.T0040, AML.T0044, AML.T0048, AML.T0050, AML.T0051, AML.T0051.001, AML.T0053, AML.T0057, AML.T0060, AML.T0080, AML.T0104, AML.T0109

OWASP Agentic categories ATR adds: ASI01:2026, ASI02:2026, ASI03:2026, ASI04:2026, ASI05:2026, ASI06:2026, ASI07:2026, ASI08:2026, ASI09:2026

### tool-poisoning

Rules in category: 96

ATT&CK techniques (join key):

| ATT&CK technique | Name | ATR rules |
|---|---|---|
| T1036 | Masquerading | `ATR-2026-00572`, `ATR-2026-01932` |
| T1041 | Exfiltration Over C2 Channel | `ATR-2026-00576` |
| T1059 | Command and Scripting Interpreter | `ATR-2026-00010`, `ATR-2026-00012`, `ATR-2026-00209`, `ATR-2026-00210`, `ATR-2026-00415`, `ATR-2026-00419`, `ATR-2026-00434`, `ATR-2026-00531`, `ATR-2026-00538`, `ATR-2026-00540`, `ATR-2026-00541`, `ATR-2026-00542`, `ATR-2026-00543`, `ATR-2026-00545`, `ATR-2026-00572`, `ATR-2026-00575`, `ATR-2026-01930`, `ATR-2026-01931`, `ATR-2026-01980`, `ATR-2026-01982`, `ATR-2026-01983`, `ATR-2026-01985`, `ATR-2026-01987`, `ATR-2026-02041` |
| T1059.003 | Windows Command Shell | `ATR-2026-00537` |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `ATR-2026-00532`, `ATR-2026-00536` |
| T1059.006 | Python | `ATR-2026-00544`, `ATR-2026-01935` |
| T1059.007 | JavaScript | `ATR-2026-00415` |
| T1071 | Application Layer Protocol | `ATR-2026-00010`, `ATR-2026-00013` |
| T1078 | Valid Accounts | `ATR-2026-00435`, `ATR-2026-00531`, `ATR-2026-00533`, `ATR-2026-00536`, `ATR-2026-00538`, `ATR-2026-00543` |
| T1083 | File and Directory Discovery | `ATR-2026-00012` |
| T1090 | Proxy | `ATR-2026-00013` |
| T1190 | Exploit Public-Facing Application | `ATR-2026-00210`, `ATR-2026-00415`, `ATR-2026-00434`, `ATR-2026-00435`, `ATR-2026-00448`, `ATR-2026-00531`, `ATR-2026-00532`, `ATR-2026-00533`, `ATR-2026-00534`, `ATR-2026-00536`, `ATR-2026-00537`, `ATR-2026-00538`, `ATR-2026-00540`, `ATR-2026-00541`, `ATR-2026-00542`, `ATR-2026-00545`, `ATR-2026-01952`, `ATR-2026-01953`, `ATR-2026-01959`, `ATR-2026-01963`, `ATR-2026-01965`, `ATR-2026-01967`, `ATR-2026-01968`, `ATR-2026-01970`, `ATR-2026-01973`, `ATR-2026-01978`, `ATR-2026-01979` |
| T1195 | Supply Chain Compromise | `ATR-2026-01930` |
| T1195.002 | Compromise Software Supply Chain | `ATR-2026-00419`, `ATR-2026-00572`, `ATR-2026-00575`, `ATR-2026-00576`, `ATR-2026-01932` |
| T1204.001 | User Execution: Malicious Link | `ATR-2026-01968` |
| T1499 | Endpoint Denial of Service | `ATR-2026-00209` |
| T1546 | Event Triggered Execution | `ATR-2026-00419`, `ATR-2026-00572`, `ATR-2026-00575` |
| T1546.016 | Boot or Logon Autostart Execution: .pth Files | `ATR-2026-00544` |
| T1552 | Unsecured Credentials | `ATR-2026-00534`, `ATR-2026-01931` |
| T1552.001 | Credentials In Files | `ATR-2026-00576` |

ATLAS techniques ATR adds: AML.T0010, AML.T0019, AML.T0024, AML.T0040, AML.T0049, AML.T0051, AML.T0051.001, AML.T0053, AML.T0056, AML.T0057, AML.T0069, AML.T0070, AML.T0104, AML.T0110

OWASP Agentic categories ATR adds: ASI01:2026, ASI02:2026, ASI03:2026, ASI04:2026, ASI05:2026, ASI06:2026, ASI07:2026, ASI08:2026, ASI09:2026

## Methodology

- Source of truth: the YAML rule files under `rules/`. Each rule's
  `references` block carries `mitre_attack`, `mitre_atlas`, and
  `owasp_agentic` lists in `Txxxx - Name` form.
- The generator (`scripts/generate-attack-crosswalk.py`) parses every rule,
  takes the leading id token from each entry, and classifies it: `T1xxx`
  (optionally `.NNN`) is enterprise ATT&CK; `AML.Txxxx` or short-form
  `T00xx` is ATLAS.
- The ATT&CK column is fully auto-derivable and is what an ATT&CK-tagged
  ruleset joins against. ATLAS and OWASP Agentic columns are likewise
  extracted from metadata, not hand-authored.
- All counts above are computed by the generator at build time; none are
  hard-coded. Re-run the script to refresh after rule changes.
- License: ATR is MIT. This crosswalk may be reused under the same terms.

