# ATR → OWASP Agentic Skills Top 10 (AST10) Mapping

Last updated: 2026-07-12 (corpus re-stamp v3.5.2->v3.5.8)
ATR corpus: v3.5.8, 793 rules (10 categories, including skill-compromise)
OWASP framework: Agentic Skills Top 10 (AST10), March 2026

> Coverage note: the per-category ATR rule citations below were last fully
> enumerated against the 113-rule v2.0.0 corpus. Category coverage is monotonic —
> adding rules can only maintain or increase it — so the current 462-rule corpus
> covers at least the 7/10 categories shown (a conservative lower bound; the other
> 3 are process/meta-level, not pattern-detectable). A full re-enumeration is pending.

## Background

OWASP AST10 is a separate framework from the Agentic Top 10 (ASI01-ASI10). ASI focuses on
**agent runtime threats** (prompt injection, tool misuse, privilege escalation). AST focuses
on **skill supply chain threats** (malicious skills, over-privileged packages, update drift).

ATR now covers both frameworks:
- OWASP Agentic Top 10 (ASI): 10/10 categories → see `docs/OWASP-MAPPING.md`
- OWASP Agentic Skills Top 10 (AST): see below

## Coverage Summary

| OWASP AST Category | Severity | ATR Rules | Status |
|---|---|---|---|
| AST01: Malicious Skills | CRITICAL | 7 rules | STRONG |
| AST02: Supply Chain Compromise | CRITICAL | 8 rules | STRONG |
| AST03: Over-Privileged Skills | HIGH | 4 rules | MODERATE |
| AST04: Insecure Metadata | HIGH | 3 rules | MODERATE |
| AST05: Unsafe Deserialization | HIGH | 3 rules | MODERATE |
| AST06: Weak Isolation | HIGH | 3 rules | PARTIAL |
| AST07: Update Drift | MEDIUM | 2 rules | PARTIAL |
| AST08: Poor Scanning | MEDIUM | 0 rules | GAP (meta-concern) |
| AST09: No Governance | MEDIUM | 0 rules | GAP (process-level) |
| AST10: Cross-Platform Reuse | MEDIUM | 1 rule | PARTIAL |

**Overall: 7/10 categories with rule coverage. 3 categories are process/meta-level (not detectable by pattern rules).**

Note: AST08 (Poor Scanning) is a critique of scanner quality — ATR itself is the mitigation.
AST09 (No Governance) is an organizational process gap — not a pattern detection target.

---

## Detailed Mapping

### AST01: Malicious Skills (CRITICAL) — STRONG

Skills containing malicious payloads: credential theft, infostealers, reverse shells,
ransomware, persistence mechanisms. Real campaigns: ClawHavoc (1,184 skills, C2 91.92.242.30),
AMOS infostealer (314 skills from hightower6eu), MedusaLocker PoC (Cato Networks).

| ATR Rule | Title | Severity | What it detects |
|---|---|---|---|
| ATR-2026-120 | SKILL.md Prompt Injection | CRITICAL | DAN jailbreaks, instruction override, system impersonation, HTML comment injection, Unicode smuggling |
| ATR-2026-121 | Malicious Code in Skill Package | CRITICAL | Base64 payloads, password-protected ZIP evasion, curl\|bash, credential file access, reverse shells, persistence |
| ATR-2026-122 | Weaponized Skill | HIGH | SQLMap, Metasploit, brute-force tools, ransomware patterns |
| ATR-2026-111 | Shell Metacharacter Injection | CRITICAL | Shell escape sequences in tool arguments |
| ATR-2026-113 | Credential File Theft | CRITICAL | Access to .aws, .ssh, .env, openclaw.json |
| ATR-2026-110 | Eval Injection | CRITICAL | eval() and dynamic code execution |
| ATR-2026-095 | Supply Chain Poisoning | CRITICAL | Poisoned tool descriptions and responses |

### AST02: Supply Chain Compromise (CRITICAL) — STRONG

Compromised dependencies, hijacked repos, silent API key exfiltration at project-open.
CVE-2026-25253 (CVSS 8.8), CVE-2025-59536 (CVSS 8.7), CVE-2026-28363 (CVSS 9.9 ClawJacked).

| ATR Rule | Title | Severity | What it detects |
|---|---|---|---|
| ATR-2026-060 | Skill Impersonation | CRITICAL | Typosquatting of known skills |
| ATR-2026-061 | Description-Behavior Mismatch | HIGH | Skill does something different from what it claims |
| ATR-2026-062 | Hidden Capability | HIGH | Undisclosed dangerous capabilities |
| ATR-2026-065 | Skill Update Attack | HIGH | Malicious updates to previously safe skills |
| ATR-2026-066 | Parameter Injection | HIGH | Hidden parameters in tool schemas |
| ATR-2026-089 | Polymorphic Skill | HIGH | Skills that change behavior to evade detection |
| ATR-2026-095 | Supply Chain Poisoning | CRITICAL | Poisoned components in supply chain |
| ATR-2026-124 | Skill Name Squatting | HIGH | Fake brand claims, crypto-themed name patterns |

### AST03: Over-Privileged Skills (HIGH) — MODERATE

Skills requesting permissions far exceeding their stated function. 280+ leaky skills found
by Snyk. "Consent gap" (Cato Networks): once approved, skills gain persistent permissions.

| ATR Rule | Title | Severity | What it detects |
|---|---|---|---|
| ATR-2026-064 | Over-Permissioned MCP Skill | HIGH | sudo, chmod, user creation, service management |
| ATR-2026-123 | Over-Privileged Skill (AST) | HIGH | Bash(*), autoApprove, safety disablement, identity file writes |
| ATR-2026-041 | Scope Creep | HIGH | Operations beyond declared scope |
| ATR-2026-118 | Approval Fatigue Exploitation | MEDIUM | Exploiting repetitive approval prompts |

### AST04: Insecure Metadata (HIGH) — MODERATE

Typosquatting, fake brand impersonation, understated risk_tier masking destructive capability.

| ATR Rule | Title | Severity | What it detects |
|---|---|---|---|
| ATR-2026-124 | Skill Name Squatting | HIGH | Fake official claims, brand impersonation, crypto-themed names |
| ATR-2026-060 | Skill Impersonation | CRITICAL | Name similarity to known tools |
| ATR-2026-106 | Schema-Description Contradiction | MEDIUM | Metadata inconsistencies |

### AST05: Unsafe Deserialization (HIGH) — MODERATE

YAML deserialization attacks, "From SKILL.md to Shell Access in Three Lines of Markdown" (Snyk).

| ATR Rule | Title | Severity | What it detects |
|---|---|---|---|
| ATR-2026-120 | SKILL.md Prompt Injection | CRITICAL | Injection via SKILL.md markdown body |
| ATR-2026-121 | Malicious Code in Skill Package | CRITICAL | Code execution triggered by skill loading |
| ATR-2026-110 | Eval Injection | CRITICAL | Dynamic code evaluation |

### AST06: Weak Isolation (HIGH) — PARTIAL

135,000+ OpenClaw instances publicly exposed. No sandboxing by default.
Microsoft Defender advisory: "treat as untrusted code execution."

| ATR Rule | Title | Severity | What it detects |
|---|---|---|---|
| ATR-2026-123 | Over-Privileged Skill | HIGH | Safety disablement, sandbox bypass instructions |
| ATR-2026-040 | Privilege Escalation | CRITICAL | Escalation beyond intended scope |
| ATR-2026-107 | Delayed Execution Bypass | HIGH | Deferred execution to avoid detection |

**Gap:** ATR detects symptoms of weak isolation (privilege escalation attempts) but cannot enforce isolation itself. Isolation is a platform responsibility.

### AST07: Update Drift (MEDIUM) — PARTIAL

Version range specs (~1.0.0, ^1.0.0) allow auto-install of compromised patches.

| ATR Rule | Title | Severity | What it detects |
|---|---|---|---|
| ATR-2026-065 | Skill Update Attack | HIGH | Malicious version updates |
| ATR-2026-089 | Polymorphic Skill | HIGH | Behavior changes across versions |

**Gap:** ATR cannot detect version pinning policies or range spec issues. This requires registry-level enforcement.

### AST08: Poor Scanning (MEDIUM) — GAP (meta-concern)

"Pattern-matching scanners miss semantic attacks" — this is a critique of scanner quality.
ATR itself is a scanning tool, so this category is a quality target, not a detection target.

**Mitigation:** ATR addresses this by using multiple detection tiers (pattern matching +
behavioral analysis + LLM review via Threat Cloud). The Snyk critique applies to regex-only
scanners; ATR's multi-tier approach partially addresses semantic attack gaps.

### AST09: No Governance (MEDIUM) — GAP (process-level)

No centralized skill inventory, no approval workflow, no audit logging.

**Mitigation:** This is an organizational process gap. Runtime monitoring tools provide
audit logging. Threat Cloud provides centralized rule management.
ATR rules cannot enforce governance policies.

### AST10: Cross-Platform Reuse (MEDIUM) — PARTIAL

Malicious skills ported from ClawHub to skills.sh with minimal modification.

| ATR Rule | Title | Severity | What it detects |
|---|---|---|---|
| ATR-2026-121 | Malicious Code in Skill Package | CRITICAL | Platform-agnostic malicious code patterns |

**Gap:** ATR cannot detect cross-platform porting itself. The same malicious patterns are
detected regardless of platform, but ATR doesn't track skill provenance across registries.

---

## Key Research References

| Source | Date | Key Finding |
|---|---|---|
| Snyk ToxicSkills | Feb 2026 | 3,984 skills scanned, 36.82% flawed, 76 confirmed malicious |
| arXiv 2601.17548 | Jan 2026 | 85%+ attack success rate, 3-dimensional taxonomy |
| Cato Networks | Dec 2025 | MedusaLocker ransomware via Claude skill PoC |
| VirusTotal | Feb 2026 | 314 AMOS infostealer skills from hightower6eu |
| OWASP AST10 | Mar 2026 | Agentic Skills Top 10 framework |
| Mobb.ai | Mar 2026 | 22,511 skills, 140,963 findings |
| Aikido | 2026 | Slopsquatting: 19.7% hallucinated package names |

## CVEs Referenced

| CVE | CVSS | Product | Impact |
|---|---|---|---|
| CVE-2026-25253 | 8.8 | OpenClaw | RCE via auth token exfiltration |
| CVE-2026-28363 | 9.9 | OpenClaw | ClawJacked: WebSocket brute-force hijack |
| CVE-2025-59536 | 8.7 | OpenClaw | Silent API key exfiltration |
| CVE-2025-53773 | — | VS Code Copilot | Auto-approve escalation |
| CVE-2025-49150 | — | Cursor | RCE via MCP |

---

## Version History

| Date | ATR Version | Total Rules | AST Coverage |
|---|---|---|---|
| 2026-03-29 | v0.4.0+ | 76 | 7/10 (3 GAP/meta) |
