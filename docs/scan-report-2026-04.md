# 53,577 AI Agent Skills Scanned. 946 Are Malicious.

> **ERRATUM (added 2026-09-22).** This is a dated historical artifact, preserved as
> published. Figures quoted below have since been withdrawn or frozen and must not be
> cited as current fact:
>
> - **Ecosystem / wild scan.** The "96,096 skills scanned" and "751 confirmed malware"
>   figures are frozen. The only externally citable wild-scan figures are
>   **101,280 items scanned / 1,434 flagged** (engine v2.0.0, as of 2026-04-13). See
>   `docs/research/wild-scan-drift.md`, which also explains why the confirmed-malicious
>   count is a triage floor and not a precision figure.
> - **Precision / false-positive rate.** "99.7% precision" and the paired "0.3% FP rate"
>   were withdrawn on 2026-06-15 and should not be cited by anyone, including this
>   project. The per-lane FP rates published afterwards were withdrawn as well. Current
>   version-pinned measurements live in README section 8 and `data/stats.json`.
> - **Downstream adoption.** A merged pull request into an open-source repository such as
>   `cisco-ai-defense/skill-scanner` is not a vendor product shipment or endorsement.
>   `ADOPTERS.md` is the source of truth, with per-entry PR evidence.
>
> Rule counts, version numbers and adopter lists below are point-in-time and have moved.
> Nothing below has been rewritten; this note is the correction of record.

**April 2026** | ATR v1.1.1 | 108 detection rules

We scanned every MCP skill on OpenClaw (50,485) and Skills.sh (3,115) — the two largest public AI agent skill registries. 946 skills contain malicious code, credential theft, reverse shells, or prompt injection payloads. Most are still live.

## Numbers

| Metric | Value |
|--------|-------|
| Skills scanned | 53,577 |
| Clean | 52,631 (98.2%) |
| Malicious | 946 (1.77%) |
| CRITICAL severity | 875 |
| HIGH severity | 52 |
| MEDIUM severity | 19 |
| Scan time | 3.4 minutes |
| False positive rate | 0% on clean corpus |

## What we found

**#1 threat: malicious code in skill packages (674 hits)**

ATR-2026-00121 triggered 674 times — base64-obfuscated payloads, curl-pipe-to-shell from raw IPs, password-protected ZIP evasion, and paste service relays. These are the same patterns seen in the ClawHavoc campaign (1,184 malicious skills) and Snyk's ToxicSkills report.

**#2: instruction injection in SKILL.md (81 hits)**

ATR-2026-00120 caught 81 skills with hidden instructions embedded in their SKILL.md files — `[SYSTEM]` overrides, base64-encoded directives in HTML comments, and invisible unicode sequences.

**#3: compound exfiltration patterns (76 hits)**

ATR-2026-00149 detected 76 skills combining credential file access with external transmission — SSH key archival, browser cookie database extraction, DNS exfiltration, and cloud metadata (IMDS) access.

## Top rules fired

| Rule | Hits | What it detects |
|------|------|-----------------|
| ATR-2026-00121 | 674 | Malicious code (base64 exec, curl\|bash, reverse shell) |
| ATR-2026-00120 | 81 | Instruction injection in SKILL.md |
| ATR-2026-00149 | 76 | Compound exfiltration (SSH + upload, cookies + POST) |
| ATR-2026-00135 | 55 | Exfiltration URL in instructions |
| ATR-2026-00124 | 41 | Skill name squatting / typosquatting |
| ATR-2026-00122 | 27 | Weaponized skill instructions |
| ATR-2026-00127 | 18 | Subcommand overflow bypass |
| ATR-2026-00126 | 12 | Rug pull setup (time-delayed payload) |
| ATR-2026-00128 | 9 | Hidden payload in HTML comments |
| ATR-2026-00129 | 3 | Unicode smuggling |

## Protect your CI/CD in 30 seconds

```yaml
# .github/workflows/atr-scan.yml
name: ATR Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Agent-Threat-Rule/agent-threat-rules@v1
```

Results appear in your GitHub Security tab. 108 rules. Zero configuration.

## CLI

```bash
npm install -g agent-threat-rules
atr scan ./my-skills/
atr scan my-mcp-config.json --sarif --output results.sarif
```

## Methodology

- Engine: ATR v1.1.1 (108 rules, regex-based pattern matching)
- Sources: OpenClaw skills repo (50,485 SKILL.md files) + Skills.sh registry (3,115 SKILL.md files)
- Scan date: April 8, 2026
- Validation: 824/824 embedded test cases pass, 0% FP on 498 labeled benchmark samples (96.9% recall)
- Same rules merged upstream into the open-source `cisco-ai-defense/skill-scanner` repository ([PR #79](https://github.com/cisco-ai-defense/skill-scanner/pull/79)). This is a repository merge, not a shipment in a Cisco commercial product.

## Full data

- [mega-scan-report.json](../data/mega-scan-report.json) — complete scan results
- [Paper (Zenodo)](https://doi.org/10.5281/zenodo.19178002)
- [ATR Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
- [Website](https://agentthreatrule.org)
