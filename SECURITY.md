# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ATR rules, the evaluation engine,
or any component of this project, please report it privately. Do not open a
public issue for an unfixed vulnerability.

Preferred: a [GitHub Security Advisory](https://github.com/Agent-Threat-Rule/agent-threat-rules/security/advisories/new).
Private vulnerability reporting is enabled on this repository (verified by API on
2026-09-22), so this keeps the whole exchange private and inside GitHub, and it
cannot be lost to a mail routing problem.

**Email: adam@agentthreatrule.org**

Use this if you would rather not report through GitHub, or if the "Report a
vulnerability" button is not visible to you. This address was confirmed to
receive mail on 2026-09-22. Mail is unencrypted — no PGP key is published. If
the report is sensitive enough that this matters, send a first message with no
vulnerability details and ask for an encrypted channel.

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Affected rule IDs (if applicable)
- Potential impact assessment

**What to expect:**
- Acknowledgment within 3 business days
- A first assessment — reproduced or not, and a rough remediation shape —
  within 10 business days
- Credit in the advisory (unless you prefer anonymity)

These windows are set to be met rather than aspired to. If 10 business days pass
with no response at all, escalate to the maintainer directly at
adam@agentthreatrule.org — silence is a failure of this process, not a decision
about your report.

## Supported Versions

Security fixes land on `main` and ship in the next release. There are no
long-term-support branches and no backports to earlier majors: **only the
current `latest` release on npm is supported.**

Check which version that is before reporting anything version-specific:

```bash
npm view agent-threat-rules dist-tags
```

As of 2026-09-22 the published `latest` is **4.0.0**, while this repository is
tagged **v4.1.0** — 4.1.0 was never published to npm (see
[CHANGELOG.md](CHANGELOG.md)). So if you installed from npm you are running
4.0.0, and if you installed from git you are ahead of every published release.
Please say which of the two you are on when you report.

## Scope

The following are in scope for security reports:

- **False negatives**: Rules that fail to detect known attack patterns
- **Regex ReDoS**: Patterns vulnerable to catastrophic backtracking
- **Engine bypass**: Ways to evade detection by the ATR engine
- **Schema injection**: Malformed YAML that causes unexpected behavior
- **Test case gaps**: Missing coverage for known CVEs or attack techniques

## Out of Scope

- Theoretical attacks not reproducible against the reference engine
- Rules marked as `draft` status (known to be incomplete)
- Feature requests (use GitHub Issues instead)

## Disclosure Policy

We follow coordinated disclosure. Please allow 90 days for remediation
before public disclosure. We will coordinate with you on timeline and
credit.

## Security Updates

Security-relevant updates are tagged in releases and noted in
[CHANGELOG.md](CHANGELOG.md). Watch this repository for notifications.
