# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ATR rules, the evaluation engine,
or any component of this project, please report it responsibly.

**Email:** Open a [GitHub Security Advisory](https://github.com/Agent-Threat-Rule/agent-threat-rules/security/advisories/new) (preferred) or email the maintainers directly via GitHub.

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Affected rule IDs (if applicable)
- Potential impact assessment

**What to expect:**
- Acknowledgment within 48 hours
- Status update within 7 business days
- Credit in the advisory (unless you prefer anonymity)

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

Security-relevant updates are tagged in releases and noted in CHANGELOG.md.
Watch this repository for notifications.
