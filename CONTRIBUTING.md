# Contributing to ATR

Thank you for your interest in contributing to ATR (Agent Threat Rules).
This project relies on the security community's expertise to build
comprehensive, accurate detection rules for AI agent threats.

## How to Submit a Rule

1. Fork this repository
2. Create a new YAML file in the appropriate `rules/` subdirectory
3. Follow the ATR schema (see `spec/atr-schema.yaml`)
4. Include test cases (at least 2 true positives + 2 true negatives)
5. Run validation: `npm run validate`
6. Submit a PR with a clear description of the attack this rule detects

## Rule Quality Checklist

Before submitting, verify:

- [ ] Follows ATR schema (passes `npm run validate`)
- [ ] Has OWASP LLM Top 10 or MITRE ATLAS mapping
- [ ] Has at least 2 true positive test cases
- [ ] Has at least 2 true negative test cases
- [ ] `false_positives` section lists known edge cases
- [ ] `description` clearly explains what attack this detects
- [ ] `severity` is justified and consistent with similar rules
- [ ] Regex patterns are tested and don't cause catastrophic backtracking
- [ ] Rule ID follows format: `ATR-YYYY-NNN`

## Rule Naming Convention

- File name: `ATR-YYYY-NNN-short-description.yaml`
- Place in the correct `rules/<category>/` subdirectory
- Category must match one of: `prompt-injection`, `tool-poisoning`,
  `context-exfiltration`, `agent-manipulation`, `privilege-escalation`,
  `excessive-autonomy`, `data-poisoning`

## Reporting False Positives

If a rule triggers on legitimate behavior, open an issue with:

- Rule ID (e.g., ATR-2026-001)
- The input/output that triggered it
- Why it's a false positive
- Suggested fix (if any)

## Proposing Schema Changes

Major schema changes go through community discussion:

1. Open an issue with the `schema-change` label
2. Describe the proposed change and rationale
3. Wait for community feedback (minimum 7 days)
4. Submit a PR if consensus is reached

## Testing Rules

```bash
# Validate all rules against schema
npm run validate

# Run full test suite
npm test
```

## Code of Conduct

- Be constructive in reviews
- Credit original research when submitting rules based on published work
- Report security vulnerabilities privately (see SECURITY.md)
- Respect differing opinions on rule severity and classification

## License

All contributions are licensed under MIT.
By submitting a PR, you agree to license your contribution under MIT.
