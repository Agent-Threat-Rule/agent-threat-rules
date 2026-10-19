# Integration and Contribution Paths

ATR is an open detection standard. Every tool that integrates ATR becomes part of a
global sensor network: you get rules, and your scan results (anonymized) help generate
better rules for everyone.

```
Your scanner ──── detects threat ────→ ATR Threat Cloud
                                           │
                              LLM crystallizes new rule
                                           │
All ATR endpoints ←── new rule pushed ─────┘
```

Every integration is both a consumer and a sensor.

---

## Tier 1: Individual Developers (5 minutes)

Use ATR to scan your MCP configs and SKILL.md files in CI/CD.

### GitHub Action

```yaml
# .github/workflows/atr-scan.yml
name: ATR Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Agent-Threat-Rule/agent-threat-rules@v3
```

That's it. Every PR gets scanned against 113 detection rules.

### CLI

```bash
npm install -g agent-threat-rules

# Scan MCP config
atr scan my-mcp-config.json

# Scan SKILL.md files
atr scan ./skills/

# Opt-in: report detections to Threat Cloud
atr scan ./skills/ --report-to-cloud
```

**What you get:** Free security scanning, 113 rules, 9 threat categories.

**What the network gets:** If you opt into `--report-to-cloud`, your anonymized detection data (rule ID + severity + content hash, zero raw content) helps crystallize new rules that protect everyone.

---

## Tier 2: Small Teams & AI Startups (30 minutes)

Integrate ATR into your Node.js or Python application.

### Node.js / TypeScript

```bash
npm install agent-threat-rules
```

```typescript
import { ATREngine } from 'agent-threat-rules';
import type { ATRReporter } from 'agent-threat-rules';

// Optional: report detections to Threat Cloud
const reporter: ATRReporter = {
  onDetection: (report) => {
    // report contains: ruleId, severity, category, confidence, contentHash
    // No raw content, no PII, no file paths
    fetch('https://tc.example.com/api/detections', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(report),
    }).catch(() => {}); // fire-and-forget, never block your app
  },
};

const engine = new ATREngine({ rulesDir: 'node_modules/agent-threat-rules/rules', reporter });
await engine.loadRules();

// Scan every tool response in your agent pipeline
const matches = engine.evaluate({
  type: 'tool_response',
  content: toolOutput,
  timestamp: new Date().toISOString(),
});

if (matches.length > 0) {
  // Threat detected — block, alert, or log
}
```

### Python (pyATR)

```bash
pip install git+https://github.com/Agent-Threat-Rule/agent-threat-rules.git#subdirectory=python
```

```python
from pyatr import ATREngine

engine = ATREngine()
result = engine.evaluate(event={
    "type": "tool_response",
    "content": tool_output,
})

if result.outcome == "deny":
    # Block the request
```

**What you get:** Real-time threat detection in your agent pipeline. 113 rules maintained by the community. Zero maintenance cost.

**What the network gets:** Your scanner becomes an endpoint. Attacks seen by your users (anonymized) help generate rules that protect Cisco, Microsoft, and every other endpoint.

---

## Tier 3: Security Platforms (2-4 hours)

Integrate ATR rules into your scanner, SIEM, or governance toolkit.

### Generic Regex Export

Extract ATR patterns in a format any scanner can consume:

```bash
atr convert generic-regex --output atr-patterns.json
# [{ id, title, severity, category, patterns: [{ field, regex, flags, description }] }]
```

Compile each pattern as `new RegExp(regex, flags)`. Following SPEC §6.4,
`regex` is the condition without its leading flag group and `flags` is always
`i`, or `iu` when the pattern needs Unicode mode: every condition matches
case-insensitively, and `m`, `s` and `x` have no effect. If the regex engine
takes the pattern as one string with inline flags only (for example Splunk's
PCRE or Go's `regexp`), use `(?i)` followed by `regex`. The patterns are
ECMAScript: RE2-based engines such as Go's `regexp` cannot compile the ones that
use lookaround or backreferences (see docs/ARCHITECTURE.md §6.2), and PCRE and
Python `re` differ in places, for example `$` also matches before a final
newline. Where `flags` is `iu`, a PCRE-based engine needs UTF mode for the
astral characters such a pattern contains.

`rulesToGenericRegex()` is not exported by the package, from the entry point or
a subpath, so use the CLI.

### SIEM Integration (Splunk / Elasticsearch)

```bash
atr convert splunk --output splunk-queries.txt    # SPL queries
atr convert elastic --output elastic-queries.json  # Elasticsearch Query DSL
```

### Raw YAML (any language — Go, Rust, Java)

```bash
git submodule add https://github.com/Agent-Threat-Rule/agent-threat-rules.git vendor/atr
```

Parse `vendor/atr/rules/*.yaml` with any YAML library. Schema at `vendor/atr/spec/atr-schema.yaml`.

### SARIF (GitHub Security tab)

```bash
atr scan my-config.json --format sarif --output results.sarif
```

Upload to GitHub Code Scanning for security alerts in your PR review.

**What you get:** ATR's detection rules in your platform's format, updated through npm or git.

**What the network gets:** Your platform's users become endpoints. A threat first seen by a Garak probe protects a Microsoft AGT deployment. A pattern caught by your SIEM triggers a rule that shields individual developers.

---

## Tier 4: Deep Ecosystem Partners (ongoing relationship)

For platforms that want to be part of the ATR governance and rule lifecycle.

### What we offer

- **Custom format converter**: We write the code to convert ATR YAML to your platform's native format
- **Integration PR**: We submit the PR to your repo, matching your code style and test patterns
- **Co-maintenance**: When ATR rules update, the integration updates automatically
- **Threat Cloud data exchange**: Your platform's detections feed TC, TC's crystallized rules feed your platform

### What we ask

- List ATR in your README or integrations page
- (Encouraged) Enable ATRReporter so your users' detections strengthen the network
- (Optional) Display the ATR badge on your platform

### Current partners

| Platform | Integration | How they consume ATR |
|----------|------------|---------------------|
| **Cisco AI Defense** | 34 rules in skill-scanner | Generic regex export → their scanner engine ([PR #79](https://github.com/cisco-ai-defense/skill-scanner/pull/79)) |
| **OWASP Agentic Top 10** | Detection mapping | Rule-to-category mapping document ([PR #14](https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14)) |

### Become a partner

Open an issue with the `ecosystem-integration` label. We will:
1. Study your platform's architecture
2. Write the integration code
3. Submit a PR that matches your standards
4. Maintain the integration as ATR evolves

---

## For Contributors (write new detection rules)

### Write a rule (1-2 hours)

```bash
atr scaffold                    # Generate template
# Edit the YAML: patterns, test cases, OWASP mapping
atr validate my-rule.yaml       # Check schema
atr test my-rule.yaml           # Run test cases
# Submit PR to rules/<category>/
```

Requirements: 5+ true positive tests, 5+ true negative tests, 3+ evasion tests, OWASP or MITRE mapping.

### Report an evasion (15 minutes)

Found a way to bypass a rule? Open an issue with the **Evasion Report** template. Include: rule ID, bypass input, technique. This is the most valuable contribution.

### Report a false positive (20 minutes)

A rule triggered on safe content? Open an issue with the **False Positive Report** template. Include: rule ID, the input, why it's legitimate.

### Runtime auto-draft

If you run ATR in production and encounter a novel attack that no rule catches, the ATR Drafter module can auto-generate a draft rule and open a GitHub issue for community review.

---

## Quality Gate (all contributions)

Every rule must pass before merge:

| Automated (CI) | Human Review |
|----------------|-------------|
| Schema validation passes | Patterns target real attacks, not generic language |
| 5+ true positives pass | False positive scenarios documented |
| 5+ true negatives pass | 3+ evasion tests with known bypasses |
| OWASP or MITRE reference | Severity matches real-world impact |
| No ReDoS-vulnerable regex | At least one maintainer approval |

---

## The Network Effect

Every integration makes ATR more valuable for every other integration:

```
More endpoints → more detection data → better rules → more endpoints
```

A malicious MCP server discovered by a solo developer's GitHub Action
becomes a rule that downstream consumers can pick up on their next sync, including the open-source cisco-ai-defense/skill-scanner repository.

An evasion technique found by NVIDIA Garak's probes
becomes a hardened pattern that shields every small startup's agent pipeline.

This is the flywheel. Every scan makes the network smarter.
