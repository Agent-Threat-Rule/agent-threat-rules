# Contributing to ATR

ATR is MIT-licensed. No proprietary tooling. No telemetry. No CLA.

---

## Fastest path: open a GitHub Issue

Spotted an attack pattern? File a **[New Rule Proposal](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=new-rule.yml)** issue. Fill in three fields — attack type, description, example payload. A bot converts it to a draft proposal within minutes and opens a PR. You don't need to clone the repo.

A maintainer (or you) authors the detection regex from there.

---

## How to Contribute

#### A. Propose a New Rule via Issue (~5 minutes, no repo setup needed)

1. Open a **[New Rule Proposal](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=new-rule.yml)** issue.
2. Fill in: attack type, description, and at least one example payload.
3. A bot creates `proposals/community/ISSUE-{number}-{slug}.proposal.yaml` and opens a draft PR automatically.
4. The proposal is queued for regex authoring. You can stop here, or continue to step 5.
5. Optional: check out the PR branch, fill in `detection.conditions`, run `npx tsx scripts/check-rules-safety.ts <file>`, push.

Every filed issue becomes a tracked proposal. Your name appears in the `author` field of any rule that ships from it.

#### B. Write the Regex for an Existing Proposal (~30–60 minutes)

The `proposals/` directory has CVE-sourced drafts that have payloads but no detection logic yet. These are the fastest contributions to ship.

1. Browse `proposals/` for files with `_triage.detection_ready: true`
2. Pick one, check out a branch, fill in `detection.conditions` based on the `_triage.example_payload`
3. Run `npx agent-threat-rules test <file>` — must pass all test cases
4. Run `npx tsx scripts/check-rules-safety.ts <file>` — must show 0 FP
5. Submit a PR

#### C. Report an Evasion (~15 minutes)

Found a way to bypass an existing rule?

1. Check the rule's `evasion_tests` section and [LIMITATIONS.md](./LIMITATIONS.md) — might already be documented.
2. Open an issue using the **Evasion Report** template.
3. Include: rule ID, bypass input, technique used, why it works.

Every confirmed evasion becomes a new `evasion_tests` entry. You get credited in [CONTRIBUTORS.md](./CONTRIBUTORS.md). We publish evasion tests openly — your bypass makes the project more honest.

#### D. Report a False Positive (~20 minutes)

A rule triggered on legitimate content?

1. Open an issue using the **False Positive Report** template.
2. Include: rule ID, the input that triggered it, why it is legitimate.

Confirmed false positives become new `true_negatives` test cases.

#### E. Submit a New Rule Directly (~1 hour)

Write a full detection rule from scratch.

1. Fork this repository
2. Create a YAML file in the appropriate `rules/<category>/` subdirectory
3. Follow the ATR schema (`spec/atr-schema.yaml`)
4. See [examples/how-to-write-a-rule.md](./examples/how-to-write-a-rule.md) for a walkthrough
5. Validate and test locally (see Quick Start below)
6. Submit a PR

### AI-Native Contributions

Security standards in the AI era need AI-era contribution workflows.
You do not have to write YAML by hand to make ATR better.

#### F. Scan and Report (~2 minutes)

Run ATR against your MCP skills or any public skill. Findings go to
Threat Cloud for aggregation (anonymized, opt-in via `--report-to-cloud`).

```bash
npx agent-threat-rules scan .                       # Scan current directory
npx agent-threat-rules scan skill.md                # Scan a single SKILL.md
npx agent-threat-rules scan events.json             # Scan MCP event log
npx agent-threat-rules scan . --report-to-cloud     # Scan + report to TC
```

When TC aggregates enough signals for a new attack pattern, it
crystallizes a draft rule, opens a PR to this repo, and a human
reviewer merges it. Your scan data becomes part of the global defense.

#### G. Add ATR to Your CI (~5 minutes)

Add one file to your repo. Every PR gets scanned automatically.

```yaml
# .github/workflows/atr-scan.yml
name: ATR Security Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx agent-threat-rules scan . --sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Results appear in GitHub's Security tab as code scanning alerts.

#### H. Contribute via LLM-Assisted Rule Generation

Use AI tools to draft ATR rules. The ATR MCP server lets any AI
agent read, test, and propose new rules:

```bash
npx agent-threat-rules mcp   # Start the ATR MCP server
```

Example prompt for your AI assistant:
> "Read the ATR rules in rules/prompt-injection/. Find a prompt injection
> technique not yet covered. Draft a new rule following the ATR schema at
> spec/atr-schema.yaml. Include 3 true positives and 3 true negatives.
> Validate with `atr validate` and test with `atr test`."

Submit LLM-assisted rules via PR. Mark them with `author: your-name (LLM-assisted)`
so reviewers know to pay extra attention to regex quality and edge cases.

---

## Quick Start

Clone and test all rules:

```bash
git clone https://github.com/Agent-Threat-Rule/agent-threat-rules
cd agent-threat-rules
npm install
npm test
```

Or validate and test a single rule without cloning:

```bash
npx agent-threat-rules validate path/to/my-rule.yaml
npx agent-threat-rules test path/to/my-rule.yaml
```

The `agent-threat-rules` CLI pulls from npm. No monorepo setup required.
Source code: [src/cli.ts](./src/cli.ts).

---

## Rule Quality Checklist

Before submitting, verify:

**Required (experimental tier, per RFC-001 v1.1):**

- [ ] Follows ATR schema (`spec/atr-schema.yaml`)
- [ ] Has `maturity: experimental`
- [ ] Has `author` field with your name or handle
- [ ] At least 3 true positive test cases (real attack payloads)
- [ ] At least 3 true negative test cases (similar-looking legitimate content)
- [ ] `description` explains what IS detected AND what IS NOT
- [ ] `npx agent-threat-rules validate` passes
- [ ] `npx agent-threat-rules test` passes

**Encouraged (improves confidence score, helps promotion to stable):**

- [ ] OWASP Agentic Top 10 or OWASP LLM Top 10 mapping
- [ ] MITRE ATLAS mapping
- [ ] Evasion tests with `bypass_technique` and honest `expected: not_triggered`
- [ ] `false_positives` section listing known edge cases
- [ ] Regex patterns tested for catastrophic backtracking (ReDoS)

**Required for stable promotion (maintainers handle this):**

- [ ] 5+ true positives, 5+ true negatives, 3+ evasion tests
- [ ] OWASP + MITRE mapping with `human-reviewed` provenance
- [ ] Wild-validated on 1,000+ samples with FP rate ≤ 0.5%
- [ ] 14+ days at experimental, confidence score ≥ 80

See [RFC-001](docs/proposals/001-atr-quality-standard-rfc.md) for full details.

---

## Rule Naming Convention

- File: `ATR-YYYY-NNN-short-description.yaml`
- Place in the correct `rules/<category>/` subdirectory
- Categories: `prompt-injection`, `tool-poisoning`, `context-exfiltration`,
  `agent-manipulation`, `privilege-escalation`, `excessive-autonomy`,
  `skill-compromise`, `data-poisoning`, `model-security`
- If unsure about the next available ID, use a placeholder.
  Maintainers assign the final ID during review.

---

## Where to Hunt

Not sure what to contribute? **[CONTRIBUTION-GUIDE.md](CONTRIBUTION-GUIDE.md)** maps 12 research
areas with concrete attack surfaces, data sources, and difficulty levels.
From 5-minute incident reports to weekend red team fuzzing sessions.

---

## See ATR in Action (Optional)

Want to see ATR rules working before contributing? Try scanning some content
with the CLI:

```bash
npx agent-threat-rules scan events.json
npx agent-threat-rules stats
```

Or start the MCP server and test interactively:

```bash
npx agent-threat-rules mcp
```

If you notice a gap -- an attack it should catch but does not -- that gap
is your first rule contribution.

Reading [COVERAGE.md](./COVERAGE.md)
and [LIMITATIONS.md](./LIMITATIONS.md) is another way to find what is missing.

---

## Recognition

Contributors are credited through:

1. **YAML `author` field** -- Your name appears in every rule you write.
   Ships with the npm package. Everyone who installs ATR sees it.
2. **[CONTRIBUTORS.md](./CONTRIBUTORS.md)** -- Listed by contribution type.
3. **Release notes** -- New rules credited by author in each release.
4. **CVE credit** -- If your rule detects a CVE you discovered, the
   `references.cve` section links your work permanently.

---

## Schema Changes

Major schema changes require community discussion:

1. Open an issue with the `schema-change` label
2. Describe the proposed change and rationale
3. Minimum 7-day comment period
4. Submit a PR if consensus is reached

---

## Code of Conduct

- Be constructive in reviews
- Credit original research when submitting rules based on published work
- Report security vulnerabilities privately (see [SECURITY.md](./SECURITY.md))
- Respect differing opinions on severity classification
- No marketing or product promotion in rule descriptions

---

## ATR Standards Programs

### ATR Certified Skill — Getting Certified (Free)

If you have an MCP skill and want to display the ATR Certified badge:

1. Open a GitHub Issue with title `[ATR Certified] <skill-name>`
2. Attach or link the skill artifact (SKILL.md or MCP tool description)
3. A community reviewer will run `atr scan` against the artifact and post
   the full output
4. If zero critical/high findings: maintainer applies the `atr-certified`
   label and adds the skill to the certified registry
5. Certification is valid 90 days. Recertify after each major ATR release.

Cost: Zero. No account required. No commercial relationship required.

### ATR Enterprise Member — Governance Participation

Enterprise Membership is for organizations that depend on ATR in a security
product, research project, or internal tooling and want governance participation.

Membership is $10,000/year and provides:
- One governance vote per organization in TSC-level decisions (post-TSC formation)
- 14-day early access to new RFC drafts before public comment period opens
- 7-day priority PR review SLA (vs standard 14-day SLA)
- Organization logo in this repository's README and ATR website
- Private mailing list for coordinating vendor-pack rule contributions

To apply: open a GitHub Issue with label `enterprise-member-application` and
include a brief description of how your organization uses ATR.

Enterprise Membership does not grant influence over individual rule decisions.
Rule acceptance is determined by CI quality gate and community review only.

Full terms: [docs/BDFL-charter.md](docs/BDFL-charter.md).

---

## License

All contributions are licensed under MIT.
By submitting a PR, you agree to license your contribution under MIT.
No CLA required.
