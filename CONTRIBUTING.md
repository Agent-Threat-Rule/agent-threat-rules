# Contributing to ATR

ATR is an MIT-licensed open standard for detecting AI agent attacks — think Snort rules but for LLMs and MCP tools. 768 detection rules across 10 categories; canonical rule counts and per-lane precision/FP figures live in [`data/stats.json`](data/stats.json) and the README evaluation table. Merged into open-source repos at Microsoft, Cisco, MISP, and OWASP-community projects. When you contribute a detection rule, it ships to every downstream consumer within hours.

No CLA. No telemetry. No proprietary tooling.

---

## Path 1: Submit an attack probe (5 min, no setup)

You spotted an attack pattern. You have example payloads. That's enough to start.

1. Open a new issue using the [Red Team Probe template](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=red-team-probe.yml).

2. Fill in the required fields:
   - Probe name (short title, becomes the rule title)
   - Attack category (prompt-injection, tool-poisoning, context-exfiltration, etc.)
   - Severity
   - Attack description (two or three sentences: what the probe does, what the attacker gains)
   - Positive examples — at least 3 real attack payloads, one per line
   - Negative examples — at least 3 benign strings that look similar but must NOT trigger
   - Discovered by (your name and handle — this becomes your attribution)

3. Submit the issue.

That's it. A workflow runs immediately and opens a draft PR. The proposal YAML
is auto-generated from your examples. You do not need to clone anything.

A maintainer reviews the regex shape and runs the full quality gate before
merging. You can stop at step 3, or check out the PR branch and write the
regex yourself if you want to stay involved.

---

## Path 2: Write a detection regex for an existing CVE stub (30 min)

The `proposals/` directory contains CVE-sourced stubs: real attack payloads,
no detection logic yet. These are the fastest rules to ship because the hard
part (finding the attack) is already done.

1. Clone the repo and install dependencies:

   ```bash
   git clone https://github.com/Agent-Threat-Rule/agent-threat-rules
   cd agent-threat-rules
   npm install
   ```

2. Find a stub with `_triage.detection_ready: true`:

   ```bash
   grep -rl "detection_ready: true" proposals/
   ```

3. Create a branch and open the file. Write the `detection.conditions` regex
   based on the `_triage.example_payload` field in the stub.

4. Run the safety gate:

   ```bash
   npx tsx scripts/check-rules-safety.ts path/to/your-rule.yaml
   ```

   This checks your rule against 432 known-benign skills. Must show 0 FP.

5. Run the test suite:

   ```bash
   npx agent-threat-rules test path/to/your-rule.yaml
   ```

6. Submit a PR.

If you need a new rule ID before creating the file:

```bash
npx tsx scripts/next-rule-id.ts
```

---

## What happens after you submit

Once your issue or PR lands:

1. Automated PR opens (probe path) or CI runs (direct PR path). The safety gate
   checks 0 FP against 432 benign samples. If it fails, the PR gets the
   `needs-human-review` label and a maintainer looks at it manually.

2. Maintainer reviews the regex. Usually one round of tightening. The benign
   corpus is the bar — the regex must not fire on clean content.

3. PR merges. The `publish-on-rules-merge.yml` workflow runs automatically:
   patch version bump, npm publish, GitHub release.

4. Downstream sync runs. Microsoft AGT, Cisco AI Defense, MISP galaxy, and OWASP
   pull from the npm package on their regular cadence. Your rule is live in
   production at those organizations within their next update cycle.

Typical time from probe submission to npm publish: same day or next day,
depending on maintainer availability.

---

## Where your name appears

Every rule that ships from your probe or PR carries your attribution in two places:

- `author` field in the rule YAML — ships in the npm package, visible to every
  organization that installs ATR
- `metadata_provenance.discovered_by` — links back to the original issue or
  research that surfaced the attack

Your name also appears in:

- [CONTRIBUTORS.md](./CONTRIBUTORS.md)
- Release notes for each version that includes your rule
- Downstream at Microsoft, Cisco, OWASP, MISP — every consumer of the npm
  package gets the YAML with your name in it

If your rule maps to a CVE you discovered, `references.cve` links your work
permanently in the rule record.

---

## Quality bar

The CI gate is non-negotiable. Everything else is guidance.

Required for any rule to merge:

- At least 3 true positive test cases — real attack payloads, not synthetic
- At least 3 true negative test cases — real benign strings, not placeholders
- 0 false positives on the 432-sample benign corpus (`check-rules-safety.ts`)
- Regex must be attack-specific. Broad patterns that match general conversation
  will not pass review.
- `description` must say what IS detected and what IS NOT

The most common rejection reason is a regex that's too broad. If your positive
examples all share a specific structural marker, anchor the regex to that marker.
Do not try to catch the entire attack family in one pattern — narrow rules with
0 FP are more valuable than wide rules with 1%.

Maintainers handle stable promotion after merge: the rule needs at least
5 TPs, 5 TNs, 3 evasion tests, framework mappings, and wild validation
on 1,000+ samples. You do not need to do this yourself.

---

## Local dev setup

```bash
git clone https://github.com/Agent-Threat-Rule/agent-threat-rules
cd agent-threat-rules
npm install
npm test
npx agent-threat-rules validate path/to/rule.yaml
npx agent-threat-rules test path/to/rule.yaml
```

Rule schema: `spec/atr-schema.yaml`. Categories: `rules/prompt-injection/`,
`rules/tool-poisoning/`, `rules/context-exfiltration/`,
`rules/agent-manipulation/`, `rules/privilege-escalation/`,
`rules/excessive-autonomy/`, `rules/skill-compromise/`,
`rules/data-poisoning/`, `rules/model-security/`.

---

Credit original research when submitting rules based on published work.
Report security vulnerabilities privately via [SECURITY.md](./SECURITY.md).
No product promotion in rule descriptions.

All contributions are MIT. By submitting a PR, you agree to license your
contribution under MIT.
