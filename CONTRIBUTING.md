# Contributing to ATR

ATR is an MIT-licensed open standard for detecting AI agent attacks — think Snort rules but for LLMs and MCP tools. Detection rules span 10 categories; the canonical rule count and the version-pinned benchmark table live in [`data/stats.json`](data/stats.json) and the README, which are the numbers to quote (the count moves daily, so this page does not carry one). Note that the per-lane false-positive rates once published in the README are **withdrawn and not citable** — see the lanes section there. ATR rules have been merged into open-source repos maintained by Microsoft, Cisco, MISP, and OWASP-community projects. When you contribute a detection rule, it ships to every downstream consumer of the npm package on their next update.

No CLA. No proprietary tooling. No telemetry by default — the CLI sends nothing unless you pass `--report-to-cloud` (see the Telemetry section of the README).

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

   This checks your rule against the committed benign skill corpus, walking
   subdirectories. Must show 0 FP. The gate prints the sample count it used;
   trust that number over any figure written here, and count the corpus yourself
   rather than trusting this line:

   ```bash
   find data/skill-benchmark/benign -name '*.md' | wc -l
   ```

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
   checks 0 FP against the benign skill corpus (the gate prints the sample count
   it used).
   If it fails, the PR gets the `needs-human-review` label and a maintainer
   looks at it manually.

2. Maintainer reviews the regex. Usually one round of tightening. The benign
   corpus is the bar — the regex must not fire on clean content.

3. PR merges. The `publish-on-rules-merge.yml` workflow runs automatically:
   patch version bump, npm publish, GitHub release.

4. The new version is on npm. Open-source projects that vendor ATR — including
   repos under Microsoft, Cisco, MISP and OWASP-community orgs — pick it up
   whenever they next sync. What ATR can promise is the publish; when and
   whether any downstream repo updates is theirs to decide, and merging a rule
   here is not a claim that it is running in any company's product.

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
- Downstream — every consumer of the npm package, including the open-source
  repos under the Microsoft, Cisco, OWASP-community and MISP orgs that vendor
  ATR, gets the YAML with your name in it

If your rule maps to a CVE you discovered, `references.cve` links your work
permanently in the rule record.

---

## Path 3: Mine a corpus (a few hours)

Most of the ruleset came from attack corpora, not from the proposal queue.
[docs/RULE-PRODUCTION.md](docs/RULE-PRODUCTION.md) is the written procedure for
that path: how to decide whether a corpus is usable raw material at all, how to
measure recall against it without wiring the harness wrong, how to turn false
negatives into candidate rule anchors, and every gate between a candidate and
`main`. Start with `npx tsx scripts/mine-corpus-fn.ts --list`.

Read §4.4 before writing anything. Every artifact-bearing candidate the corpora
currently in this repository produce is a fixture of the benchmark rather than
of an attack, and the document explains how to tell the difference.

---

## Quality bar

The CI gate is non-negotiable. Everything else is guidance.

Required for any rule to merge:

- At least 3 true positive test cases — real attack payloads, not synthetic
- At least 3 true negative test cases — real benign strings, not placeholders
- 0 false positives on the benign skill corpus (`check-rules-safety.ts`, which
  prints the sample count it used)
  (count the directory with
  `find data/skill-benchmark/benign -name '*.md' | wc -l` rather than trusting
  this line)
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

Rule schema: `spec/atr-schema.yaml`. The ten category directories are
`rules/prompt-injection/`, `rules/tool-poisoning/`,
`rules/context-exfiltration/`, `rules/agent-manipulation/`,
`rules/privilege-escalation/`, `rules/excessive-autonomy/`,
`rules/skill-compromise/`, `rules/model-abuse/`, `rules/data-poisoning/` and
`rules/model-security/` (`ls rules/` is the live list).

---

Credit original research when submitting rules based on published work.
Report security vulnerabilities privately via [SECURITY.md](./SECURITY.md).
No product promotion in rule descriptions.

All contributions are MIT. By submitting a PR, you agree to license your
contribution under MIT.
