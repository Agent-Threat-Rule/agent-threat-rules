# ATR Reviewer Guide

Version 1.0 · Effective 2026-04-22

This guide is for anyone reviewing ATR rule PRs — community contributors,
TAG members, and the BDFL. It defines review standards, checklists, SLAs,
conflict-of-interest rules, and merge authority.

---

## Who Reviews What

| Role | Can review | Can approve | Can merge |
|------|------------|-------------|-----------|
| Community contributor | Any PR | No formal approve | No |
| TAG member | Any PR | Yes (1 approval counts toward SLA) | No |
| BDFL | Any PR (subject to recusal) | Yes | Yes |
| TSC member (post-2027) | Any PR (subject to recusal) | Yes | No (requires 2 TSC approvals) |

Community reviews are welcome and valuable. TAG and BDFL reviews are the
authoritative reviews for merge purposes.

---

## CI Gate — Always First

The CI quality gate must pass before a human reviewer spends time on the PR.

The check is: `ATR Rule Quality` GitHub Actions job running
`validateRuleMeetsStandard()` from `src/quality/quality-gate.ts`.

If CI fails, the PR is not ready for human review. Post a comment pointing to
the failing check and wait for the author to fix it. Do not begin content review
on a failing PR.

Additionally, check that the PR does not degrade the SKILL.md benchmark:
- Recall must not drop below 100% on labeled test corpus
- FP rate on the 432 benign skills must remain at 0%

---

## Review Checklist

Work through each section in order. For each item: pass / needs-work / N/A.

### 1. Schema correctness

- [ ] All required fields present: `title`, `id`, `rule_version`, `status`, `description`,
  `author`, `date`, `schema_version`, `detection_tier`, `maturity`, `severity`,
  `references`, `tags`, `agent_source`, `detection`
- [ ] `id` format: `ATR-YYYY-DRAFT-<hex>` (new rules) or `ATR-YYYY-NNNNN` (BDFL assigns final)
- [ ] `status` is one of: `experimental`, `stable`, `deprecated`
- [ ] `severity` is one of: `critical`, `high`, `medium`, `low`
- [ ] `maturity` is one of: `experimental`, `stable`
- [ ] YAML is valid (no tabs, correct indentation, no duplicate keys)

### 2. Detection quality

- [ ] At least 3 true positive test cases (real attack payloads, not paraphrases)
- [ ] At least 3 true negative test cases (similar-but-legitimate content)
- [ ] Regex patterns are tested for catastrophic backtracking (ReDoS) — check with
  `safe-regex` or an equivalent tool if patterns have nested quantifiers
- [ ] Rule does not duplicate an existing rule (search existing rules for overlap)
- [ ] The detection pattern is specific enough for production use (low FP risk)
- [ ] `description` explains what IS detected and what IS NOT

### 3. Test cases quality

- [ ] True positives are actual attack payloads from published research, CVEs, or
  real incident data — not AI-generated descriptions of attacks
- [ ] True negatives cover the most obvious false-positive edge cases
- [ ] Evasion tests document known bypass techniques honestly, even if the rule
  does not detect them (`expected: not_triggered` with `bypass_technique` note)
- [ ] `author: ATR Community (MiroFish Predicted)` rules require extra scrutiny:
  confirm the test cases are real payloads, not AI-inferred descriptions

### 4. MITRE and OWASP mappings

- [ ] At least one OWASP Agentic Top 10 or OWASP LLM Top 10 reference is present
- [ ] At least one MITRE ATLAS technique is present
- [ ] Mappings are accurate — reviewer must independently verify the technique
  matches the detection pattern (do not accept mappings blindly)
- [ ] CVE references exist where the rule addresses a specific CVE (not required for
  general pattern rules)

### 5. Compliance metadata (if present)

Rules may include a `compliance:` block. If present:
- [ ] `context` sentence explains WHY this rule satisfies the framework requirement
  (not just what the rule does)
- [ ] `strength` is one of: `primary`, `secondary`, `partial`
- [ ] Framework IDs are accurate (verify against the framework source document)
- [ ] No misleading compliance claims (the rule must genuinely address the cited article)

If `compliance:` is absent, that is acceptable for experimental rules. Do not block
a PR solely for missing compliance metadata.

### 6. Category and naming

- [ ] Rule file is in the correct `rules/<category>/` directory
- [ ] File name follows `ATR-YYYY-DRAFT-<slug>.yaml` convention
- [ ] `tags.category` matches the directory
- [ ] `tags.subcategory` is specific and useful for filtering

### 7. Scope and ATR independence

- [ ] Rule description does not reference any specific commercial product by name
  unless the rule is specifically a CVE rule for that product's vulnerability
- [ ] `author` field correctly identifies the contributor
- [ ] No PII, credentials, or sensitive data in test cases

---

## PR Review SLAs

| PR type | Initial acknowledgment | Full review |
|---------|----------------------|-------------|
| Standard community PR | 5 business days | 14 days |
| Enterprise Member PR (tagged `priority-review`) | 2 business days | 7 days |
| Security-critical (CVE rule, severity: critical) | 2 business days | 5 days |
| Autoresearch / Threat Cloud PR | Automated CI | BDFL reviews during weekly batch |

SLA clock starts when CI passes. A PR that has been waiting longer than its SLA with
no review comment should be nudged via a comment tagging the BDFL or a TAG member.

---

## Conflict of Interest

A reviewer must recuse from a PR when any of the following apply:
- They authored the rule being reviewed
- The rule specifically targets (detects or excludes) a product made by their employer
- They have a financial relationship with the PR author that could bias the review
- The PR author is a direct report, manager, or investor relation of the reviewer

Recusal must be stated publicly in the PR thread: "Recusing due to [conflict type]."
A recused TAG member's approval does not count toward the required review count.

When the BDFL recuses, the PR waits for a TAG member approval plus a second TAG
member confirmation (or TSC member approval post-2027).

---

## Merge Authority

Rules for merging:

1. CI must pass (quality gate green)
2. At least one TAG member or BDFL approval (in addition to passing CI)
3. No open `changes-requested` review from a TAG member or BDFL (community
   `changes-requested` reviews are advisory, not blocking)
4. BDFL assigns the final permanent ID (`ATR-YYYY-NNNNN`) at merge time
5. BDFL merges (or designates a TAG member with merge rights to merge)

Post-TSC: 2 TSC member approvals required for merge. TSC member merges.

---

## Evasion Report Triage

When a community member opens an evasion report (issue with `evasion` label):

| Priority | Acknowledgment | Fix SLA |
|----------|---------------|---------|
| Critical bypass (changes rule outcome for majority of real attacks) | 48 hours | 30 days |
| Significant bypass (new evasion technique, high practical risk) | 72 hours | 60 days |
| Minor bypass (edge case, low practical impact) | 7 days | Best effort |

Acknowledgment means: a comment in the issue confirming the bypass is real (or
explaining why it is not), and an initial severity assessment.

Fixes may be: regex improvement, new detection layer, or adding the bypass to
`evasion_tests` with `expected: not_triggered` and an honest explanation of why
the rule does not catch it.

---

## False Positive Triage

When a community member opens a false positive report (issue with `false-positive` label):

1. Acknowledge within 7 days
2. Reproduce the false positive using the provided input
3. Determine root cause: overly broad pattern, missing context, or invalid test case
4. Fix: narrow the regex, add a `true_negatives` test case, or close as
   `not-reproducible` with explanation
5. If FP rate on production traffic appears elevated (> 0.5%), escalate to
   `status: experimental` temporarily until fixed

---

## Batch Review (Threat Cloud / Autoresearch PRs)

The Threat Cloud crystallization pipeline opens automated PRs tagged
`source: threat-cloud`. These are batched for weekly review.

For batch PRs, apply a simplified checklist:
- [ ] No rules with `author: ATR Community (MiroFish Predicted)` that have
  AI-generated descriptions as test cases (not real payloads)
- [ ] Rule count per PR does not exceed 10 (configured in `check-rules-safety.ts`)
- [ ] All rules have at least 1 true positive and 1 true negative that pass `atr test`
- [ ] FP check against 432 benign skills: 0 new false positives introduced

The `auto-mergeable` label was retired on 2026-06-03 (521b4b0e): rule PRs from the
TC pipeline get the same human review as any other. A passing safety gate shortens
review but does not replace it. PRs labeled `needs-human-review` require full
checklist review.

---

## Reviewer Guidance on Compliance Metadata

The `compliance:` block is optional but strongly encouraged for rules addressing
standard attack categories. When reviewing compliance blocks:

- The `context` sentence must explain why the detection rule satisfies the specific
  framework requirement — not just restate what the rule does
- Framework article numbers must be accurate — verify against the source document
  (EU AI Act 2024/1689, NIST AI RMF 1.0, ISO 42001:2023, OWASP Agentic Top 10)
- Compliance claims must be defensible: if an auditor asks "how does this rule
  satisfy Article 15?", the `context` sentence must answer that question directly

Do not add compliance metadata speculatively. Only map to frameworks where the
connection is clear and the context sentence can be written honestly.
