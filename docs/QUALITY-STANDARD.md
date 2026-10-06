# ATR Rule Quality Standard

Version: 1.0 | Effective: 2026-04-10

This document defines the quality requirements for ATR rules at each maturity level, the criteria for promotion and demotion, and the confidence scoring system. It is the authoritative source for "can I trust this rule in production?"

## Maturity Levels

ATR rules progress through four maturity levels. Each level has explicit entry criteria that must be met before promotion.

```
  DRAFT ──> EXPERIMENTAL ──> STABLE ──> DEPRECATED
    │            │              │            │
    │            │              │            └─ Replacement rule exists
    │            │              │               OR threat no longer relevant
    │            │              │
    │            │              └─ Wild-validated, enterprise-ready
    │            │                 confidence >= 80, wild FP rate <= 0.5%
    │            │
    │            └─ CI-validated, benchmark-tested
    │               precision >= 95% on test cases
    │
    └─ Schema-valid, minimal testing
       Entry point for all new rules
```

### DRAFT

Entry point for all new rules. Anyone can submit.

| Requirement | Details |
|-------------|---------|
| Valid YAML | Parses without error |
| Schema pass | All required fields present (title, id, status, description, author, date, severity, tags, agent_source, detection, response) |
| ID format | `ATR-YYYY-NNNNN` |
| At least 1 test case | Minimum 1 true_positive + 1 true_negative |
| No ReDoS | Regex passes catastrophic backtracking check |

**Not deployed.** Draft rules are development artifacts only.

### EXPERIMENTAL

CI-validated rules with benchmark coverage. Safe for evaluation and non-blocking alerting.

| Requirement | Details |
|-------------|---------|
| All DRAFT requirements | |
| >= 5 true_positives | Real attack payloads, not hypothetical |
| >= 5 true_negatives | Similar-looking legitimate content |
| >= 3 evasion_tests | Documented bypass techniques with `expected: not_triggered` |
| Precision >= 95% | On embedded test cases |
| false_positives section | At least 1 documented false positive scenario |
| OWASP mapping | At least one `owasp_llm` or `owasp_agentic` reference |
| MITRE mapping | At least one `mitre_atlas` or `mitre_attack` reference |
| CI pass | `atr validate` + `atr test` both green |

**Promotion criteria (EXPERIMENTAL -> STABLE):**

| Criterion | Threshold |
|-----------|-----------|
| Wild scan coverage | Tested on >= 1,000 real-world skills |
| Wild FP rate | <= 0.5% on wild scan data |
| Time in experimental | >= 14 days |
| Independent confirmations | >= 2 (different scan sources or community reports) |
| No unresolved FP reports | All reported false positives investigated and addressed |
| Confidence score | >= 80 |

### STABLE

Production-ready rules validated on real-world data. Safe for blocking actions in enterprise deployments.

| Requirement | Details |
|-------------|---------|
| All EXPERIMENTAL requirements | |
| Wild FP rate <= 0.5% | Measured on >= 1,000 real skills |
| Confidence score >= 80 | Assigned based on wild scan performance |
| `wild_validated` field | Date of last wild scan validation |
| `wild_samples` field | Number of real-world samples tested |
| Known evasions documented | All known bypass techniques in `evasion_tests` |

**Demotion criteria (STABLE -> EXPERIMENTAL):**

| Trigger | Action |
|---------|--------|
| Wild FP rate > 2% | Automatic demotion |
| 3+ unresolved FP reports in 30 days | Automatic demotion |
| Regex becomes obsolete | Manual demotion by maintainer |

### DEPRECATED

Rules that have been superseded or are no longer relevant.

| Requirement | Details |
|-------------|---------|
| `deprecated_reason` field | Why this rule was deprecated |
| `replaced_by` field | ID of replacement rule (if any) |
| Retained in repo | For historical reference and backward compatibility |
| Not loaded by default | Scanners skip deprecated rules unless explicitly requested |

---

## Confidence Score

Every rule at EXPERIMENTAL or above has a numeric confidence score (0-100) reflecting its reliability in real-world scanning.

### Score Ranges

| Range | Label | Meaning | Deployment Guidance |
|-------|-------|---------|-------------------|
| 90-100 | Very High | Precise regex, wild-validated, 0 FP in 30+ days | Safe for blocking in production |
| 80-89 | High | Wild-validated, FP rate < 0.5% | Safe for blocking with monitoring |
| 60-79 | Medium | Benchmark-tested, limited wild data | Alert-only, do not block |
| 40-59 | Low | Experimental, narrow coverage | Evaluation and research only |
| 0-39 | Draft | Minimal testing | Not deployed |

The "Deployment Guidance" column is a review and promotion signal, not a runtime
filter. The reference engine does not read this score when deciding whether to
act; the switches that do are the lane and the blocking opt-in described in
[For Consumers](#for-consumers) below.

### Score Calculation

Confidence is computed from four factors:

```
confidence = (precision_score * 0.4)
           + (coverage_score * 0.2)
           + (wild_validation_score * 0.3)
           + (evasion_documentation_score * 0.1)
```

| Factor | Weight | How to measure |
|--------|--------|---------------|
| **Precision** | 40% | `(1 - FP_rate) * 100` on test cases + wild data |
| **Coverage** | 20% | Number of distinct attack variants detected / total known variants for this category |
| **Wild validation** | 30% | `min(wild_samples / 10000, 1) * 100` — more real-world data = higher score |
| **Evasion docs** | 10% | `min(documented_evasions / 5, 1) * 100` — more honest = higher score |

### Cross-Context Confidence

When a rule designed for one scan context (e.g., MCP runtime) fires in another context (e.g., SKILL.md static scan), confidence is downweighted:

| Context match | Multiplier |
|--------------|------------|
| Native (rule context == scan context) | 1.0x |
| Cross-context (rule context != scan context) | 0.7x |

This is already implemented in `ATRMatch.scan_context` and the engine applies the multiplier automatically.

---

## Required Fields by Maturity

| Field | DRAFT | EXPERIMENTAL | STABLE | DEPRECATED |
|-------|-------|-------------|--------|------------|
| `title` | Required | Required | Required | Required |
| `id` | Required | Required | Required | Required |
| `status` | Required | Required | Required | Required |
| `description` | Required | Required | Required | Required |
| `author` | Required | Required | Required | Required |
| `date` | Required | Required | Required | Required |
| `severity` | Required | Required | Required | Required |
| `tags` | Required | Required | Required | Required |
| `agent_source` | Required | Required | Required | Required |
| `detection` | Required | Required | Required | Required |
| `response` | Required | Required | Required | Required |
| `test_cases` | >= 1 TP + 1 TN | >= 5 TP + 5 TN | >= 5 TP + 5 TN | -- |
| `evasion_tests` | -- | >= 3 | >= 3 | -- |
| `false_positives` | -- | >= 1 | >= 1 | -- |
| `references` | -- | OWASP + MITRE | OWASP + MITRE | -- |
| `confidence` | -- | Computed | Computed | -- |
| `wild_validated` | -- | -- | Required (date) | -- |
| `wild_samples` | -- | -- | Required (>= 1000) | -- |
| `wild_fp_rate` | -- | -- | Required (<= 0.5%) | -- |
| `deprecated_reason` | -- | -- | -- | Required |
| `replaced_by` | -- | -- | -- | If applicable |

---

## Quality Gates in CI/CD

### On Every PR

1. **Schema validation** — All rules pass `atr validate`
2. **Test execution** — All `test_cases` pass (true_positives trigger, true_negatives don't)
3. **Evasion test execution** — All `evasion_tests` run, results match expectations
4. **ReDoS check** — No catastrophic backtracking patterns
5. **Benchmark regression** — SKILL.md recall >= 80%, precision >= 95%, FP rate <= 2%

### On Promotion to STABLE

6. **Wild scan validation** — Rule tested on >= 1,000 real-world skills from latest mega scan
7. **FP rate calculation** — Wild FP rate <= 0.5%
8. **Confidence score** — Computed and embedded in rule YAML
9. **Maintainer review** — At least 1 maintainer approval

### Ongoing (Post-STABLE)

10. **FP monitoring** — Community reports tracked via GitHub issues
11. **Quarterly re-validation** — Stable rules re-tested on latest wild scan data
12. **Auto-demotion** — Rules exceeding FP threshold automatically demoted

---

## Comparison to Industry Standards

| Feature | ATR | Sigma | YARA | OWASP CRS | Suricata |
|---------|-----|-------|------|-----------|----------|
| Maturity levels | 4 (draft/exp/stable/dep) | 3 (test/stable/finalized) | Informal | 3 (early/stable/opt-in) | 3 (sandbox/reg/approved) |
| Confidence score | 0-100, formula-based | No | No | No | 0-100 |
| Wild validation | Required for stable | No | Community-vetted | No | CVE-linked |
| Evasion tests | Required for experimental | No | No | No | No |
| FP rate tracking | Per-rule, wild-measured | No | No | Tag-based | Forum-based |
| Auto-demotion | Yes (FP threshold) | No | No | No | No |
| Cross-context scoring | Yes (0.7x multiplier) | N/A | N/A | N/A | N/A |

ATR is the only rule standard that requires wild-scan validation with measured FP rates and automatic demotion on quality regression.

---

## For Rule Authors

1. Start at **DRAFT**. Run `atr scaffold` to generate a template.
2. Add 5+ TP, 5+ TN, 3+ evasion tests. Run `atr test`.
3. Submit PR. CI validates schema + tests + benchmark regression.
4. Maintainers merge as **EXPERIMENTAL**.
5. After 14+ days and wild scan validation, maintainers promote to **STABLE**.

See [rule-writing-guide.md](./rule-writing-guide.md) for detailed authoring instructions.

## For Consumers

The reference engine does not enforce unless you ask it to. By default it
reports detections and returns no blocking decision, whatever maturity the
matching rules are. Choosing a posture therefore means setting two independent
switches — the **lane** (which maturities may fire) and the **blocking** opt-in
(whether ATR may act). See
[ENFORCEMENT-MODEL.md](./ENFORCEMENT-MODEL.md) for the full model.

| Posture | Lane | Blocking | Rules that fire |
|---|---|---|---|
| **Enterprise blocking** | `enforce` | on | `maturity: stable` only |
| **Alert-only monitoring** | `alert` | off | `stable` + `test` |
| **Research / evaluation** | `hunt` (default) | off (default) | every maturity except `deprecated` |

```bash
# Enterprise blocking: stable rules only, and they are permitted to act.
atr guard --lane enforce --blocking
# Equivalently, for a process you do not control the argv of:
ATR_LANE=enforce ATR_BLOCKING=1 atr guard
```

```ts
new ATREngine({ rulesDir, lane: 'enforce' });   // which rules fire
new HookHandler({ engine, executor, blocking: true });  // whether ATR may act
```

**Do not enable blocking on the `hunt` lane** unless you have measured the
false-positive cost on your own traffic. `hunt` loads every maturity, including
rules that have never been validated against real-world data.

> **The `confidence >= 80` half of this guidance is not enforceable today.** The
> 0–100 score defined in [§Confidence Score](#confidence-score) above is not
> read by the reference engine at match time; the engine derives a match
> confidence from the rule's three-valued `tags.confidence` instead. Filter on
> `maturity` (via the lane) for a threshold that actually takes effect, and treat
> the numeric confidence score as a review and promotion signal rather than a
> runtime gate.
