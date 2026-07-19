# ATR Profile Format v1.0

> **STATUS: PROPOSED v1.0 — NOT YET RATIFIED.** This specification describes
> a target profile format for community comment. No formal profile resolver
> is shipping yet in the production engine. See `STANDARDIZATION-STATUS.md`
> for full status.

**Status:** Draft for AEP-003 ratification — NOT RATIFIED
**Date:** 2026-05-25
**License:** MIT
**Required by (on ratification):** Conformance claims, sovereign sub-rule packages, F500 compliance binders

---

## Purpose

A **profile** is a named subset of the ATR rule corpus. An adopter
claims conformance to a profile, not to "all of ATR." This enables:

1. **Tiered conformance claims.** A startup can claim "ATR-baseline-
   runtime conformant" without having to run the full 427-rule
   corpus.
2. **Compliance binder mapping.** Profiles can be defined per
   regulatory framework (EU AI Act Article 50, NIST AI RMF MEASURE,
   ISO/IEC 42001 Annex). Audit pipelines consume the profile, not
   the entire corpus.
3. **Sovereign scoping.** A sovereign authority can ship a profile
   that includes its own `ATR-XX-*` rules plus the relevant canonical
   subset for its jurisdiction.
4. **Domain-specific deployment.** Financial-services agents need
   different rule coverage than healthcare agents. Profiles let
   verticals declare their relevant subset.

Profiles are inspired by NIST OSCAL `profile` format (which assembles
a subset of a control catalog) and the FedRAMP / NIST 800-53
baseline pattern (Low / Moderate / High).

---

## Profile JSON Schema reference

Machine-readable schema: `spec/schema/profile.schema.json`.

This Markdown document is the normative prose spec; JSON Schema must
match (corrected via AEP if drift).

---

## Required fields

```yaml
profile:
  schema_version: "1.0"                       # ATR profile spec version
  id: "atr-baseline-runtime"                  # globally unique profile identifier
  title: "ATR Baseline Runtime Profile"
  version: "1.0.0"                            # profile version
  description: >
    Minimum runtime detection profile for any AI agent deployment.
    Covers the high-severity attack classes that occur in every
    deployed agent runtime regardless of vertical.
  author: "ATR TSC"
  date: "2026-05-25"
  license: "MIT"
  status: "draft"                             # draft | stable | deprecated
  conformance_bound:
    spec_version_min: "1.0"
    spec_version_max: null                    # null = any future version
    minimum_rule_coverage: 1.00               # 1.0 = MUST load all included rules
    minimum_engine_passing: 1.00              # engine MUST pass 100% of conformance corpus when running this profile

inclusions:
  - rule_id: "ATR-2026-00001"                 # explicit rule ID
  - rule_id: "ATR-2026-00525"
  - rule_id_pattern: "ATR-2026-005*"          # glob pattern
  - category: "prompt-injection"              # all rules in category
  - tag_match:                                # all rules matching tag filter
      severity: ["critical", "high"]
      maturity: ["stable", "test"]

exclusions:
  - rule_id: "ATR-2026-00444"                 # explicit exclusion (overrides inclusions)
  - tag_match:
      maturity: ["draft"]                     # exclude draft rules from this profile

resolved_rules_summary:                       # populated at profile-resolution time, informative
  total: 138
  by_category:
    prompt-injection: 65
    tool-poisoning: 18
    skill-compromise: 22
    ...
```

---

## Inclusion + exclusion semantics

Profile resolution is a deterministic set-theoretic operation:

```
resolved = ∅
for incl in inclusions:
  resolved ∪= rules matching incl
for excl in exclusions:
  resolved -= rules matching excl
```

Inclusions are unioned. Exclusions are subtracted last (so an
explicit exclusion overrides any inclusion).

Engines MUST resolve profiles deterministically. Two engines loading
the same profile against the same corpus version MUST resolve to the
same rule set.

---

## Conformance bounds

Each profile declares:

- `spec_version_min` / `spec_version_max`: which ATR spec versions
  this profile is valid against.
- `minimum_rule_coverage`: fraction of included rules the engine
  must load successfully to claim conformance. Typically `1.00`.
- `minimum_engine_passing`: fraction of the conformance corpus
  test cases the engine must pass while running this profile.

A claim of "engine X is ATR-baseline-runtime conformant" requires
running the conformance corpus through the engine with this
profile loaded, and meeting both bounds.

---

## Canonical profiles published at v1.0

The TSC publishes a set of canonical profiles at
`spec/profiles/v1.0/`. Initial set:

| Profile ID | Purpose | Approximate rule count |
|---|---|---|
| `atr-baseline-runtime` | Minimum coverage for any agent runtime. Critical/high severity only, stable+test maturity. | ~130-180 |
| `atr-full-corpus` | All canonical rules at all maturity levels. | full (427+) |
| `atr-stable-only` | Only stable+tsc_approved rules. F500 compliance baseline. | ~50-80 |
| `atr-eu-aiact-art50` | Rules relevant to EU AI Act Article 50 disclosure obligations. | TBD per legal review |
| `atr-nist-rmf-measure` | Rules relevant to NIST AI RMF MEASURE function. | TBD per OSCAL mapping |
| `atr-iso42001-annex-a` | Rules relevant to ISO/IEC 42001 AIMS Annex A controls. | TBD |
| `atr-skill-supply-chain` | Rules targeting skill / package supply-chain compromise (Mini Shai-Hulud class). | ~30-50 |
| `atr-mcp-runtime-only` | Rules with scan_target=mcp only. | ~270 |
| `atr-skill-static-only` | Rules with scan_target=skill (static SKILL.md scanning). | ~80 |

Vertical-specific profiles (financial, healthcare, public-sector)
are published by the relevant working group as community profiles,
not canonical.

Sovereign-specific profiles (`atr-sovereign-de`, `atr-sovereign-sg`)
are published by the sovereign authority per their sovereign sub-
range and reviewed by the TSC for spec conformance only (not
content review — content is sovereign authority's editorial call).

---

## Versioning

Profile versioning follows SemVer:

- **PATCH** bump: rule additions to inclusions / exclusions that do
  not remove existing coverage.
- **MINOR** bump: rule removals or scope changes that affect coverage.
- **MAJOR** bump: schema changes or conformance-bound tightening.

Consumers SHOULD pin to a specific profile version
(`atr-baseline-runtime@1.0.0`) for audit reproducibility.

---

## Example — `atr-baseline-runtime` v1.0.0 (canonical)

```yaml
profile:
  schema_version: "1.0"
  id: "atr-baseline-runtime"
  title: "ATR Baseline Runtime Profile"
  version: "1.0.0"
  description: >
    Minimum runtime detection profile for any AI agent deployment.
    Covers high-severity attack classes (prompt injection, tool
    poisoning, privilege escalation, skill compromise) at stable
    and test maturity. Excludes draft, experimental, and deprecated
    rules. Designed as the bare-minimum claim for any production
    agent deployment.
  author: "ATR TSC"
  date: "2026-05-25"
  license: "MIT"
  status: "stable"
  conformance_bound:
    spec_version_min: "1.0"
    spec_version_max: null
    minimum_rule_coverage: 1.00
    minimum_engine_passing: 1.00

inclusions:
  - tag_match:
      category: ["prompt-injection", "tool-poisoning",
                 "privilege-escalation", "skill-compromise"]
      severity: ["critical", "high"]
      maturity: ["stable", "test"]

exclusions:
  - rule_status: "deprecated"
  - rule_status: "draft"
  - tag_match:
      maturity: ["draft", "experimental"]
```

---

## Example — `atr-sovereign-de` v1.0.0 (sovereign profile)

```yaml
profile:
  schema_version: "1.0"
  id: "atr-sovereign-de"
  title: "ATR German Sovereign Profile (BSI-issued)"
  version: "1.0.0"
  description: >
    Sovereign profile maintained by German BSI for use in regulated
    sectors under NIS2 / BSI-Grundschutz / German implementation of
    EU AI Act. Includes canonical baseline plus BSI-issued
    ATR-DE-* rules for German-specific threat landscape.
  author: "Bundesamt für Sicherheit in der Informationstechnik (BSI)"
  date: "2026-05-25"
  license: "MIT"
  status: "draft"
  conformance_bound:
    spec_version_min: "1.0"
    minimum_rule_coverage: 1.00
    minimum_engine_passing: 1.00

inclusions:
  - profile: "atr-baseline-runtime@1.0.0"     # inherit baseline
  - rule_id_pattern: "ATR-DE-*"               # include all DE-prefixed rules
  - tag_match:
      category: ["context-exfiltration"]      # additional DE-relevant category
      severity: ["critical", "high", "medium"]

exclusions:
  - rule_id_pattern: "ATR-2026-009*"          # de-scoped per BSI editorial
```

The `profile: "<other-profile>@<version>"` inclusion syntax enables
composition — a sovereign profile inherits baseline + adds its
sovereign-specific rules + de-scopes any rules its authority does
not endorse.

---

## Profile resolution algorithm (normative)

```python
def resolve_profile(profile, corpus, recursion_guard):
    if profile.id in recursion_guard:
        raise ProfileCircularReference(profile.id)
    recursion_guard.add(profile.id)

    resolved = set()

    for incl in profile.inclusions:
        if incl.profile:
            base_profile = corpus.profiles[incl.profile_id]
            resolved |= resolve_profile(base_profile, corpus, recursion_guard)
        if incl.rule_id:
            resolved.add(corpus.rules[incl.rule_id])
        if incl.rule_id_pattern:
            resolved |= {r for r in corpus.rules if fnmatch(r.id, incl.rule_id_pattern)}
        if incl.category:
            resolved |= {r for r in corpus.rules if r.tags.category == incl.category}
        if incl.tag_match:
            resolved |= {r for r in corpus.rules if matches_tag_filter(r, incl.tag_match)}

    for excl in profile.exclusions:
        if excl.rule_id:
            resolved.discard(corpus.rules[excl.rule_id])
        if excl.rule_id_pattern:
            resolved -= {r for r in corpus.rules if fnmatch(r.id, excl.rule_id_pattern)}
        if excl.tag_match:
            resolved -= {r for r in corpus.rules if matches_tag_filter(r, excl.tag_match)}
        if excl.rule_status:
            resolved -= {r for r in resolved if r.status == excl.rule_status}

    recursion_guard.remove(profile.id)
    return resolved
```

Circular profile references are an error. Resolution depth is
unbounded by spec; engines MAY impose a depth limit for performance,
which MUST be ≥ 10.

---

## References

- NIST OSCAL Profile model: https://pages.nist.gov/OSCAL/concepts/layer/profile/profile/
- NIST 800-53 baselines (Low/Moderate/High): https://csrc.nist.gov/publications/detail/sp/800-53b/final
- FedRAMP profile pattern: https://www.fedramp.gov/baselines/
- SemVer 2.0: https://semver.org/
- ATR Rule Format Spec v1.0: ATR-SPEC-v1.md
- ATR Category Registry v1.0: spec/category-registry/v1.0.yaml
