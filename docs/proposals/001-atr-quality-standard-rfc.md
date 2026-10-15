# RFC-001: ATR Quality Standard v1.0

> **ERRATUM (added 2026-09-22).** This is a dated historical artifact, preserved as
> published. Figures quoted below have since been withdrawn or frozen and must not be
> cited as current fact:
>
> - **Ecosystem / wild scan.** The "96,096 skills scanned" and "751 confirmed malware"
>   figures are frozen. The only externally citable wild-scan figures are
>   **101,280 items scanned / 1,434 flagged** (engine v2.0.0, as of 2026-04-13). See
>   `docs/research/wild-scan-drift.md`, which also explains why the confirmed-malicious
>   count is a triage floor and not a precision figure.
> - **Precision / false-positive rate.** "99.7% precision" and the paired "0.3% FP rate"
>   were withdrawn on 2026-06-15 and should not be cited by anyone, including this
>   project. The per-lane FP rates published afterwards were withdrawn as well. Current
>   version-pinned measurements live in README section 8 and `data/stats.json`.
> - **Downstream adoption.** A merged pull request into an open-source repository such as
>   `cisco-ai-defense/skill-scanner` is not a vendor product shipment or endorsement.
>   `ADOPTERS.md` is the source of truth, with per-entry PR evidence.
>
> Rule counts, version numbers and adopter lists below are point-in-time and have moved.
> Nothing below has been rewritten; this note is the correction of record.
## The Open Detection Standard for the AI Agent Era

**Status:** Ready for Publication
**Version:** 1.1
**Effective:** 2026-04-14
**Authors:** ATR Project Maintainers
**Target:** Public RFC — any AI agent security scanner can adopt
**Reference Implementation:** `src/quality/` in this repo (MIT License)
**Companion Paper:** forthcoming

---

## Preamble

Every Fortune 500 will deploy AI agents in production by 2027. Almost none of them have a detection layer today.

The CISOs do not know this yet. We do, because we scanned 67,597 agents across OpenClaw, Claude Code, Cursor, Windsurf, and the Skills.sh registry. We found 10,275 threats. 875 were CRITICAL. Most are still live.

This document is the specification for catching them.

### The landscape as of April 2026

In the last twelve months the agent-security ecosystem formalized three reference frameworks:

- **OWASP Top 10 for Agentic Applications 2026** — peer-reviewed by more than 100 industry experts, researchers, and practitioners, published December 14, 2025. The first taxonomy built specifically for autonomous AI agents that plan, decide, and act across tools and steps.
- **MITRE ATLAS v5.4.0** (February 2026) — 16 tactics, 84 techniques, 56 sub-techniques, 42 real-world case studies. In October 2025 ATLAS integrated 14 new agent-specific techniques in collaboration with Zenity Labs, including AI Agent Context Poisoning, Memory Manipulation, Thread Injection, and Modify AI Agent Configuration. February 2026 added *Publish Poisoned AI Agent Tool* and *Escape to Host*.
- **SAFE-MCP** — formally adopted under the Linux Foundation and the OpenID Foundation. 14 tactic categories and 80+ techniques covering MCP-specific attack surface, with contributions from Meta, eBay, Okta, Red Hat, Intel, and American Express.

These three frameworks answer *what* can go wrong with an AI agent. They do not answer *how to detect it*.

In parallel, runtime-vendor solutions landed:

- **Claude Managed Agents** — launched public beta on April 8, 2026, three days before the effective date of this specification. A managed runtime for Claude agents with sandboxing, identity, execution tracing, and persistent memory. Billed at $0.08 per session-hour plus token cost. Customers include Notion, Rakuten, and Asana.
- **Microsoft Agent Governance Toolkit** — published April 2, 2026 under MIT license. The first toolkit to target all 10 OWASP Agentic risks with deterministic sub-millisecond policy enforcement.
- **Cisco AI Defense MCP Scanner** — open-sourced 2026. The `cisco-ai-defense/skill-scanner` repository merged 34 ATR rules upstream via `skill-scanner/#79`; this is an open-source repository merge, not a statement about a Cisco commercial product.
- **Invariant Labs mcp-scan** — de facto standard MCP scanner (now a Snyk product).
- **Adversa AI SecureClaw** — won "Most Innovative Agentic AI Security" at RSA Conference 2026 Global InfoSec Awards (March 2026). Open-source, OWASP-aligned agent security platform.
- **Zenity** — showcased open-source AI agent security tools at RSA Conference 2026. Collaborated with MITRE ATLAS on 14 agent-specific techniques added in October 2025.

These runtime offerings are valuable. They are also bounded. Anthropic does not secure OpenAI agents. OpenAI does not secure Anthropic. Neither secures a Cursor installation on a developer's laptop, a self-hosted MCP stack inside an enterprise VPC, or a locally-run LLaMA agent reading customer documents on a contractor's machine. Ninety-five percent of agent workloads in 2026 run outside any single managed runtime. Those workloads have no safety layer.

There is no Sigma for agents. No YARA for prompt injection. No Snort for tool poisoning.

ATR is that layer. This document is its specification.

### What has been tried, and why it is not enough

**The runtime-vendor approach.** Every agent runtime will eventually ship its own guardrails. That is good. It is also structurally insufficient, because an open standard must live *above* any single vendor's runtime. A rule that Anthropic ships inside Claude Managed Agents cannot also run inside Cursor, OpenAI Assistants, or a customer's on-prem deployment, unless the rule itself is expressed in a vendor-neutral format with a vendor-neutral evaluator. That format does not exist today outside ATR.

**The classical-security approach.** CrowdStrike watches processes. Microsoft Defender watches files. Neither can see a prompt injection that tells Claude to exfiltrate a customer database through a legitimately-invoked, properly-signed tool call. The attack happens inside the context window — a place classical security does not look, because classical security was built for a world where control flow and data flow were separable. In AI agents, control flow and data flow collapse into the same channel. Every legitimate instruction and every attack arrives as the same kind of token in the same prompt window. This is not a patch. It is the end of the perimeter-defense era.

**The taxonomy-without-detection approach.** OWASP Top 10, MITRE ATLAS, and SAFE-MCP are excellent taxonomies. A taxonomy tells you a category exists. A taxonomy does not detect anything at runtime. An engineer reading OWASP ASI02 (Prompt Injection) cannot paste the definition into a CI job and get a verdict. A SIEM cannot ingest SAFE-T1102 and start alerting. Taxonomies are nouns; defenders need verbs. The verbs are detection rules, and rules need a quality bar — which is where this document begins.

### First-principles requirements

If there were no existing standards and we had to invent one from first principles, it would need to satisfy six requirements:

1. **Machine-executable.** A rule must run without human interpretation. You paste YAML, you get verdicts. No judgment calls, no "consult the analyst."
2. **Vendor-neutral.** The standard must not favor any single runtime, model, or cloud. A Fortune 500 running agents on Anthropic, OpenAI, and self-hosted LLaMA should use the same rule set on all three.
3. **Empirically grounded.** Quality claims must be reproducible on published benchmarks — PINT, MCPTox, or a declared wild-scan corpus. No "trust us."
4. **Self-correcting.** As attacks evolve, rules must evolve. As rules mis-fire, they must be demoted. The standard must build these feedback loops in, not bolt them on afterward.
5. **Honest about limits.** Every rule must document its known evasions, false positives, and coverage gaps. A rule that claims 100% precision without evidence is a liability, not an asset.
6. **Community-extensible.** No single vendor can write enough rules fast enough. The standard must make third-party contributions safe to accept, fast to validate, and traceable in their chain of custody.

This document specifies a standard that meets all six.

---

## Summary

Define a vendor-neutral quality standard for AI agent threat detection rules.
Provide a scoring algorithm, a validation library, and a reference pipeline
that any scanner (ATR, Cisco AI Defense, Snyk mcp-scan, Microsoft AGT, etc.)
can adopt. The goal is not to lock in ATR's rule format — it is to make rule
quality measurable and comparable across vendors.

## Motivation

Today, every AI agent security vendor publishes rules without a common quality
bar. A consumer asking "can I trust rule X in production?" has no answer. Each
vendor claims their rules are high quality; none can prove it in a comparable
way.

Existing rule ecosystems solved this:

- **Sigma** — test → stable → finalized maturity levels
- **YARA** — community vetting, per-rule confidence scoring
- **Snort/Suricata** — sandbox → registered → approved tiers
- **OWASP CRS** — early-release → stable → opt-in with FP rate tags

AI agent rules are a new category. There is no equivalent standard. ATR
proposes to define one, publish it as open RFC, and ship a reference
implementation any vendor can adopt.

**Design principle:** the standard must be useful to someone who does not ship
ATR rules. A Cisco rule, a Snyk rule, or a rule written by hand must all pass
through the same validator and receive comparable scores.

## Non-Goals

- **Not a rule format standard.** This RFC does not mandate ATR YAML. A vendor
  using YARA-style rules, Sigma rules, or a proprietary format can still adopt
  the scoring algorithm by providing an adapter that extracts the required
  metadata.
- **Not a certification program.** There is no "ATR certified" badge. Scores
  are published; consumers decide their own threshold.
- **Not a replacement for existing standards.** OWASP LLM Top 10, MITRE ATLAS,
  and OWASP Agentic Top 10 are taxonomies. This RFC is about rule quality, not
  threat classification.

## Specification

### 1. Maturity Levels

Every rule declares exactly one maturity level.

| Level | Meaning | Promotion gate |
|-------|---------|----------------|
| `draft` | Submitted, not yet validated | Valid YAML/JSON, at least 1 TP + 1 TN |
| `experimental` | CI-validated, limited evidence | 3 TP + 3 TN + CI pass (evasion tests, OWASP/MITRE mapping encouraged, not required) |
| `stable` | Wild-validated, enterprise-ready | 14+ days in experimental + wild scan ≥1000 samples + FP rate ≤0.5% + confidence ≥80 |
| `deprecated` | Superseded or no longer relevant | Replacement rule ID documented |

**Automatic demotion.** A `stable` rule with wild FP rate >2% or 3+ unresolved
FP reports in 30 days is demoted to `experimental` without human review.

### 2. Confidence Score (0–100)

Every rule at `experimental` or above has a numeric confidence score computed
by a well-defined formula. The formula is:

```
confidence = round(
    precision_score     * 0.40
  + wild_validation     * 0.30
  + coverage_score      * 0.20
  + evasion_docs        * 0.10
)
```

Where each component is in [0, 100]:

| Component | Formula | Intuition |
|-----------|---------|-----------|
| `precision_score` | `(1 - measured_fp_rate) * 100` | How often the rule is right when it fires |
| `wild_validation` | `min(wild_samples / 10000, 1) * 100` | How much real-world data has seen this rule |
| `coverage_score` | `min(conditions / 5, 1) * 100` | Defense in depth — more layers = higher |
| `evasion_docs` | `min(documented_evasions / 5, 1) * 100` | Honest acknowledgment of known bypasses |

**Cross-context penalty.** If a rule designed for one scan context (e.g. MCP
runtime) fires in a different context (e.g. SKILL.md static scan), the
contribution is multiplied by `0.7`. This is computed per-match, not baked
into the rule's stored score.

**Score bands and deployment guidance:**

| Score | Label | Recommended deployment |
|-------|-------|------------------------|
| 90–100 | Very High | Blocking mode in production |
| 80–89  | High | Blocking mode with monitoring |
| 60–79  | Medium | Alert-only |
| 40–59  | Low | Evaluation / research |
| <40    | Draft | Do not deploy |

### 2.5 Two-Dimensional Compliance Model

**Differentiator from existing standards.** Traditional rule standards (Sigma,
YARA, OWASP CRS) answer the question "does the rule have the required
metadata?" They treat compliance as binary: present or missing. This creates
a perverse incentive — vendors pad metadata to pass the check without doing
the underlying work.

ATR Quality Standard introduces a second dimension: **who verified the
metadata**. Every field that requires a subjective judgment (MITRE mapping,
OWASP category, false positive documentation) carries a `metadata_provenance`
value:

| Provenance | Meaning | Accepted at |
|-----------|---------|-------------|
| `human-reviewed` | A maintainer verified this mapping | all levels |
| `community-contributed` | Submitted via PR, reviewed by maintainers | all levels |
| `auto-generated` | Filled by a script without human review | draft, experimental only |
| `llm-generated` | Produced by the TC crystallization flywheel | draft, experimental only |

**Why two dimensions matter.**

A rule with `mitre_atlas: "AML.T0051"` and `metadata_provenance.mitre_atlas:
auto-generated` is technically compliant — the field is present. But
downstream consumers know the mapping was not human-verified. They can
filter it out if they need strong guarantees (e.g. for regulated
environments) or accept it if they just want broad coverage.

**Compliance at each level:**

- `draft`: Dimension 1 only (metadata present)
- `experimental`: Dimension 1 only (any provenance accepted)
- `stable`: Dimension 1 **and** Dimension 2 (provenance must be `human-reviewed` or `community-contributed`)

This creates a **progressive trust ladder**:

```
auto-generated metadata        → rule passes experimental
→ human reviews the mapping    → provenance: human-reviewed
→ rule eligible for stable     → deployable in production
```

No existing rule standard has this. It is the mechanism that makes "ship
fast" and "stay honest" compatible.

### 3. Required Metadata

Every rule must expose the following metadata (the exact field names can differ
per vendor; the semantics must match):

**Required for `experimental`:**

- Unique rule ID
- Human-readable title
- Severity (`critical` | `high` | `medium` | `low` | `informational`)
- At least 1 detection condition (regex, fingerprint, or behavioral pattern)
- At least 3 true positives (real attack payloads)
- At least 3 true negatives (similar-looking legitimate content)
- Evasion tests encouraged but not required (contributes to confidence score)
- OWASP reference encouraged but not required (contributes to confidence score)
- MITRE reference encouraged but not required (contributes to confidence score)
- False positive documentation encouraged but not required

> **v1.1 note (2026-04-12):** The experimental gate was relaxed from 5/5/3
> (TP/TN/evasion) to 3/3/0 to lower the contribution barrier. Community
> velocity matters more than metadata completeness at the experimental tier.
> The stable tier (§3 below) retains the full requirements as the production bar.

**Additionally required for `stable`:**

- At least 5 true positives and 5 true negatives
- At least 3 evasion tests with documented bypass techniques
- At least 1 OWASP reference and 1 MITRE reference
- At least 1 documented false positive pattern
- `wild_validated` date
- `wild_samples` count (≥1000)
- `wild_fp_rate` (≤0.5%)
- `confidence` score (≥80)
- All `metadata_provenance` fields must be `human-reviewed` or `community-contributed`

### 4. Validation Library

ATR ships `@agent-threat-rules/quality` as a reference implementation. The
library exposes:

```typescript
// Pure functions, no I/O
export function computeConfidence(rule: RuleMetadata): ConfidenceScore;
export function validateMaturity(rule: RuleMetadata, level: Maturity): ValidationResult;
export function canPromote(rule: RuleMetadata, wildStats: WildStats): PromotionDecision;
export function shouldDemote(rule: RuleMetadata, recentFpReports: FpReport[]): DemotionDecision;
```

Where `RuleMetadata` is a minimal interface any vendor can implement:

```typescript
interface RuleMetadata {
  id: string;
  title: string;
  severity: Severity;
  maturity: Maturity;
  conditions: number;          // count of detection layers
  truePositives: number;
  trueNegatives: number;
  evasionTests: number;
  hasOwaspRef: boolean;
  hasMitreRef: boolean;
  hasFalsePositiveDocs: boolean;
  wildSamples?: number;
  wildFpRate?: number;
  wildValidatedAt?: string;
}
```

A vendor using a non-ATR rule format writes an adapter:

```typescript
// Example: Sigma adapter
function sigmaToMetadata(sigmaRule: SigmaRule): RuleMetadata { ... }

// Example: YARA adapter
function yaraToMetadata(yaraRule: YaraRule): RuleMetadata { ... }
```

Once adapted, any rule can be scored with the same formula. A Cisco rule and
an ATR rule become directly comparable.

### 5. Adoption Path

Adoption is voluntary and incremental.

**Level 1 — Compute scores:**
Any vendor imports `@agent-threat-rules/quality`, writes an adapter for their
rule format, and computes confidence scores. Scores can be displayed in scan
output or used internally for tuning.

**Level 2 — Declare maturity:**
Vendor sets `maturity` field on each rule per this RFC's promotion gates.
Consumers can filter rules by minimum maturity.

**Level 3 — Publish wild stats:**
Vendor runs wild validation and publishes per-rule `wild_samples` and
`wild_fp_rate`. This enables `stable` status.

**Level 4 — Cross-vendor federation:**
Multiple vendors publish their rule metadata in a common format (this RFC).
Consumers can compare rules across vendors on the same axes. No vendor is
locked in.

### 6. Threat Ontology Mapping

Every rule at `experimental` or above must map to at least one entry in each of two required taxonomies, plus optionally a third, using the fields below.

| Taxonomy | Version | Field | Required at experimental+ |
|---|---|---|---|
| OWASP Top 10 for LLM Applications | 2025 | `references.owasp_llm` | At least one of `owasp_llm` or `owasp_agentic` must be present |
| OWASP Top 10 for Agentic Applications | 2026 (Dec 14, 2025) | `references.owasp_agentic` | (see above) |
| MITRE ATLAS | v5.4.0+ (Feb 2026) | `references.mitre_atlas` or `references.mitre_attack` | Required |
| SAFE-MCP | current | `references.safe_mcp` | Optional but strongly recommended for rules targeting MCP context |

**Why three taxonomies and not one.** Each framework covers a different slice of the same space. OWASP is organized by **impact** (what the attacker achieves, e.g. *Agent Behavior Hijacking*). MITRE ATLAS is organized by **technique** (how the attacker operates, e.g. *AI Agent Context Poisoning*). SAFE-MCP is organized by **protocol surface** (where the attack touches MCP specifically, e.g. *SAFE-T1102 Prompt Manipulation*). A rule that can be described along all three axes is more useful to defenders than a rule describable along only one.

**The detection surface is wider than any single taxonomy.** MITRE ATLAS added 14 agent-specific techniques in late 2025 and *Publish Poisoned AI Agent Tool* in February 2026. ATR rules had been catching the corresponding patterns for months before those taxonomy updates landed. **The taxonomies are how the community describes what has already been happening.** The detection layer must move faster than the taxonomy layer, then feed its findings back upstream.

**A rule that cannot be mapped to any of the three taxonomies is either novel or incorrectly scoped.** If it is novel, the taxonomy committees should hear about it — the RFC recommends that vendors open issues against OWASP / ATLAS / SAFE-MCP when new attack classes are discovered. If it is incorrectly scoped, the rule is likely detecting something that is not actually an agent-specific threat and should be rewritten or rejected. The gate enforces this as a hard blocker at experimental level.

### 7. Multi-Runtime Compatibility

Agent runtimes differ materially in how they expose tool descriptions, user input, agent memory, and inter-agent messages. A rule that fires correctly on Claude Code may be structurally unable to fire on Cursor, and a rule validated on Anthropic's Claude Managed Agents may not apply to OpenAI Assistants because the field shapes are different. The standard must surface these differences explicitly rather than pretend all agents are the same shape.

Every rule at `experimental` or above declares its runtime coverage:

```yaml
runtimes:
  compatible:        # runtimes where this rule is known to work
    - claude-code
    - cursor
    - windsurf
    - anthropic-managed
  tested_on:         # runtimes where the rule has been wild-validated
    - claude-code
    - cursor
  caveats:           # known differences
    - runtime: openai-assistants
      note: "tool_description field is shorter than MCP spec; rule may under-match"
```

**Normative runtime identifiers.** The canonical registry is maintained in `docs/RUNTIMES.md` in this repository. Adding a new runtime requires a PR to `RUNTIMES.md`, not an RFC addendum. The registry format is: lowercase identifier, hyphen-separated, one line per runtime. Initial set:

| Identifier | Runtime | Scan target format |
|---|---|---|
| `claude-code` | Anthropic Claude Code CLI | SKILL.md, MCP config |
| `cursor` | Cursor IDE | MCP config |
| `hermes` | Hermes Agent (Nous Research) | SKILL.md, MCP config (YAML) |
| `windsurf` | Codeium Windsurf | MCP config |
| `anthropic-managed` | Claude Managed Agents (April 2026+) | MCP tool descriptions |
| `openai-assistants` | OpenAI Assistants API v2+ | Tool descriptions |
| `openai-gpts` | OpenAI custom GPTs | Tool descriptions |
| `google-gemini-agents` | Google Gemini Agent Builder | Tool descriptions |
| `google-a2a` | Google Agent-to-Agent Protocol | A2A agent cards |
| `microsoft-agt` | Microsoft Agent Framework 1.0 | Semantic Kernel plugins |
| `langgraph` | LangChain LangGraph | Tool definitions |
| `local-llama` | Self-hosted LLaMA-family agent | Varies |
| `local-mistral` | Self-hosted Mistral-family agent | Varies |
| `self-hosted-mcp` | Any self-hosted MCP server / client | MCP tool descriptions |

**Cross-runtime confidence multiplier.** When a rule fires on a runtime not listed in `tested_on`, the effective confidence contribution is multiplied by `0.7`. This is a runtime-level analogue of the per-context penalty in §2 and is applied at match time, not stored in the rule.

**Why this is novel.** Sigma rules assume a SIEM; they do not differentiate Splunk from QRadar because the underlying log semantics are shared. YARA rules assume binary files; the platform is irrelevant. Agent detection rules do not have that luxury — MCP tool descriptions in Claude Code and OpenAI Assistants have different maximum lengths, different escaping rules, and different places where user-controlled text can land. A standard that ignores this ships rules that silently fail on half the ecosystem.

### 8. Review Tier Levels

Every rule carries a review tier (`review_tier`) that records how much human and machine scrutiny the rule has received. Tiers are strictly additive — a rule at L3 has passed everything at L0, L1, and L2.

| Tier | Name | Gate |
|---|---|---|
| **L0** | Schema Only | YAML/JSON parses, required fields present |
| **L1** | Self-Test Passed | Rule's own regex matches all its `true_positives` and rejects all its `true_negatives` |
| **L2** | LLM-Reviewed | An LLM reviewer has judged the rule and stored a verdict (approved, rejected, or flagged) with written reasoning |
| **L3** | Human-Reviewed | At least one human maintainer has approved the rule against the experimental checklist |
| **L4** | Wild-Validated | Rule has been executed against ≥1,000 real-world samples with FP rate recorded |
| **L5** | Community-Confirmed | At least 3 independent reporters have confirmed the rule's detection on distinct traffic |

**Gate mapping:**

- `draft` requires L0 + L1
- `experimental` requires L0 + L1 + (L2 or L3)
- `stable` requires L0 + L1 + L3 + L4 + L5

**LLM-assisted review as a first-class citizen.** No existing detection-rule standard — Sigma, YARA, Snort, or OWASP CRS — acknowledges LLM-assisted review as a legitimate quality tier. Those standards were designed before LLMs were capable enough to act as reviewers. ATR is the first standard to incorporate LLM review explicitly into the quality pipeline. The tier is deliberately placed at L2, below L3 human review, to avoid the temptation to over-rely on it. LLM review is fast and scales well; human review is slow and scales badly but catches things the LLM misses. The standard accepts both and requires the combination for stable promotion.

**Self-test at L1 is non-negotiable.** A rule whose own regex cannot match its own declared true positives is broken regardless of how good the surrounding metadata looks. This check is cheap, objective, and catches the most common failure mode of LLM-generated rules (pattern syntax drift). The reference implementation runs self-tests automatically at crystallization time.

### 9. Community Signal Aggregation

A stable standard needs a feedback loop from the world back into the rule set. Traditional detection-rule ecosystems grew these loops organically — Sigma and YARA rely on maintainer review, GitHub issues, and occasional community fire-drills. ATR formalizes the loop so the same infrastructure works across vendors.

**Signal types.** Every rule at experimental or above accepts and aggregates the following community signals:

| Signal | Meaning | Impact on rule |
|---|---|---|
| `confirmations` | Independent reporter saw this rule's pattern in the wild | Contributes to L5 promotion |
| `fp_reports` | Consumer flagged a specific match as a false positive | Contributes to automatic demotion |
| `sightings_in_wild` | Rule fired on a wild-scan run | Contributes to `wild_samples` count |
| `cross_runtime_matches` | Rule fired on a runtime not in `tested_on` | Contributes to `runtime_caveats` |
| `evasion_reports` | Consumer demonstrated a working bypass | Contributes to `evasion_tests` after verification |

**Threshold rules** (reference implementation):

- A rule promoting from experimental to stable requires at least 3 `confirmations` from distinct client IDs.
- A stable rule with 3+ unresolved `fp_reports` in 30 days is automatically demoted to experimental.
- A rule with 5+ `evasion_reports` that the maintainer has not addressed is automatically flagged in scan output as "contested".

**Anonymity and provenance.** Community signals must preserve reporter identity at the aggregator level (for rate-limiting, abuse detection, and uniqueness counting) but must not leak reporter identity in published rule metadata. The reference implementation uses hashed client IDs with per-rule salts so the same reporter counts once per rule but cannot be correlated across rules by an observer reading the public feed.

**Why this is novel.** Sigma, YARA, and Snort grew their community signal loops after years of use; they were not specified upfront. This RFC specifies the loop as part of the standard because ATR's crystallization flywheel already produces these signals today and needs a contract with downstream consumers about how to interpret them. Specifying the signal types makes the flywheel auditable by third parties rather than opaque to them.

---

## Reference Implementation

ATR will ship the reference implementation in this repo:

```
src/quality/
  index.ts              // Public API
  types.ts              // RuleMetadata, ConfidenceScore, etc.
  compute-confidence.ts // The scoring formula
  validate-maturity.ts  // Promotion gate checks
  adapters/
    atr.ts              // ATR YAML → RuleMetadata
    sigma.ts            // Sigma YAML → RuleMetadata (optional)
    yara.ts             // YARA → RuleMetadata (optional)
```

Published as part of `agent-threat-rules` on npm. No separate package. Other
vendors import it directly or copy the formula.

## Outreach & Ecosystem

Once the reference implementation ships, ATR will:

1. Open a PR to each of these projects inviting them to adopt the scoring
   algorithm (not the rule format, just the formula):
   - **Cisco AI Defense** (via their OSS scanner repo)
   - **Snyk Invariant / mcp-scan**
   - **Microsoft Agent Governance Toolkit**
   - **Portkey Gateway**
   - **Meta PurpleLlama**

2. Publish the RFC at `atr.dev/rfc/001` (or equivalent) with a public
   comment period.

3. Submit the scoring algorithm as an extension to the OWASP Agentic Top 10
   working group and the MITRE ATLAS project.

## Open Questions

1. **Who maintains the standard?** If multiple vendors adopt it, decisions
   about changes (new fields, threshold adjustments) need a governance model.
   Options: ATR maintainers only / rotating chair / OWASP working group / CSA
   foundation.

2. **Backward compatibility.** Once v1.0 ships and vendors adopt it, how do
   future versions avoid breaking existing rule sets? Proposal: semantic
   versioning, with breaking changes only at major versions, and a migration
   tool that upgrades metadata between versions.

3. **Wild validation fairness.** A vendor with access to large scan corpora
   (53K+ skills) can promote rules to `stable` faster than a vendor without.
   This creates a data moat. Should wild stats from any corpus count, or
   should there be a canonical "reference corpus" all vendors validate
   against? Analogy: PINT benchmark for prompt injection.

4. **LLM-generated rules.** If a rule is generated by an LLM (e.g. via ATR's
   crystallization pipeline), should its initial confidence be capped until
   human review? Proposal: yes, cap at 70 until a human reviewer approves.

## Alternatives Considered

### Alternative 1: Proprietary internal scoring

Keep quality scoring as ATR-internal logic. Simpler, but limits the
standard's impact — other vendors cannot use it, so it never becomes a
common language.

**Rejected because:** the goal is to define the industry standard, not to
build ATR moats.

### Alternative 2: Leave it to OWASP / CSA

Wait for OWASP Agentic Top 10 or CSA Agentic AI Foundation to define a
quality standard. Safer politically, but they are currently focused on
taxonomy (what threats exist), not rule quality (how well a given rule
detects them).

**Rejected because:** someone has to start. ATR has the data and the rule
set. Waiting means the standard gets defined by whoever moves first, and
that may be a vendor with worse positioning for openness.

### Alternative 3: Copy Sigma's model exactly

Sigma has `test → stable → finalized`. Copy it verbatim.

**Rejected because:** Sigma's model assumes human maintainers grade every
rule. ATR's flywheel generates rules at machine speed, so the promotion
gates need wild validation metrics, not just human review. The levels are
similar but the gates are different.

## References

**Reference frameworks cited in the Preamble and §6 (Threat Ontology Mapping):**

1. OWASP Gen AI Security Project, *OWASP Top 10 for Agentic Applications 2026*. Published December 14, 2025. <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
2. OWASP Gen AI Security Project, *OWASP Top 10 for LLM Applications 2025*. <https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/>
3. MITRE Corporation, *ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)*. v5.4.0, February 2026. <https://atlas.mitre.org/>
4. Zenity Labs and MITRE ATLAS, *14 Agent-Specific Techniques Added to ATLAS* (October 2025). Includes AI Agent Context Poisoning, Memory Manipulation, Thread Injection, Modify AI Agent Configuration. <https://zenity.io/blog/current-events/mitre-atlas-ai-security>
5. MITRE Corporation, *MITRE ATLAS OpenClaw Investigation*. PR-26-00176-1, February 2026. <https://www.mitre.org/sites/default/files/2026-02/PR-26-00176-1-MITRE-ATLAS-OpenClaw-Investigation.pdf>
6. SAFE-MCP Project (Linux Foundation / OpenID Foundation), *Security Analysis Framework for Evaluation of MCP*. <https://github.com/safe-agentic-framework/safe-mcp>

**Runtime offerings referenced in the Preamble:**

7. Anthropic, *Claude Managed Agents*. Public beta launched April 8, 2026. <https://platform.claude.com/docs/en/managed-agents/overview>
8. Microsoft, *Introducing the Agent Governance Toolkit: Open-source runtime security for AI agents*. April 2, 2026. <https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/>
9. Cisco, *Securing the AI Agent Supply Chain with Cisco's open-source MCP Scanner*. <https://blogs.cisco.com/ai/securing-the-ai-agent-supply-chain-with-ciscos-open-source-mcp-scanner>
10. Snyk Labs (formerly Invariant Labs), *mcp-scan: Prompt Injection and Tool Poisoning Detection for MCP*. <https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/>
11. Adversa AI, *SecureClaw: Open-Source OWASP-Aligned Agent Security Platform*. RSA Conference 2026 Global InfoSec Awards winner. <https://www.prnewswire.com/news-releases/adversa-ai-wins-most-innovative-agentic-ai-security-platform-at-global-infosec-awards-during-rsa-conference-2026-302730963.html>
12. Zenity, *Open-Source AI Agent Security Tools*. Showcased at RSA Conference 2026. <https://www.tipranks.com/news/private-companies/zenity-showcases-open-source-ai-agent-security-tools-at-rsa-conference>
13. OWASP GenAI Security Project, *AI Security Solutions Landscape for Agentic AI Q2 2026*. <https://genai.owasp.org/resource/ai-security-solutions-landscape-for-agentic-ai-q2-2026/>

**Benchmarks referenced for empirical grounding (§2 Confidence Score, First-Principles Requirement 3):**

14. Lakera, *Prompt Injection Test (PINT) Benchmark*. <https://github.com/lakeraai/pint-benchmark>
15. *MCPTox: Tool Poisoning Benchmark for MCP Agents*. 20 LLM agents, 45 real-world MCP servers, 353 authentic tools. o1-mini attack success rate 72.8%.

**Prior-art rule standards (§0.5 First-Principles Requirements, Alternative 3):**

16. SigmaHQ, *Sigma Rules Specification*. Status progression: `experimental` → `test` → `stable` → `deprecated`, ~1 year to stable. <https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html>
17. YARA Project, *Writing YARA Rules*. Community-vetted, no formal maturity tiers.
18. Snort / Suricata, *Emerging Threats Rule Sets*. Tier progression: sandbox → registered → approved.
19. OWASP ModSecurity Core Rule Set (CRS), *Paranoia Levels*. Tiered deployment model with per-rule FP rate tags.

**ATR empirical baselines referenced in this RFC:**

20. ATR Project, *96,096 Agent Skills Scanned Across OpenClaw, Claude Code, Cursor, Hermes, Skills.sh, MCP Registry*. April 2026. 1,302 flagged (1.35%), 751 confirmed malware. **[Erratum 2026-09-22: the figures in this cited title are frozen and must not be requoted. The only citable wild-scan figures are 101,280 scanned / 1,434 flagged, engine v2.0.0, 2026-04-13 — see `docs/research/wild-scan-drift.md`.]**
21. ATR Project, *Cisco skill-scanner PR #79*. 34 ATR rules merged upstream into the open-source `cisco-ai-defense/skill-scanner` repository. April 2026. **[Erratum 2026-09-22: a merged PR into an open-source repository is not a shipment in, or an endorsement by, any Cisco commercial product.]**
22. Adversa AI, *Top Agentic AI Security Resources — April 2026*. <https://adversa.ai/blog/top-agentic-ai-security-resources-april-2026/>

## Future Work

The following areas are explicitly out of scope for RFC-001 v1.x but are
recognized as necessary for the standard's evolution. Each is expected to
become a separate RFC.

### RFC-002: Detection Type Taxonomy

RFC-001 assumes `pattern` detection (regex/string match on text). The agent
attack surface is expanding to:

- **Behavioral sequences** — an agent that reads `~/.ssh/id_rsa` then makes
  an HTTP POST is suspicious not because of either action alone, but because
  of the sequence. Detecting this requires temporal pattern matching across
  multiple tool calls.
- **Multimodal attacks** — prompt injection embedded in images, audio, or
  structured data. Text regex cannot catch these.
- **Composite rules** — meta-rules that fire when 2+ individual rules match
  within the same session (e.g. credential access + network exfiltration).

RFC-002 will define a `detection_type` field (`pattern` | `behavioral` |
`multimodal` | `composite`) and specify how the confidence formula adapts for
non-pattern rules.

### RFC-003: Collective Defense Protocol

Every scan — whether from a CLI install, a website paste, or a CI/CD action —
generates threat intelligence. RFC-001 describes individual rule quality but
does not specify how scanners contribute to and consume from a shared threat
feed.

RFC-003 will define:
- Signal submission API (anonymized threat events, skill hashes, FP reports)
- Signal aggregation and deduplication
- Feed distribution (public community feed vs private enterprise feed)
- Privacy guarantees (what data leaves the device, what stays local)

This formalizes the Threat Cloud flywheel as a vendor-neutral protocol any
scanner can participate in.

### RFC-004: Enterprise Deployment Guidance

Enterprises deploying 20–500 AI agents need:
- **Unified rule policy** — which rules run in blocking mode, which in alert-only
- **Compliance reporting** — EU AI Act (August 2026), SOC 2, ISO 27001 mapping
- **Private rule feeds** — enterprise-specific rules that never reach the public feed
- **Multi-agent visibility** — which agents are installed, which rules protect them
- **Role-based access** — security team vs developers vs compliance

RFC-004 will define deployment tiers (Free / Team / Enterprise) and the
management API surface each tier exposes.

## Changelog

- **2026-04-15**: v1.1.1 — Updates Preamble with RSA 2026 entrants (Adversa AI SecureClaw, Zenity). Adds OWASP Q2 2026 AI Security Solutions Landscape reference. Updates wild scan numbers to 96K (was 53K). Renumbers references.
- **2026-04-14**: v1.1 published. Relaxes experimental gate from 5/5/3 to 3/3/0 (TP/TN/evasion). Adds Hermes Agent, Google A2A, LangGraph to runtime registry. Moves runtime registry to extensible `RUNTIMES.md`. Adds scan target format column. Adds Future Work section (RFC-002 Detection Types, RFC-003 Collective Defense, RFC-004 Enterprise Deployment). Clarifies stable tier retains full 5/5/3 + OWASP/MITRE/FP requirements.
- **2026-04-11**: v1.0 published. Adds Preamble, First-Principles Requirements, Landscape (§0), Threat Ontology Mapping (§6), Multi-Runtime Compatibility (§7), Review Tier Levels (§8), Community Signal Aggregation (§9), and References. Sets effective date to 2026-04-11.
- 2026-04-10: Initial draft (v0.9) — Maturity Levels, Confidence Score, Two-Dimensional Compliance Model, Required Metadata, Validation Library, Adoption Path.
