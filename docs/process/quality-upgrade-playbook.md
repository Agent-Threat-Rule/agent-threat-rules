# ATR Quality Upgrade Playbook

How to take the ATR rule corpus from "rules that exist" to "rules that
meet RFC-001 v1.0" — and how to keep it there as new rules are added.

Written 2026-04-12 after the first end-to-end RFC-001 v1.0 upgrade
session (109 → 110 rules, 97/110 passing strict experimental gate).

## The quality bar (RFC-001 v1.0 summary)

| Requirement | experimental | stable |
|---|---|---|
| detection.conditions | ≥ 3 (or single-pattern exception) | ≥ 3 |
| true_positives | ≥ 5 (real attack payloads) | ≥ 5 |
| true_negatives | ≥ 5 (similar but benign) | ≥ 5 |
| evasion_tests | ≥ 3 (documented bypasses) | ≥ 3 |
| OWASP reference | required (LLM + Agentic) | required |
| MITRE ATLAS reference | required | required |
| false_positives docs | required (≥ 1) | required |
| wild_samples | — | ≥ 1,000 |
| wild_fp_rate | — | ≤ 0.5% |
| confidence score | — | ≥ 80 |
| provenance | any | human-reviewed |

Single-pattern exception (RFC-001 v1.1 §1.1): a rule with 1-2
conditions may pass experimental if `wild_fp_rate = 0%` AND
`wild_samples ≥ 50,000`.

## Two production paths for new rules

### Path A: Research-driven (human + LLM)

Best for: novel attack classes from threat reports, CVEs, academic papers.

```
1. Read threat report (Invariant Labs, Snyk, Elastic, MITRE ATLAS, arxiv)
2. grep existing rules for keywords → verify not already covered
3. If already covered → stop
4. If gap found → draft rule YAML with 3-5 detection layers
5. Mentally verify: each TP must match ≥1 regex, each TN must match 0
6. Run: npm run build && npm test
7. Run: quality gate audit (validateRuleMeetsStandard)
8. Run: SKILL.md benchmark (must not regress)
9. Commit + push
```

### Path B: Community Feed v2 (automated)

Best for: bulk scanning of skill registries and MCP servers.

```
1. POST skills to /api/analyze-skills
2. TC v2 Claude auto-calls:
   a. grep_existing_rules(keywords) → dedup check
   b. read_rule(id) → inspect overlapping rules
   c. fetch_research(url) → ground in published attack
3. Claude drafts rule YAML (or outputs NO_THREATS_FOUND)
4. Pipeline validates:
   a. YAML parse + required fields
   b. Regex compilation (JS-compatible)
   c. Quality gate (validateRuleMeetsStandard)
   d. Self-test (L1): regex matches all TPs, misses all TNs
5. If all pass → inserted as proposal → canary 24h → auto-PR
6. Maintainer reviews + assigns permanent ID → merge
```

Both paths exit through the SAME quality gate. Output quality is
identical; only the discovery mechanism differs.

## Bulk upgrade procedure (for raising the bar on existing rules)

Used when the quality standard is tightened (e.g. RFC-001 v1.0 raised
the experimental bar from 3/3/0 to 5/5/3).

### 1. Audit

```bash
node -e 'import("./dist/quality/index.js").then(q => {
  // walk rules/, parseATRRule, validateRuleMeetsStandard, count pass/fail
})'
```

### 2. Run scripts/quality-upgrade.ts

```bash
ANTHROPIC_API_KEY=... npx tsx scripts/quality-upgrade.ts --dry-run --limit 5
```

Inspect the dry-run output. Key things to look for:
- Are TPs real attack payloads (not descriptions)?
- Are TNs similar-looking but benign?
- Do evasion_tests genuinely bypass the regex?
- Does the LLM hallucinate TPs that don't match?

If dry-run looks good:

```bash
npx tsx scripts/quality-upgrade.ts --all
```

### 3. Self-test layer

The script has 5 safety layers (L1-L5):
- L1: JSON extraction (brace-balanced, handles LLM prose prefix)
- L2: Schema sanity (correct keys + types)
- L3: Self-test (TP must match regex, TN must not)
- L4: Quality gate revalidation
- L5: Retry loop (failed items re-prompted with regex feedback)

### 4. Known failure modes from the first upgrade

| Failure mode | Count | Root cause | Fix |
|---|---|---|---|
| LLM TPs too creative, don't hit regex | ~40% first pass | LLM doesn't read regex carefully | Added: pre-extract regex into prompt + retry with explicit failure feedback |
| LLM TNs quote attack phrase verbatim | ~20% first pass | LLM thinks "docs about attacks" = safe TN | Added: prompt explicitly forbids verbatim quoting |
| LLM-generated conditions introduce wild FPs | Round 2 regression (precision 100%→82%) | Per-rule TN set too small to validate wild behavior | **DISABLED** condition generation entirely. Conditions < 3 go to manual queue. |
| YAML round-trip normalizes quoting/ordering | All rules | js-yaml.dump() is spec-compliant but changes visual format | Accepted — tests still pass, semantics preserved |
| `tool_args` field rules: LLM writes English TPs but regex matches shell commands | 6 rules | LLM doesn't realize the `field` is `tool_args` not `content` | Manual queue — these need hand-written TPs |

### 5. Benchmark regression check

After ANY bulk upgrade, run:

```bash
npm test
```

The SKILL.md benchmark checks:
- precision ≥ 95%
- recall ≥ 90%
- FP rate ≤ 0.5%
- Layer A recall ≥ 95% (obvious payloads)
- Layer C recall ≥ 80% (semantic/evasive)
- Zero FP on official MCP server READMEs
- Latency < 50ms per sample

If ANY of these regress, the upgrade introduced false positives or
detection gaps. Revert and investigate.

## Wild scan procedure

### What to scan

| Source | How to get | Volume | Value |
|---|---|---|---|
| skills.sh | `data/skills-sh/skills/` (cached locally) | 3,115 | Medium (curated, mostly clean) |
| ClawHub registry | `data/clawhub-scan/clawhub-registry.json` | 36,394 | Low (metadata only, not body) |
| GitHub MCP servers | `npx tsx scripts/crawl-mcp-registry.ts` | 9,000+ | Medium (README descriptions) |
| npm MCP packages | `npx tsx scripts/audit-npm-skills.ts` | varies | High (actual package content) |
| Real MCP server tool descriptions | `npx tsx scripts/audit-mcp-dynamic.ts` | per-server | Highest (actual attack surface) |

### What to look for

Wild scans serve two purposes:

1. **Validate precision**: existing rules should NOT fire on legitimate
   skills. If they do → tighten the regex (see 00124/00127 fix from
   the 2026-04-11 ClawHub scan).

2. **Discover gaps**: look at skills that are NOT flagged but "feel"
   suspicious. These require human judgment — not everything is
   automatable.

Wild scans DO NOT efficiently find new attacks in curated registries
(those are filtered). For new attack discovery, use Path A (research-
driven) or adversarial generation.

## TC v2 tool-use architecture

TC v2 runs a multi-turn tool-use loop for each skill analysis:

```
User: "Analyze this skill..."
  → Claude: grep_existing_rules(["prompt injection", "hidden instruction"])
  ← Tool: {matches: [{ruleId: "ATR-2026-00100", ...}]}
  → Claude: read_rule("ATR-2026-00100")
  ← Tool: {content: "title: Consent Bypass..."}
  → Claude: "Existing rule covers consent bypass but not <IMPORTANT> tag..."
  → Claude: fetch_research("https://invariantlabs.ai/blog/...")
  ← Tool: {content: "Tool Poisoning Attacks..."}
  → Claude: "```yaml\ntitle: '...'\nid: ATR-2026-DRAFT-...\n```"
```

The loop is bounded at 6 rounds. Typical: 2-3 rounds (grep + read +
draft). Cost: ~$0.50/draft (Opus), ~$0.10/draft (Sonnet).

## Gravity well alignment

Every rule improvement should be evaluated against the four gravity
wells (see MEMORY project_gravity_well_strategy.md):

1. **Naming Authority**: does this rule use an official ATR-YYYY-NNNNN ID?
2. **Quality Gate**: does this rule pass RFC-001 v1.0?
3. **Data Gravity**: does this rule's deployment generate TC telemetry?
4. **Reference Impl**: does Guard correctly enforce this rule at runtime?

If any answer is "no", fix that before shipping the rule.
