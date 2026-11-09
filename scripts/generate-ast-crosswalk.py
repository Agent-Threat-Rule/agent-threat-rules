#!/usr/bin/env python3
"""Generate the ATR -> OWASP Agentic Skills Top 10 (AST) crosswalk document.

This maps ATR detection rules to the OWASP Agentic Skills Top 10 (AST01-AST10)
so a project working from the AST checklist can see which AST controls ATR
already produces executable detections for.

Join keys (documented so the mapping cannot drift silently):
  * PRIMARY: each rule's ``tags.category`` (the enum in spec/atr-schema.yaml). The
    category -> AST mapping is a curated, one-time editorial table (CATEGORY_TO_AST
    below), each entry carrying a short rationale. It is applied mechanically to
    every rule; the doc regenerates from metadata, so counts never drift even as
    rules are added.
  * SECONDARY (evidence, not a join): each rule's ``references.owasp_agentic``
    (ASIxx, the OWASP Agentic Security Initiative Top 10 -- a DIFFERENT taxonomy
    from AST). Surfaced per AST row as supporting context only.

This is NOT an id-equality join like the ATT&CK crosswalk (ATR has no native
AST id in its metadata). It is a curated thematic mapping over the category
enum, and is labelled as such in the output so reviewers can judge the mapping
independently from the per-rule counts.

Run:  python3 scripts/generate-ast-crosswalk.py
      python3 scripts/generate-ast-crosswalk.py --check   # CI: verify doc is current
"""
from __future__ import annotations

import argparse
import glob
import sys
from collections import defaultdict

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

DOC_PATH = "docs/crosswalks/atr-ast-crosswalk.md"
# The summary document the website's coverage page reads (website/lib/coverage.ts
# parses its "| ASTxx: Title | Severity | N rules | STATUS |" rows). Generated
# from the same join so the two documents cannot disagree.
SUMMARY_PATH = "docs/OWASP-AST10-MAPPING.md"

# Severity per AST control, as published by the OWASP project.
AST_SEVERITY = {
    "AST01": "CRITICAL", "AST02": "CRITICAL",
    "AST03": "HIGH", "AST04": "HIGH", "AST05": "HIGH", "AST06": "HIGH",
    "AST07": "MEDIUM", "AST08": "MEDIUM", "AST09": "MEDIUM", "AST10": "MEDIUM",
}

# Status thresholds, on enforce-lane rules (see lane_bucket). Rule counts alone
# overstate coverage: most mapped rules are test or experimental maturity.
STRONG_MIN_STABLE = 20
MODERATE_MIN_STABLE = 5

# Lane buckets reported per control, in column order.
LANE_BUCKETS = ("stable", "test", "experimental", "draft")

# AST01-AST10 titles, verbatim from OWASP/www-project-agentic-skills-top-10.
AST_TITLES = {
    "AST01": "Malicious Skills",
    "AST02": "Supply Chain Compromise",
    "AST03": "Over-Privileged Skills",
    "AST04": "Insecure Metadata",
    "AST05": "Untrusted External Instructions",
    "AST06": "Weak Isolation",
    "AST07": "Update Drift",
    "AST08": "Poor Scanning",
    "AST09": "No Governance",
    "AST10": "Cross-Platform Reuse",
}

# Curated join table: ATR tags.category -> (AST control, rationale). A category
# may map to more than one AST control. Editorial, reviewed once; the rationale
# is printed in the doc so the mapping is auditable, not asserted.
CATEGORY_TO_AST = {
    "prompt-injection": [
        ("AST05", "Injected/untrusted instructions are exactly the AST05 external-instruction class."),
    ],
    "agent-manipulation": [
        ("AST05", "Manipulating an agent via crafted external content is untrusted-instruction abuse."),
    ],
    "tool-poisoning": [
        ("AST01", "A poisoned tool/skill is a malicious skill at the point of use."),
        ("AST04", "Tool-description / metadata poisoning is the AST04 insecure-metadata surface."),
    ],
    "skill-compromise": [
        ("AST01", "A compromised skill is a malicious skill."),
        ("AST02", "Skill compromise via a tampered upstream is supply-chain compromise."),
    ],
    "data-poisoning": [
        ("AST02", "Poisoned training/reference data enters through the supply chain."),
    ],
    "privilege-escalation": [
        ("AST03", "Privilege escalation is the direct consequence of over-privileged skills."),
    ],
    "excessive-autonomy": [
        ("AST03", "Unbounded action authority is an over-privilege condition."),
        ("AST09", "Autonomy without checks is the AST09 governance gap."),
    ],
    "context-exfiltration": [
        ("AST03", "Reading/exfiltrating data beyond the skill's need is over-privilege."),
        ("AST06", "Cross-context data leakage indicates weak isolation between skills/sessions."),
    ],
    "model-abuse": [
        ("AST01", "Coercing the model into attacker-chosen behaviour manifests as a malicious skill action."),
    ],
}


def load_rules():
    rules = []
    for path in sorted(glob.glob("rules/**/*.yaml", recursive=True)):
        try:
            with open(path) as fh:
                doc = yaml.safe_load(fh)
        except Exception:
            continue
        if not isinstance(doc, dict) or "id" not in doc:
            continue
        rules.append(doc)
    return rules


def lane_bucket(rule):
    """Maturity bucket as the engine's lanes see it.

    The enforce lane loads maturity=stable only and skips status draft or
    deprecated (src/engine.ts); the alert lane adds maturity=test. A rule
    whose status is draft or deprecated is counted as draft here whatever its
    maturity, since no lane but hunt evaluates it.
    """
    if rule.get("status") in ("draft", "deprecated"):
        return "draft"
    maturity = rule.get("maturity")
    return maturity if maturity in LANE_BUCKETS else "draft"


def ast_status(ast, total, stable):
    if total == 0:
        # Controls ATR maps no rule to are lifecycle or process concerns.
        return "GAP (process-level)"
    if stable >= STRONG_MIN_STABLE:
        return "STRONG"
    if stable >= MODERATE_MIN_STABLE:
        return "MODERATE"
    return "PARTIAL"


def asi_ids(rule):
    out = []
    for entry in (rule.get("references", {}) or {}).get("owasp_agentic", []) or []:
        token = str(entry).split(" ")[0].split(":")[0].strip()
        if token.startswith("ASI"):
            out.append(token)
    return out


def collect():
    """Join every rule to its AST controls. Shared by both documents."""
    rules = load_rules()

    # AST control -> rule id -> rule, and supporting ASI counts.
    ast_rules = defaultdict(dict)
    ast_asi = defaultdict(lambda: defaultdict(int))
    category_counts = defaultdict(int)
    unmapped = defaultdict(int)

    for rule in rules:
        cat = (rule.get("tags", {}) or {}).get("category")
        category_counts[cat] += 1
        mappings = CATEGORY_TO_AST.get(cat)
        if not mappings:
            unmapped[cat] += 1
            continue
        for ast, _rationale in mappings:
            ast_rules[ast][rule["id"]] = rule
            for asi in asi_ids(rule):
                ast_asi[ast][asi] += 1

    ast_lanes = {}
    for n in range(1, 11):
        ast = f"AST{n:02d}"
        counts = dict.fromkeys(LANE_BUCKETS, 0)
        for rule in ast_rules[ast].values():
            counts[lane_bucket(rule)] += 1
        ast_lanes[ast] = counts

    return {
        "total": len(rules),
        "ast_rules": ast_rules,
        "ast_asi": ast_asi,
        "ast_lanes": ast_lanes,
        "category_counts": category_counts,
        "unmapped": unmapped,
    }


def build(data):
    total = data["total"]
    ast_rules = data["ast_rules"]
    ast_asi = data["ast_asi"]
    ast_lanes = data["ast_lanes"]
    category_counts = data["category_counts"]
    unmapped = data["unmapped"]

    lines = []
    lines.append("# ATR -> OWASP Agentic Skills Top 10 (AST) Crosswalk")
    lines.append("")
    lines.append(
        "This document maps Agent Threat Rules (ATR) detection rules to the OWASP "
        "Agentic Skills Top 10 (AST01-AST10), so a project working from the AST "
        "checklist can see which controls ATR already ships executable detections for. "
        "It was produced in response to OWASP/www-project-agentic-skills-top-10#22."
    )
    lines.append("")
    lines.append("## Method and join keys")
    lines.append("")
    lines.append(
        "This is a **curated thematic mapping**, not an id-equality join. ATR carries "
        "no native AST id in its metadata, so the crosswalk is generated as follows:"
    )
    lines.append("")
    lines.append(
        f"- **Primary join key:** each rule's `tags.category` ({len(category_counts)} values "
        "in the current corpus; the enum is defined in `spec/atr-schema.yaml`). "
        "The `category -> AST` table is a one-time editorial mapping "
        "(`CATEGORY_TO_AST` in `scripts/generate-ast-crosswalk.py`), each entry "
        "carrying a short rationale reproduced below. It is applied mechanically to "
        "every rule, so per-control counts regenerate from metadata and cannot drift."
    )
    lines.append(
        "- **Secondary evidence (not a join):** each rule's "
        "`references.owasp_agentic` (ASIxx -- the OWASP Agentic Security Initiative "
        "Top 10, a *different* taxonomy from AST). Surfaced per row as supporting "
        "context, never as the mapping basis."
    )
    lines.append("")
    lines.append(
        "Regenerate with `python3 scripts/generate-ast-crosswalk.py`. CI runs "
        "`--check` so a stale copy fails the build."
    )
    lines.append("")
    lines.append(f"Rules in corpus at generation time: **{total}**.")
    lines.append("")

    lines.append("## Coverage by AST control")
    lines.append("")
    lines.append(
        "Rule counts are split by maturity, because the lanes differ: the enforce "
        "lane (the one meant to block) loads `maturity: stable` only, the alert lane "
        "adds `test`, and `experimental` and `draft` rules run in the hunt lane only. "
        "A rule mapped to a control is a detection for part of that control's "
        "threat surface, not coverage of the control."
    )
    lines.append("")
    lines.append(
        "| AST | Title | ATR rules | stable | test | experimental | draft | "
        "Top supporting ASI (evidence) |"
    )
    lines.append("|-----|-------|-----------|--------|------|--------------|-------|-------------------------------|")
    for n in range(1, 11):
        ast = f"AST{n:02d}"
        ids = ast_rules.get(ast, set())
        asis = ast_asi.get(ast, {})
        top = ", ".join(
            f"{k} ({v})" for k, v in sorted(asis.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        ) or "-"
        lane = ast_lanes[ast]
        lane_cells = " | ".join(str(lane[b]) for b in LANE_BUCKETS)
        lines.append(f"| {ast} | {AST_TITLES[ast]} | {len(ids)} | {lane_cells} | {top} |")
    lines.append("")

    lines.append("## Category -> AST mapping (the editorial join table)")
    lines.append("")
    lines.append("| ATR category | Rules | AST control(s) | Rationale |")
    lines.append("|--------------|-------|----------------|-----------|")
    for cat in sorted(CATEGORY_TO_AST, key=lambda c: -category_counts.get(c, 0)):
        for i, (ast, rationale) in enumerate(CATEGORY_TO_AST[cat]):
            catcell = f"{cat} ({category_counts.get(cat, 0)})" if i == 0 else ""
            rulescell = str(category_counts.get(cat, 0)) if i == 0 else ""
            lines.append(f"| {catcell} | {rulescell} | {ast} {AST_TITLES[ast]} | {rationale} |")
    lines.append("")

    if unmapped:
        detail = ", ".join(f"`{cat}` ({n})" for cat, n in sorted(unmapped.items(), key=lambda kv: str(kv[0])))
        lines.append(
            f"> {sum(unmapped.values())} rule(s) carry a category not in the mapping "
            f"table and are excluded rather than force-fit: {detail}."
        )
        lines.append("")

    lines.append("## What ATR does not cover")
    lines.append("")
    lines.append(
        "ATR is a runtime/near-runtime detection ruleset. AST controls that are "
        "primarily process or lifecycle concerns -- **AST07 Update Drift**, "
        "**AST08 Poor Scanning**, **AST09 No Governance** (partially), "
        "**AST10 Cross-Platform Reuse** -- are not things a detection rule fires on; "
        "they are addressed by scanning cadence, provenance tracking, and governance "
        "process, not by a pattern match. Rows for those controls reflect only the "
        "adjacent runtime signals ATR can contribute, not full coverage."
    )
    lines.append("")

    return "\n".join(lines) + "\n"


def cell(text):
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


def build_summary(data):
    ast_rules = data["ast_rules"]
    ast_lanes = data["ast_lanes"]

    lines = []
    lines.append("# ATR -> OWASP Agentic Skills Top 10 (AST10) Mapping")
    lines.append("")
    lines.append(
        "> Generated by `scripts/generate-ast-crosswalk.py` from rule metadata; do not "
        "edit by hand. The method, the category -> AST join table and its rationale "
        "are in [crosswalks/atr-ast-crosswalk.md](crosswalks/atr-ast-crosswalk.md). "
        "CI runs `--check`, so this file cannot fall behind the rules."
    )
    lines.append("")
    lines.append(
        "OWASP AST10 is a separate framework from the OWASP Top 10 for Agentic "
        "Applications (ASI01-ASI10). ASI covers agent runtime threats; AST covers the "
        "skill supply chain and lifecycle. Several AST controls are process "
        "requirements that a detection rule cannot satisfy."
    )
    lines.append("")
    lines.append(f"Rules in corpus at generation time: {data['total']}.")
    lines.append("")
    lines.append("## Coverage Summary")
    lines.append("")
    lines.append("| OWASP AST Category | Severity | ATR Rules | Status |")
    lines.append("|---|---|---|---|")
    for n in range(1, 11):
        ast = f"AST{n:02d}"
        count = len(ast_rules.get(ast, {}))
        status = ast_status(ast, count, ast_lanes[ast]["stable"])
        lines.append(f"| {ast}: {AST_TITLES[ast]} | {AST_SEVERITY[ast]} | {count} rules | {status} |")
    lines.append("")
    lines.append(
        f"Status is set by enforce-lane (`maturity: stable`) rules: STRONG at "
        f"{STRONG_MIN_STABLE} or more, MODERATE at {MODERATE_MIN_STABLE} or more, "
        "PARTIAL below that, GAP when no rule maps to the control. It measures how "
        "many blocking-grade detections exist for the control's threat surface, not "
        "how much of the control is met, and no per-control precision has been "
        "measured."
    )
    lines.append("")
    lines.append("## Enforce-lane rules by control")
    lines.append("")
    for n in range(1, 11):
        ast = f"AST{n:02d}"
        rules = ast_rules.get(ast, {})
        lane = ast_lanes[ast]
        lines.append(f"### {ast}: {AST_TITLES[ast]} ({AST_SEVERITY[ast]})")
        lines.append("")
        if not rules:
            lines.append("No ATR rule maps to this control.")
            lines.append("")
            continue
        lines.append(
            f"{len(rules)} rules: {lane['stable']} stable, {lane['test']} test, "
            f"{lane['experimental']} experimental, {lane['draft']} draft or deprecated."
        )
        lines.append("")
        stable = [r for r in rules.values() if lane_bucket(r) == "stable"]
        if not stable:
            lines.append("No stable rule maps to this control yet.")
            lines.append("")
            continue
        lines.append("| ATR Rule | Title | Severity |")
        lines.append("|---|---|---|")
        for rule in sorted(stable, key=lambda r: r["id"]):
            lines.append(f"| {rule['id']} | {cell(rule.get('title'))} | {cell(rule.get('severity')).upper()} |")
        lines.append("")

    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify the committed docs are current (CI mode)")
    args = ap.parse_args()

    data = collect()
    outputs = ((DOC_PATH, build(data)), (SUMMARY_PATH, build_summary(data)))
    if args.check:
        failed = False
        for path, content in outputs:
            try:
                with open(path) as fh:
                    current = fh.read()
            except FileNotFoundError:
                print(f"FAIL: {path} does not exist. Run scripts/generate-ast-crosswalk.py.")
                failed = True
                continue
            if current != content:
                print(f"FAIL: {path} is stale. Re-run scripts/generate-ast-crosswalk.py.")
                failed = True
            else:
                print(f"OK: {path} matches the rule metadata.")
        if failed:
            sys.exit(1)
        return
    for path, content in outputs:
        with open(path, "w") as fh:
            fh.write(content)
        print(f"Wrote {path} ({len(content)} bytes)")


if __name__ == "__main__":
    main()
