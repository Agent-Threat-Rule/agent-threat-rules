#!/usr/bin/env python3
"""Generate the ATR -> OWASP Agentic Skills Top 10 (AST) crosswalk document.

This maps ATR detection rules to the OWASP Agentic Skills Top 10 (AST01-AST10)
so a project working from the AST checklist can see which AST controls ATR
already produces executable detections for.

Join keys (documented so the mapping cannot drift silently):
  * PRIMARY: each rule's ``tags.category`` -- a closed 9-value enum. The
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


def asi_ids(rule):
    out = []
    for entry in (rule.get("references", {}) or {}).get("owasp_agentic", []) or []:
        token = str(entry).split(" ")[0].split(":")[0].strip()
        if token.startswith("ASI"):
            out.append(token)
    return out


def build():
    rules = load_rules()
    total = len(rules)

    # AST control -> set of rule ids, and supporting ASI counts.
    ast_rules = defaultdict(set)
    ast_asi = defaultdict(lambda: defaultdict(int))
    category_counts = defaultdict(int)
    unmapped = 0

    for rule in rules:
        cat = (rule.get("tags", {}) or {}).get("category")
        category_counts[cat] += 1
        mappings = CATEGORY_TO_AST.get(cat)
        if not mappings:
            unmapped += 1
            continue
        for ast, _rationale in mappings:
            ast_rules[ast].add(rule["id"])
            for asi in asi_ids(rule):
                ast_asi[ast][asi] += 1

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
        "- **Primary join key:** each rule's `tags.category` (a closed 9-value enum). "
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
    lines.append("| AST | Title | ATR rules | Top supporting ASI (evidence) |")
    lines.append("|-----|-------|-----------|-------------------------------|")
    for n in range(1, 11):
        ast = f"AST{n:02d}"
        ids = ast_rules.get(ast, set())
        asis = ast_asi.get(ast, {})
        top = ", ".join(
            f"{k} ({v})" for k, v in sorted(asis.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        ) or "-"
        lines.append(f"| {ast} | {AST_TITLES[ast]} | {len(ids)} | {top} |")
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
        lines.append(
            f"> {unmapped} rule(s) carry a category not in the mapping table and are "
            "excluded rather than force-fit."
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify the committed doc is current (CI mode)")
    args = ap.parse_args()

    content = build()
    if args.check:
        try:
            with open(DOC_PATH) as fh:
                current = fh.read()
        except FileNotFoundError:
            sys.exit(f"FAIL: {DOC_PATH} does not exist. Run scripts/generate-ast-crosswalk.py.")
        if current != content:
            sys.exit(f"FAIL: {DOC_PATH} is stale. Re-run scripts/generate-ast-crosswalk.py.")
        print(f"OK: {DOC_PATH} matches the rule metadata.")
        return
    with open(DOC_PATH, "w") as fh:
        fh.write(content)
    print(f"Wrote {DOC_PATH} ({len(content)} bytes)")


if __name__ == "__main__":
    main()
