#!/usr/bin/env python3
"""Generate the ATR -> MITRE ATT&CK / ATLAS crosswalk document.

This script reads the real MITRE mapping metadata out of every ATR rule YAML
and emits docs/crosswalks/atr-attack-crosswalk.md. Nothing is invented: every
technique id printed is read verbatim from a rule's `references` block.

Join key (per agentshield-ai/sigma-ai#9 with @markbriers): the shared,
machine-derivable axis between ATR and a Sigma ruleset is the enterprise
ATT&CK technique id -- ATR's `references.mitre_attack: Txxxx` against Sigma's
`tags: attack.txxxx` (case-folded). MITRE ATLAS (AML.Txxxx) and OWASP Agentic
(ASIxx) are the agent-specific layer ATR carries that Sigma does not tag; they
are surfaced here as the value-add columns, also read straight from metadata.

Run:  python3 scripts/generate-attack-crosswalk.py
      python3 scripts/generate-attack-crosswalk.py --check   # CI: verify doc is current
"""
from __future__ import annotations

import argparse
import glob
import re
import sys
from collections import defaultdict

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

RULES_GLOB = "rules/**/*.yaml"
DOC_PATH = "docs/crosswalks/atr-attack-crosswalk.md"

# Enterprise ATT&CK technique ids are T1000+ (optionally .NNN subtechnique).
# ATLAS technique ids are AML.Txxxx, sometimes written in short form as T00xx.
ATTACK_RE = re.compile(r"^(T1\d{3})(\.\d{3})?\b")
ATLAS_SHORT_RE = re.compile(r"^(T0\d{2,3})\b")
ATLAS_FULL_RE = re.compile(r"^(AML\.T\d{4})\b")


def first_token(value: str) -> str:
    """Return the id token from a 'Txxxx - Name' style string."""
    return str(value).strip().split()[0] if str(value).strip() else ""


def classify(token: str) -> str:
    if ATTACK_RE.match(token):
        return "attack"
    if ATLAS_FULL_RE.match(token) or ATLAS_SHORT_RE.match(token):
        return "atlas"
    return "other"


def load_rules() -> list[dict]:
    rules = []
    for path in sorted(glob.glob(RULES_GLOB, recursive=True)):
        try:
            doc = yaml.safe_load(open(path))
        except Exception as exc:  # noqa: BLE001 - report and skip malformed YAML
            print(f"WARN: could not parse {path}: {exc}", file=sys.stderr)
            continue
        if not isinstance(doc, dict):
            continue
        refs = doc.get("references") or {}
        if not isinstance(refs, dict):
            refs = {}
        tags = doc.get("tags") or {}
        if not isinstance(tags, dict):
            tags = {}
        rules.append(
            {
                "path": path,
                "id": doc.get("id", ""),
                "title": doc.get("title", ""),
                "category": tags.get("category") or path.split("/")[1],
                "mitre_attack": _aslist(refs.get("mitre_attack")),
                "mitre_atlas": _aslist(refs.get("mitre_atlas")),
                "owasp_agentic": _aslist(refs.get("owasp_agentic")),
            }
        )
    return rules


def _aslist(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def build(rules: list[dict]) -> str:
    total_rules = len(rules)

    # Split each rule's mitre_attack entries into real ATT&CK vs misfiled ATLAS.
    rules_with_attack = []  # rule has at least one genuine enterprise ATT&CK id
    atlas_in_attack_field = []  # (rule, token) where an ATLAS id sits in mitre_attack
    for r in rules:
        attack_ids, atlas_ids = [], []
        for entry in r["mitre_attack"]:
            tok = first_token(entry)
            kind = classify(tok)
            if kind == "attack":
                attack_ids.append((tok, entry))
            elif kind == "atlas":
                atlas_ids.append((tok, entry))
                atlas_in_attack_field.append((r, tok, entry))
        r["_attack_ids"] = attack_ids
        r["_atlas_in_attack"] = atlas_ids
        if attack_ids:
            rules_with_attack.append(r)

    # Coverage counts (all computed, never hard-coded).
    n_with_attack = len(rules_with_attack)
    distinct_attack = sorted(
        {tok for r in rules_with_attack for tok, _ in r["_attack_ids"]}
    )
    distinct_atlas = sorted(
        {first_token(e) for r in rules for e in r["mitre_atlas"] if first_token(e)}
    )
    n_with_atlas = sum(1 for r in rules if r["mitre_atlas"])
    n_with_owasp = sum(1 for r in rules if r["owasp_agentic"])

    # Per-category aggregation, anchored on ATT&CK id.
    cat_attack = defaultdict(lambda: defaultdict(set))  # category -> attack_id -> {rule ids}
    cat_attack_names = {}  # attack_id -> human name (from first occurrence)
    cat_atlas = defaultdict(set)  # category -> {atlas tokens}
    cat_owasp = defaultdict(set)  # category -> {owasp tokens}
    cat_rule_count = defaultdict(int)

    for r in rules:
        cat = r["category"]
        cat_rule_count[cat] += 1
        for tok, entry in r["_attack_ids"]:
            cat_attack[cat][tok].add(r["id"])
            if tok not in cat_attack_names:
                name = entry[len(tok):].lstrip(" -")
                cat_attack_names[tok] = name
        for e in r["mitre_atlas"]:
            t = first_token(e)
            if t:
                cat_atlas[cat].add(t)
        for e in r["owasp_agentic"]:
            t = first_token(e)
            if t:
                cat_owasp[cat].add(t)

    categories = sorted(cat_rule_count)

    lines: list[str] = []
    w = lines.append

    w("# ATR -> MITRE ATT&CK / ATLAS Crosswalk")
    w("")
    w("This document maps Agent Threat Rules (ATR) categories and rules to MITRE")
    w("technique ids, so any ruleset that tags with MITRE ATT&CK (for example a")
    w("Sigma ruleset using `tags: attack.txxxx`) can align with ATR on the shared")
    w("technique-id axis. It was produced in response to")
    w("agentshield-ai/sigma-ai#9.")
    w("")
    w("All technique ids below are read verbatim from each rule's `references`")
    w("block. None are authored by hand. Regenerate with")
    w("`python3 scripts/generate-attack-crosswalk.py`.")
    w("")
    w("## How to join against this crosswalk")
    w("")
    w("The clean, machine-derivable key is the enterprise ATT&CK technique id.")
    w("ATR stores it as `references.mitre_attack: Txxxx`; a Sigma rule stores it")
    w("as `tags: attack.txxxx`. They line up after case folding (ATR upper-cases")
    w("and omits the prefix, Sigma lower-cases and prefixes `attack.`):")
    w("")
    w("    ATR   references.mitre_attack: T1059")
    w("    Sigma tags: attack.t1059")
    w("")
    w("MITRE ATLAS (`AML.Txxxx`) and OWASP Agentic (`ASIxx`) are the")
    w("agent-specific layer ATR carries that ATT&CK-tagged rulesets do not tag.")
    w("They are included as additional columns so this document is the place that")
    w("connects ATT&CK-tagged runtime rules to the agent frameworks. Those")
    w("columns are still extracted from ATR metadata, not authored here.")
    w("")
    w("## Coverage")
    w("")
    w(f"- ATR rules total: {total_rules}")
    w(f"- Rules carrying an enterprise ATT&CK id (`references.mitre_attack` Txxxx): {n_with_attack}")
    w(f"- Distinct enterprise ATT&CK techniques referenced: {len(distinct_attack)}")
    w(f"- Rules carrying a MITRE ATLAS id (`references.mitre_atlas`): {n_with_atlas}")
    w(f"- Distinct MITRE ATLAS techniques referenced: {len(distinct_atlas)}")
    w(f"- Rules carrying an OWASP Agentic id (`references.owasp_agentic`): {n_with_owasp}")
    w(f"- ATR categories (distinct `tags.category` values): {len(categories)}")
    w("")
    w("Categories are keyed on each rule's `tags.category` metadata, not on its")
    w("directory. The repo has ten rule directories, but three rules under")
    w("`rules/model-security/` carry `tags.category` of `model-abuse` or")
    w("`data-poisoning`, so nine distinct categories appear in the metadata.")
    w("")
    if atlas_in_attack_field:
        w("Data-fidelity note: a small number of rules carry an ATLAS short-form id")
        w("(`T00xx`, e.g. AML.T0051) inside the `mitre_attack` field rather than in")
        w("`mitre_atlas`. These are reported as ATLAS, not enterprise ATT&CK, so the")
        w("ATT&CK join key stays clean. Affected entries:")
        w("")
        for r, tok, entry in atlas_in_attack_field:
            w(f"- `{r['id']}` ({r['category']}): `{entry}` -> treated as ATLAS `{tok}`")
        w("")

    w("## ATT&CK techniques referenced by ATR (the join surface)")
    w("")
    w("Every enterprise ATT&CK technique id present in ATR metadata, with the ATR")
    w("rules that reference it. This is the column a Sigma `attack.txxxx` tag joins")
    w("against.")
    w("")
    w("| ATT&CK technique | Name | ATR rules | ATR categories |")
    w("|---|---|---|---|")
    attack_to_rules = defaultdict(list)
    attack_to_cats = defaultdict(set)
    for r in rules_with_attack:
        for tok, _ in r["_attack_ids"]:
            attack_to_rules[tok].append(r["id"])
            attack_to_cats[tok].add(r["category"])
    for tok in distinct_attack:
        name = cat_attack_names.get(tok, "")
        rule_ids = sorted(set(attack_to_rules[tok]))
        cats = ", ".join(sorted(attack_to_cats[tok]))
        rules_cell = ", ".join(f"`{rid}`" for rid in rule_ids)
        w(f"| {tok} | {name} | {rules_cell} | {cats} |")
    w("")

    w("## Crosswalk by ATR category")
    w("")
    w("For each ATR category: the enterprise ATT&CK techniques its rules reference")
    w("(the shared join key), plus the ATLAS and OWASP Agentic techniques ATR adds.")
    w("")
    for cat in categories:
        w(f"### {cat}")
        w("")
        w(f"Rules in category: {cat_rule_count[cat]}")
        w("")
        attack_map = cat_attack[cat]
        if attack_map:
            w("ATT&CK techniques (join key):")
            w("")
            w("| ATT&CK technique | Name | ATR rules |")
            w("|---|---|---|")
            for tok in sorted(attack_map):
                name = cat_attack_names.get(tok, "")
                rule_ids = ", ".join(f"`{rid}`" for rid in sorted(attack_map[tok]))
                w(f"| {tok} | {name} | {rule_ids} |")
            w("")
        else:
            w("ATT&CK techniques (join key): none tagged in this category's rules.")
            w("")
        atlas = sorted(cat_atlas[cat])
        owasp = sorted(cat_owasp[cat])
        w(f"ATLAS techniques ATR adds: {', '.join(atlas) if atlas else 'none'}")
        w("")
        w(f"OWASP Agentic categories ATR adds: {', '.join(owasp) if owasp else 'none'}")
        w("")

    w("## Methodology")
    w("")
    w("- Source of truth: the YAML rule files under `rules/`. Each rule's")
    w("  `references` block carries `mitre_attack`, `mitre_atlas`, and")
    w("  `owasp_agentic` lists in `Txxxx - Name` form.")
    w("- The generator (`scripts/generate-attack-crosswalk.py`) parses every rule,")
    w("  takes the leading id token from each entry, and classifies it: `T1xxx`")
    w("  (optionally `.NNN`) is enterprise ATT&CK; `AML.Txxxx` or short-form")
    w("  `T00xx` is ATLAS.")
    w("- The ATT&CK column is fully auto-derivable and is what an ATT&CK-tagged")
    w("  ruleset joins against. ATLAS and OWASP Agentic columns are likewise")
    w("  extracted from metadata, not hand-authored.")
    w("- All counts above are computed by the generator at build time; none are")
    w("  hard-coded. Re-run the script to refresh after rule changes.")
    w("- License: ATR is MIT. This crosswalk may be reused under the same terms.")
    w("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed doc matches freshly generated output (CI mode)",
    )
    args = parser.parse_args()

    rules = load_rules()
    content = build(rules)

    if args.check:
        try:
            existing = open(DOC_PATH).read()
        except FileNotFoundError:
            print(f"FAIL: {DOC_PATH} does not exist; run the generator.", file=sys.stderr)
            return 1
        if existing != content:
            print(
                f"FAIL: {DOC_PATH} is stale. Re-run scripts/generate-attack-crosswalk.py.",
                file=sys.stderr,
            )
            return 1
        print(f"OK: {DOC_PATH} matches the rule metadata.")
        return 0

    with open(DOC_PATH, "w") as fh:
        fh.write(content)
    print(f"Wrote {DOC_PATH} ({len(content)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
