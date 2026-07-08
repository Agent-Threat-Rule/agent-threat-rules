#!/usr/bin/env python3
"""Generate the ATR -> MCP-38 threat-taxonomy crosswalk document.

This script joins the MCP-38 threat taxonomy (arXiv:2603.18063) to the ATR rule
corpus *through the OWASP axis*. It is deliberately a 2-hop, approximate mapping:

    MCP-38 threat  --(paper Table 4)-->  OWASP LLM/Agentic code  --(rule metadata)-->  ATR rules

It is NOT a direct MCP-id-to-ATR-id match -- ATR rules do not carry MCP-38 ids.
The join key is the OWASP code prefix (LLM01..LLM10 / ASI01..ASI10), which both
sides carry: the paper assigns OWASP codes to each MCP threat (Table 4), and every
ATR rule tags `references.owasp_llm` / `references.owasp_agentic`. The descriptive
name after the code drifts between sources, so only the code prefix is joined on.

Inputs (nothing invented):
  - data/mcp38-mappings.json : per-threat name / STRIDE / tactic category / OWASP
    codes, extracted from the paper's Tables 3 & 4 (see that file's `_source`).
  - rules/**/*.yaml          : ATR rules, read for `references.owasp_llm` and
    `references.owasp_agentic` (code prefix only).

Run:  python3 scripts/generate-mcp-crosswalk.py
      python3 scripts/generate-mcp-crosswalk.py --check   # CI: verify doc is current
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from collections import defaultdict

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

RULES_GLOB = "rules/**/*.yaml"
MAPPINGS_PATH = "data/mcp38-mappings.json"
DOC_PATH = "docs/crosswalks/atr-mcp38-crosswalk.md"

# OWASP code prefixes: LLM01..LLM10, ASI01..ASI10. Grab the bare code, drop the
# ":2025"/":2026" and the trailing descriptive name (which drifts across the corpus).
LLM_RE = re.compile(r"^(LLM\d{2})\b")
ASI_RE = re.compile(r"^(ASI\d{2})\b")


def code_prefix(value: str, pattern: re.Pattern) -> str | None:
    """Return the bare OWASP code (e.g. 'LLM01') from a 'LLM01:2025 - Name' string."""
    token = str(value).strip()
    m = pattern.match(token)
    return m.group(1) if m else None


def _aslist(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def load_mappings() -> dict:
    try:
        return json.load(open(MAPPINGS_PATH))
    except FileNotFoundError:
        sys.exit(f"missing {MAPPINGS_PATH}; it carries the MCP-38 paper extraction")


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
        llm = sorted({c for v in _aslist(refs.get("owasp_llm"))
                      if (c := code_prefix(v, LLM_RE))})
        asi = sorted({c for v in _aslist(refs.get("owasp_agentic"))
                      if (c := code_prefix(v, ASI_RE))})
        rules.append(
            {
                "path": path,
                "id": doc.get("id", ""),
                "category": tags.get("category") or path.split("/")[1],
                "owasp_llm": llm,
                "owasp_agentic": asi,
            }
        )
    return rules


def build(mappings: dict, rules: list[dict]) -> str:
    threats = mappings["threats"]
    tactic_labels = mappings["tactic_categories"]
    src = mappings["_source"]
    total_rules = len(rules)

    # Index: OWASP code -> set(rule id) and OWASP code -> set(category).
    llm_to_rules: dict[str, set[str]] = defaultdict(set)
    asi_to_rules: dict[str, set[str]] = defaultdict(set)
    llm_to_cats: dict[str, set[str]] = defaultdict(set)
    asi_to_cats: dict[str, set[str]] = defaultdict(set)
    for r in rules:
        for c in r["owasp_llm"]:
            llm_to_rules[c].add(r["id"])
            llm_to_cats[c].add(r["category"])
        for c in r["owasp_agentic"]:
            asi_to_rules[c].add(r["id"])
            asi_to_cats[c].add(r["category"])

    # Per-threat join: union of rules reachable through its OWASP codes.
    threat_rows = []  # (tid, data, rule_ids set, cats set)
    for tid in sorted(threats):
        data = threats[tid]
        rule_ids: set[str] = set()
        cats: set[str] = set()
        for c in data["owasp_llm"]:
            rule_ids |= llm_to_rules.get(c, set())
            cats |= llm_to_cats.get(c, set())
        for c in data["owasp_agentic"]:
            rule_ids |= asi_to_rules.get(c, set())
            cats |= asi_to_cats.get(c, set())
        threat_rows.append((tid, data, rule_ids, cats))

    covered = [row for row in threat_rows if row[2]]
    uncovered = [row for row in threat_rows if not row[2]]

    # Per tactic-category rollup (I-V).
    cat_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "covered": 0})
    for tid, data, rule_ids, _cats in threat_rows:
        tc = data["tactic_category"]
        cat_totals[tc]["total"] += 1
        if rule_ids:
            cat_totals[tc]["covered"] += 1

    lines: list[str] = []
    w = lines.append

    w("# ATR -> MCP-38 Threat Taxonomy Crosswalk (OWASP-axis join)")
    w("")
    w("This document maps the **MCP-38 threat taxonomy** to Agent Threat Rules (ATR)")
    w("detection content, so an operator working from the MCP-38 paper can see which")
    w("MCP threats already have executable ATR coverage and which are gaps.")
    w("")
    w("Source taxonomy: **" + src["paper"] + "**,")
    w(src["authors"] + ", arXiv:" + src["arxiv"] + " (" + src["license"] + ").")
    w("38 protocol-specific threats (MCP-01 ... MCP-38).")
    w("")
    w("## Methodology -- read this first (it is a 2-hop approximation)")
    w("")
    w("**This is NOT a direct MCP-id-to-ATR-id mapping.** ATR rules do not carry")
    w("MCP-38 ids. The crosswalk is a **2-hop join through the OWASP axis**:")
    w("")
    w("    MCP-38 threat  --[paper Table 4]-->  OWASP code  --[ATR rule metadata]-->  ATR rules")
    w("")
    w("- **Hop 1 (MCP-38 -> OWASP).** The paper's Table 4 assigns each MCP threat one")
    w("  or more OWASP LLM Top 10 (2025) and OWASP Agentic (2026) codes. Those")
    w("  assignments are extracted verbatim into `data/mcp38-mappings.json` and have")
    w("  primary-source backing in the paper.")
    w("- **Hop 2 (OWASP -> ATR).** Every ATR rule tags `references.owasp_llm` and")
    w("  `references.owasp_agentic`. The generator reads those tags and joins on the")
    w("  **bare code prefix only** (`LLM01`..`LLM10`, `ASI01`..`ASI10`). The")
    w("  descriptive name after the code drifts across the ATR corpus and between ATR")
    w("  and the paper, so it is deliberately ignored for joining.")
    w("")
    w("Consequences to keep in mind when reading the tables below:")
    w("")
    w("- A threat shown as **covered** means ATR has rules tagged with an OWASP code")
    w("  the paper assigns to that threat -- it is *topical* coverage, not a proof that")
    w("  a specific rule fires on that specific MCP mechanism. OWASP buckets are broad")
    w("  (e.g. LLM01 Prompt Injection maps to five different MCP threats), so a single")
    w("  rule set is credited to several MCP threats it is only loosely related to.")
    w("- A threat shown as an **OWASP-axis gap** (no rules via its OWASP codes) is a")
    w("  strong signal of missing coverage, but a rule using different terminology")
    w("  could still be adjacent. Treat gaps as an authoring roadmap, not proven")
    w("  absence.")
    w("- For a hand-verified, rule-id-level MCP-38 mapping that names specific rules")
    w("  per threat, see [`docs/MCP-38-MAPPING.md`](../MCP-38-MAPPING.md). This")
    w("  generated document is the *reproducible, corpus-wide* companion to it.")
    w("")
    w("All ATR-side numbers below are computed at build time from the rule YAML; none")
    w("are hard-coded. Regenerate with `python3 scripts/generate-mcp-crosswalk.py`.")
    w("")
    w("## Coverage summary")
    w("")
    w(f"- ATR rules total (join surface): {total_rules}")
    w(f"- MCP-38 threats total: {len(threat_rows)}")
    w(f"- MCP-38 threats with >=1 ATR rule via the OWASP axis: {len(covered)}"
      f" ({len(covered) * 100 // len(threat_rows)}%)")
    w(f"- MCP-38 threats with no ATR rule via the OWASP axis: {len(uncovered)}")
    w("")
    w("By MCP-38 tactic category (paper section 4 grouping):")
    w("")
    w("| Tactic category | Label | Threats | Covered (OWASP-axis) |")
    w("|---|---|---|---|")
    for tc in sorted(cat_totals):
        t = cat_totals[tc]
        label = tactic_labels.get(tc, "")
        w(f"| {tc} | {label} | {t['total']} | {t['covered']} |")
    w("")

    w("## Per-threat crosswalk")
    w("")
    w("`ATR rules` counts distinct rule ids reachable from the threat's OWASP codes")
    w("(union across all its LLM and ASI codes). `ATR categories` are the ATR rule")
    w("directories those rules fall in. STRIDE codes are the paper's (S/T/R/I/D/E).")
    w("")
    w("| MCP-38 | Threat | STRIDE | OWASP LLM | OWASP Agentic | ATR rules | ATR categories |")
    w("|---|---|---|---|---|---|---|")
    for tid, data, rule_ids, cats in threat_rows:
        stride = "/".join(data["stride"])
        llm = ", ".join(data["owasp_llm"]) or "-"
        asi = ", ".join(data["owasp_agentic"]) or "-"
        n = len(rule_ids)
        cats_cell = ", ".join(sorted(cats)) if cats else "(none)"
        gap = "" if rule_ids else " **(OWASP-axis gap)**"
        w(f"| {tid} | {data['name']}{gap} | {stride} | {llm} | {asi} | {n} | {cats_cell} |")
    w("")

    if uncovered:
        w("### OWASP-axis gaps (verification + authoring roadmap)")
        w("")
        w("These MCP-38 threats have no ATR rule reachable through the OWASP codes the")
        w("paper assigns them. Some are genuinely out of ATR's detection scope")
        w("(architectural / cryptographic / transport controls); others are authoring")
        w("targets. Each needs a manual check before being called a true gap.")
        w("")
        for tid, data, _rule_ids, _cats in uncovered:
            llm = ", ".join(data["owasp_llm"]) or "-"
            asi = ", ".join(data["owasp_agentic"]) or "-"
            w(f"- **{tid} {data['name']}** (OWASP {llm} / {asi})")
        w("")

    w("## OWASP-code join table (the actual key)")
    w("")
    w("The bare OWASP codes each side carries, and how many ATR rules tag each. This")
    w("is the literal join surface; the per-threat table above is derived from it via")
    w("Table 4.")
    w("")
    w("| OWASP code | Name (paper) | ATR rules tagging it | MCP-38 threats using it |")
    w("|---|---|---|---|")
    llm_names = mappings["owasp_llm_names"]
    asi_names = mappings["owasp_agentic_names"]
    # invert threats -> which codes they use, for the last column
    code_to_threats: dict[str, list[str]] = defaultdict(list)
    for tid in sorted(threats):
        for c in threats[tid]["owasp_llm"]:
            code_to_threats[c].append(tid)
        for c in threats[tid]["owasp_agentic"]:
            code_to_threats[c].append(tid)
    for c in [f"LLM{n:02d}" for n in range(1, 11)]:
        threats_using = ", ".join(sorted(code_to_threats.get(c, [])))
        w(f"| {c} | {llm_names.get(c, '')} | {len(llm_to_rules.get(c, set()))} | {threats_using} |")
    for c in [f"ASI{n:02d}" for n in range(1, 11)]:
        threats_using = ", ".join(sorted(code_to_threats.get(c, [])))
        w(f"| {c} | {asi_names.get(c, '')} | {len(asi_to_rules.get(c, set()))} | {threats_using} |")
    w("")

    w("## Provenance")
    w("")
    w("- MCP-38 side: " + src["provenance"])
    w(f"- ATR side: rule YAML under `rules/` ({total_rules} files at build time),")
    w("  fields `references.owasp_llm` and `references.owasp_agentic`, joined on the")
    w("  bare code prefix.")
    w("- Extracted: " + src["extracted"] + ". arXiv:" + src["arxiv"]
      + " is CC BY 4.0; ATR is MIT.")
    w("- Regenerate: `python3 scripts/generate-mcp-crosswalk.py`. Verify freshness in")
    w("  CI: `python3 scripts/generate-mcp-crosswalk.py --check`.")
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

    mappings = load_mappings()
    rules = load_rules()
    content = build(mappings, rules)

    if args.check:
        try:
            existing = open(DOC_PATH).read()
        except FileNotFoundError:
            print(f"FAIL: {DOC_PATH} does not exist; run the generator.", file=sys.stderr)
            return 1
        if existing != content:
            print(
                f"FAIL: {DOC_PATH} is stale. Re-run scripts/generate-mcp-crosswalk.py.",
                file=sys.stderr,
            )
            return 1
        print(f"OK: {DOC_PATH} matches the rule metadata and MCP-38 mappings.")
        return 0

    with open(DOC_PATH, "w") as fh:
        fh.write(content)
    print(f"Wrote {DOC_PATH} ({len(content)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
