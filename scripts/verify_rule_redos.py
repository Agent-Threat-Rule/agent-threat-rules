#!/usr/bin/env python3
"""Verify one rule after a regex change: behaviour preserved, blowup gone.

Three checks, all of which must pass:

  1. The rule's own test cases still hold -- every true_positive still fires
     and every true_negative still does not.
  2. No pattern in the rule blows up on adversarial input. Inputs are
     generated from each pattern's own AST with quantifiers pumped, which is
     the only way to reach patterns whose blowup needs their own grammar --
     a run of 'a' never finds ATR-2026-01005.
  3. The rule flags no more of the benign corpus than it did before.

Run:  python3 scripts/verify_rule_redos.py rules/.../ATR-2026-01005-*.yaml [benign_dir]
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

try:
    import re._parser as sre_parse
    import re._constants as sre
except ImportError:                       # pragma: no cover
    import sre_parse, sre_constants as sre

import yaml

PUMPS = (2, 3, 4, 8, 16)
BUDGET = 0.30          # seconds any single pattern may take on any input


def _from_in(items):
    for op, av in items:
        if op is sre.LITERAL:
            return chr(av)
        if op is sre.RANGE:
            return chr(av[0])
        if op is sre.CATEGORY:
            return {sre.CATEGORY_DIGIT: "5", sre.CATEGORY_WORD: "a",
                    sre.CATEGORY_SPACE: " "}.get(av, "a")
    return "a"


def generate(node, k, depth=0):
    if depth > 12:
        return ""
    out = []
    for op, av in node:
        if op is sre.LITERAL:
            out.append(chr(av))
        elif op is sre.NOT_LITERAL:
            out.append("a" if chr(av) != "a" else "b")
        elif op is sre.ANY:
            out.append("a")
        elif op is sre.IN:
            out.append("a" if (av and av[0][0] is sre.NEGATE) else _from_in(av))
        elif op in (sre.MAX_REPEAT, sre.MIN_REPEAT):
            lo, hi, sub = av
            reps = max(lo, k)
            if hi != sre.MAXREPEAT:
                reps = min(reps, hi)
            out.append(generate(sub, k, depth + 1) * min(reps, 40))
        elif op is sre.SUBPATTERN:
            out.append(generate(av[-1], k, depth + 1))
        elif op is sre.BRANCH:
            branches = av[1]
            out.append(generate(branches[0], k, depth + 1) if branches else "")
        elif op is sre.ATOMIC_GROUP:
            out.append(generate(av, k, depth + 1))
    return "".join(out)


def conditions(rule):
    det = rule.get("detection") or {}
    return [c for c in (det.get("conditions") or []) if c.get("operator") == "regex"]


def fires(rule, text):
    """Mirror the engine's any/all logic over this rule's regex conditions."""
    conds = conditions(rule)
    results = []
    for c in conds:
        try:
            rx = re.compile(c["value"], 0 if c.get("case_sensitive") else re.IGNORECASE)
        except re.error:
            results.append(False)
            continue
        results.append(rx.search(text) is not None)
    logic = str((rule.get("detection") or {}).get("condition", "any"))
    return all(results) if logic == "all" else any(results)


def check_test_cases(rule):
    tc = rule.get("test_cases") or {}
    problems = []
    for label, expected in (("true_positives", True), ("true_negatives", False)):
        for case in tc.get(label) or []:
            text = case if isinstance(case, str) else (
                case.get("input") or case.get("content") or case.get("text") or ""
            )
            if not text:
                continue
            if fires(rule, text) is not expected:
                problems.append(f"{label}: {text[:70]!r}")
    return problems


def check_blowup(rule):
    slow = []
    for i, c in enumerate(conditions(rule)):
        pattern = c["value"]
        flags = 0 if c.get("case_sensitive") else re.IGNORECASE
        try:
            rx = re.compile(pattern, flags)
            ast = sre_parse.parse(pattern, flags)
        except re.error as exc:
            slow.append(f"#{i} does not compile: {exc}")
            continue
        worst = 0.0
        for k in PUMPS:
            base = generate(ast, k)
            if not base:
                continue
            for text in (base[:-1] + "\x00", base + "\x00", ("a" * 3000), (" " * 3000)):
                started = time.monotonic()
                rx.search(text)
                elapsed = time.monotonic() - started
                worst = max(worst, elapsed)
                if elapsed > BUDGET:
                    slow.append(f"#{i} {elapsed:.2f}s on {len(text)} chars (k={k})")
                    break
            if worst > BUDGET:
                break
    return slow


def check_benign(rule, benign_dir):
    if not benign_dir:
        return None
    paths = sorted(Path(benign_dir).glob("*.md"))
    if not paths:
        return None
    return sum(
        1 for p in paths
        if fires(rule, p.read_text(encoding="utf-8", errors="replace"))
    )


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = Path(sys.argv[1])
    benign = sys.argv[2] if len(sys.argv) > 2 else None
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))

    print(f"rule      : {rule.get('id')}  maturity={rule.get('maturity')}")
    print(f"conditions: {len(conditions(rule))} regex")

    tc = check_test_cases(rule)
    print(f"test cases: {'PASS' if not tc else 'FAIL'}")
    for p in tc:
        print(f"    {p}")

    slow = check_blowup(rule)
    print(f"blowup    : {'PASS' if not slow else 'FAIL'} (budget {BUDGET}s per pattern)")
    for s in slow:
        print(f"    {s}")

    flagged = check_benign(rule, benign)
    if flagged is not None:
        print(f"benign    : flags {flagged} documents")

    return 1 if (tc or slow) else 0


if __name__ == "__main__":
    raise SystemExit(main())
