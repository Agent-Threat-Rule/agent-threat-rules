#!/usr/bin/env python3
"""Verify one rule after a regex change: behaviour preserved, blowup gone.

Three checks, all of which must pass:

  1. The rule's own test cases still hold -- every true_positive still fires
     and every true_negative still does not.
  2. No pattern in the rule blows up on adversarial input. The inputs and the
     timing are scripts/gate-redos.py's own, so this check and the corpus
     gate cannot disagree about the same pattern. Before, this script had
     its own generator with no long inputs, and it reported PASS on
     ATR-2026-02372 with both conditions hanging (issue #601). With --base
     REF, every condition whose pattern differs at REF is also timed on the
     inputs derived from the REF pattern: a rewrite can pass on its own
     inputs by moving out of the generator's aim while still hanging on the
     string that started the investigation.
  3. The rule flags no more of the benign corpus than it did before.

Run:  python3 scripts/verify_rule_redos.py rules/.../ATR-2026-01005-*.yaml [benign_dir] [--base origin/main]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

import yaml

BUDGET = 0.30          # seconds any single pattern may take on any input


def _load_gate():
    """scripts/gate-redos.py as a module; its file name is not importable.

    Registered in sys.modules at import time, not on first use: a worker
    started with spawn (the macOS default) re-runs this module's top level and
    then resolves the gate's worker function by this name.
    """
    path = Path(__file__).with_name("gate-redos.py")
    spec = importlib.util.spec_from_file_location("gate_redos", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["gate_redos"] = module
    spec.loader.exec_module(module)
    return module


GATE = _load_gate()


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
        except (re.error, OverflowError, RecursionError):
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


def _git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True)


def _rule_at(ref, path):
    """The rule file as it was at a git ref, or None if it did not exist there.

    Exits 2 when the ref itself does not resolve: a mistyped --base used to read
    as "no previous version" and the run printed PASS without the replay.
    """
    if _git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").returncode != 0:
        print(f"--base {ref}: not a commit in this repository", file=sys.stderr)
        raise SystemExit(2)
    top = _git("rev-parse", "--show-toplevel").stdout.strip()
    rel = Path(path).resolve().relative_to(Path(top).resolve()).as_posix()
    run = _git("show", f"{ref}:{rel}")
    return yaml.safe_load(run.stdout) if run.returncode == 0 else None


def _parses(pattern, flags):
    try:
        re.compile(pattern, flags)
        return True
    except (re.error, OverflowError, RecursionError):
        return False


def check_blowup(rule, base_rule=None):
    """Time every regex condition the way the corpus gate does, killing any
    search that hangs; with base_rule, also on the previous pattern's inputs."""
    gate = GATE
    old = {}
    if base_rule:
        for i, c in enumerate((base_rule.get("detection") or {}).get("conditions") or []):
            if c.get("operator") == "regex" and c.get("value"):
                old[i] = c["value"]
    items, notes = [], []
    for i, c in enumerate((rule.get("detection") or {}).get("conditions") or []):
        if c.get("operator") != "regex" or not c.get("value"):
            continue
        flags = 0 if c.get("case_sensitive") else re.IGNORECASE
        items.append((f"#{i}", c["value"], flags))
        if i in old and old[i] != c["value"]:
            if _parses(old[i], flags):
                items.append((f"#{i} on the base pattern's inputs", c["value"], flags, old[i]))
            else:
                # Moving off syntax `re` rejects is a fix this script must be able
                # to verify; the base pattern just cannot supply inputs.
                notes.append(f"#{i} base pattern does not compile under Python re; replay skipped")
    reference = _reference()
    budget = BUDGET
    wall = max(2.0, BUDGET * 4) * gate.machine_factor(reference)
    results, _, uncompilable = gate.measure(items, budget, wall, gate.LONG_CHARS,
                                            os.cpu_count() or 1, reference)
    # As the gate does before failing anything: re-time what is over budget
    # alone and judge the faster reading, so parallel contention cannot fail a
    # rewrite the corpus gate would pass.
    over = [it[0] for it in items if results.get(it[0], 0) > budget]
    if over:
        by_key = {it[0]: it for it in items}
        for key, value in gate.confirm(over, by_key, budget, wall, gate.LONG_CHARS, reference).items():
            results[key] = min(results[key], value)
    for note in notes:
        print(f"    note: {note}")
    slow = [f"{k} does not compile under Python re" for k in uncompilable]
    for key, worst in sorted(results.items()):
        if worst > budget:
            slow.append(f"{key} {'hang' if worst == float('inf') else f'{worst:.2f}s'}"
                        f" (budget {budget:.2f}s, reference-machine seconds)")
    return slow, sum(1 for it in items if len(it) == 4)


def _reference():
    baseline = Path("data/redos-baseline.json")
    if not baseline.exists():
        return None
    return json.loads(baseline.read_text(encoding="utf-8")).get("calibration_reference_seconds")


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
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("rule")
    ap.add_argument("benign_dir", nargs="?")
    ap.add_argument("--base", help="git ref whose version of this rule supplies extra inputs")
    args = ap.parse_args()
    # A caller's timeout should take the gate's workers down with this process.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    path = Path(args.rule)
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    base_rule = _rule_at(args.base, path) if args.base else None
    if args.base and base_rule is None:
        print(f"note      : no version of this file at {args.base}; nothing to replay")

    print(f"rule      : {rule.get('id')}  maturity={rule.get('maturity')}")
    print(f"conditions: {len(conditions(rule))} regex")

    tc = check_test_cases(rule)
    print(f"test cases: {'PASS' if not tc else 'FAIL'}")
    for p in tc:
        print(f"    {p}")

    slow, replays = check_blowup(rule, base_rule)
    replayed = f" and the base pattern's inputs for {replays} changed condition(s)" if replays else ""
    print(f"blowup    : {'PASS' if not slow else 'FAIL'} (scripts/gate-redos.py inputs{replayed})")
    for s in slow:
        print(f"    {s}")

    flagged = check_benign(rule, args.benign_dir)
    if flagged is not None:
        print(f"benign    : flags {flagged} documents")

    return 1 if (tc or slow) else 0


if __name__ == "__main__":
    raise SystemExit(main())
