#!/usr/bin/env python3
"""Corpus-wide ReDoS gate: no rule may blow up on adversarial input.

WHY THIS EXISTS ALONGSIDE gate-rule-latency.ts

The latency gate measures what a rule costs on the eval corpus, relative to a
pinned anchor cohort. That catches a rule which is expensive on ordinary text.
It is structurally blind to catastrophic backtracking, because a ReDoS pattern
is fast on the corpus and only explodes on a string shaped like its own
grammar. ATR-2026-01005 sat in the enforce lane at maturity: stable, cost
nothing measurable on the corpus, and took over four minutes on 129 bytes.

A NOTE FOR WHOEVER FIXES A RULE THIS GATE FLAGS

Re-run the gate on the WHOLE corpus, not just the rule you touched, and keep
the input that motivated the fix. Inputs are derived from a pattern own parse
tree, so editing the pattern also changes what this gate aims at it: a rewrite
can pass by moving out of its own generator sights while still hanging on the
string that started the investigation. scripts/verify_rule_redos.py replays
old-pattern-derived inputs against the new pattern for exactly this reason.

HOW THE INPUTS ARE BUILT

Generic adversarial strings are not enough and it is worth being precise about
why: a run of 'a', a run of spaces and a base64 blob together find three of the
nine patterns this gate was written after, and miss the exponential one
entirely. So each input is generated from the pattern's OWN parse tree, with
quantifiers pumped past their minimum, then truncated at the tail so the match
must fail after doing maximal work.

WHY THE STANDARD LIBRARY AND NOT THE regex MODULE

`regex` accepts timeout= and would make this script far simpler. It also
optimises away several of the shapes being hunted -- ATR-2026-01005 returns in
microseconds under `regex` and in four minutes under `re`. A gate built on
`regex` would report a clean corpus while every Python consumer using the
standard library hangs. So `re` it is, and since a `re` match cannot be
interrupted, the work runs in a child process the parent kills.

TIMEOUTS ARE BISECTED, NOT ATTRIBUTED BY GUESS

Conditions run in chunks for speed. When a chunk times out, the parent halves
it and re-runs both halves, so the report names the one condition responsible
rather than the chunk it was in.

BASELINE

Known debt lives in data/redos-baseline.json. The gate fails on anything not
already there, so existing slow patterns stay visible without blocking every
build, and accepting a new one is a deliberate --update-baseline commit.

Usage:
    python3 scripts/gate-redos.py [--budget 0.3] [--update-baseline] [--rules DIR]
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import re
import sys
import time
from pathlib import Path

try:
    import re._parser as sre_parse
    import re._constants as sre
except ImportError:                        # pragma: no cover - older runtimes
    import sre_parse, sre_constants as sre

import yaml

BASELINE = Path("data/redos-baseline.json")

# A fixed workload, timed on the same machine in the same run, so the budget
# tracks how fast that machine is. Without it the gate is an absolute
# millisecond threshold, which is the exact failure gate-rule-latency.ts was
# rewritten to escape: on a GitHub runner roughly twice as slow as the machine
# this was written on, six conditions sitting at 0.15-0.25s crossed a 0.3s line
# while nothing about them had changed. The reference number below was measured
# on that authoring machine; the ratio is what matters, not the absolute value.
CALIBRATION_PATTERN = r"(?i)(?:foo|bar|baz)+\s*[a-z0-9_]{3,40}\s*[:=]\s*\S+"
CALIBRATION_INPUT = ("foobarbaz " * 400) + "token_value = something\n"
CALIBRATION_REPEATS = 200
CALIBRATION_SAMPLES = 5
CALIBRATION_REFERENCE_SECONDS = None  # filled in by --update-baseline
PUMPS = (2, 3, 4, 8, 16)
CHUNK = 40
GENERIC = (
    "a" * 3000,
    " " * 3000,
    "-" * 3000,
    "=" * 3000,
    "*" * 3000,
    "{" * 2000,
    '"' * 2000,
    ">" * 2000,
    "\n" * 2000,
    "QUJDRGVmZ2hpams" * 200,
)


def _negated_pick(items):
    """Pick a character a negated class EXCLUDES-complement shares with its
    neighbours.

    Emitting a plain "a" for every negated class never places the interesting
    character inside the filler, and that is precisely where this bug class
    lives: ATR-2026-00091 is cubic on a run of "{" because its filler was
    [^}], which matches "{" and therefore competes with the literal brace next
    to it. An earlier version of this generator reported that rule clean.
    """
    excluded = set()
    for op, av in items:
        if op is sre.LITERAL:
            excluded.add(chr(av))
        elif op is sre.RANGE:
            excluded.update(chr(c) for c in range(av[0], av[1] + 1))
    for candidate in "{}\"'<>[]()|:;,.= \t":
        if candidate not in excluded:
            return candidate
    return "a"


def _member(items):
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
    """A string the pattern almost matches, with quantifiers pumped to k."""
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
            if av and av[0][0] is sre.NEGATE:
                out.append(_negated_pick(av[1:]))
            else:
                out.append(_member(av))
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


def collect(rules_dir: Path):
    """Every regex condition in the corpus, as (key, pattern, flags)."""
    out = []
    for path in sorted(rules_dir.rglob("*.yaml")):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(rule, dict):
            continue
        rid = rule.get("id")
        det = rule.get("detection") or {}
        for i, cond in enumerate(det.get("conditions") or []):
            if cond.get("operator") != "regex" or not cond.get("value"):
                continue
            flags = 0 if cond.get("case_sensitive") else re.IGNORECASE
            out.append((f"{rid}#{i}", cond["value"], flags))
    return out


def _worst(pattern, flags, budget):
    """Slowest single search over this pattern's adversarial inputs."""
    try:
        rx = re.compile(pattern, flags)
        ast = sre_parse.parse(pattern, flags)
    except re.error:
        return 0.0
    texts = list(GENERIC)
    for k in PUMPS:
        base = generate(ast, k)
        if not base:
            continue
        texts.append(base[:-1] + "\x00")
        texts.append(base + "\x00")
        # A literal prefix followed by a long homogeneous run. Several patterns
        # only reach their ambiguity after their own literal anchor -- for
        # ATR-2026-00146 the blowup needs "env" and then a whitespace run, and
        # neither a bare run of spaces nor the pumped string alone gets there.
        for filler in (" ", "a", "\t", "."):
            texts.append(base[: max(1, len(base) // 2)] + filler * 1500 + "\x00")
    worst = 0.0
    for text in texts:
        started = time.monotonic()
        rx.search(text)
        elapsed = time.monotonic() - started
        if elapsed > worst:
            worst = elapsed
        if worst > budget:
            break
    return worst


def _run_chunk(items, budget, out_q):
    for key, pattern, flags in items:
        out_q.put((key, round(_worst(pattern, flags, budget), 4)))


def measure(items, budget, wall):
    """Time every condition, killing and bisecting any chunk that hangs."""
    results = {}
    pending = [items[i:i + CHUNK] for i in range(0, len(items), CHUNK)]
    hung = []
    while pending:
        chunk = pending.pop(0)
        q = mp.Queue()
        proc = mp.Process(target=_run_chunk, args=(chunk, budget, q))
        proc.start()
        deadline = time.monotonic() + wall * max(1, len(chunk))
        got = {}
        while time.monotonic() < deadline:
            try:
                key, worst = q.get(timeout=0.2)
                got[key] = worst
            except Exception:
                if not proc.is_alive():
                    break
        proc.join(timeout=0.1)
        if proc.is_alive():
            proc.terminate()
            proc.join()
        results.update(got)
        missing = [it for it in chunk if it[0] not in got]
        if missing:
            if len(missing) == 1:
                hung.append(missing[0][0])
                results[missing[0][0]] = float("inf")
            else:
                half = len(missing) // 2
                pending.insert(0, missing[half:])
                pending.insert(0, missing[:half])
    return results, hung


def calibrate() -> float:
    """Seconds this machine takes on the fixed reference workload.

    Median of several samples rather than one. A single sample lands wherever
    the scheduler happened to be: the same machine produced factors of 1.01x,
    1.69x and 2.20x in one afternoon depending on what else was running, and
    the factor decides which conditions are in the baseline. A median over
    repeated samples does not remove that but does stop one unlucky slice from
    setting the budget for the whole scan.
    """
    rx = re.compile(CALIBRATION_PATTERN)
    samples = []
    for _ in range(CALIBRATION_SAMPLES):
        started = time.monotonic()
        for _ in range(CALIBRATION_REPEATS):
            rx.search(CALIBRATION_INPUT)
        samples.append(time.monotonic() - started)
    samples.sort()
    return samples[len(samples) // 2]


def scaled_budget(base: float, reference: float | None) -> tuple[float, float]:
    """Budget adjusted for this machine, and the factor used."""
    if not reference:
        return base, 1.0
    factor = calibrate() / reference
    # Clamp so a wildly noisy calibration cannot disable the gate outright or
    # make it absurdly strict.
    factor = min(max(factor, 0.5), 8.0)
    return base * factor, factor


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=float, default=0.3,
                    help="seconds any single pattern may take on any input")
    ap.add_argument("--wall", type=float, default=2.0,
                    help="seconds of wall clock allowed per condition before the "
                         "child is killed and the chunk bisected")
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--recalibrate", action="store_true",
                    help="also re-measure the machine reference. Only on a quiet "
                         "machine, and only deliberately: the reference is the "
                         "anchor the budget is scaled against, so re-measuring it "
                         "on every baseline write makes the ratio always 1 and the "
                         "calibration a no-op.")
    args = ap.parse_args()

    reference = None
    if BASELINE.exists():
        reference = json.loads(BASELINE.read_text(encoding="utf-8")).get(
            "calibration_reference_seconds"
        )
    budget, factor = scaled_budget(args.budget, reference)
    if reference:
        print(f"machine calibration factor {factor:.2f}x -> budget {budget:.3f}s "
              f"(median of {CALIBRATION_SAMPLES} samples)")
    args.budget = budget

    items = collect(Path(args.rules))
    if not items:
        print(f"no regex conditions under {args.rules}", file=sys.stderr)
        return 2
    print(f"scanning {len(items)} regex conditions, budget {args.budget}s each")

    results, hung = measure(items, args.budget, args.wall)
    over = {k: v for k, v in results.items() if v > args.budget}

    baseline = {}
    if BASELINE.exists():
        baseline = json.loads(BASELINE.read_text(encoding="utf-8")).get("known", {})

    if args.update_baseline:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        # Keep the existing anchor unless asked to move it.
        anchor = reference if (reference and not args.recalibrate) else round(calibrate(), 6)
        BASELINE.write_text(
            json.dumps(
                {
                    "_comment": "Conditions known to backtrack badly on adversarial "
                                "input. Produced by scripts/gate-redos.py "
                                "--update-baseline. Shrinking this file is the goal; "
                                "growing it needs a reason in the commit message.",
                    "budget_seconds": args.budget,
                    "calibration_reference_seconds": anchor,
                    "known": {k: ("hang" if v == float("inf") else v)
                              for k, v in sorted(over.items())},
                },
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
        print(f"baseline written: {len(over)} known slow conditions")
        return 0

    fresh = sorted(k for k in over if k not in baseline)
    fixed = sorted(k for k in baseline if k not in over)

    for k in sorted(over):
        mark = "NEW " if k in fresh else "known"
        worst = results[k]
        shown = "hang" if worst == float("inf") else f"{worst:.2f}s"
        print(f"  {mark} {k:24} {shown}")
    if hung:
        print(f"\n{len(hung)} condition(s) never returned and were killed")
    if fixed:
        print(f"\n{len(fixed)} condition(s) improved and can leave the baseline: "
              + ", ".join(fixed))

    if fresh:
        print(f"\nFAIL: {len(fresh)} condition(s) backtrack catastrophically and are "
              f"not in {BASELINE}")
        return 1
    print(f"\nOK: {len(over)} known, 0 new")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
