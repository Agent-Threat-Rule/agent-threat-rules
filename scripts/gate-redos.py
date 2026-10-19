#!/usr/bin/env python3
r"""Corpus-wide ReDoS gate: no rule may blow up on adversarial input.

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
string that started the investigation. scripts/verify_rule_redos.py --base REF
replays the inputs derived from the pattern at REF against the new one for
exactly this reason, and uses this script's own inputs and timing, so the
per-rule check and the corpus gate cannot disagree about the same pattern.

HOW THE INPUTS ARE BUILT

Generic adversarial strings are not enough and it is worth being precise about
why: a run of 'a', a run of spaces and a base64 blob together find three of the
nine patterns this gate was written after, and miss the exponential one
entirely. So each input is generated from the pattern's OWN parse tree, with
quantifiers pumped past their minimum, then truncated at the tail so the match
must fail after doing maximal work.

Those short pumped inputs find exponential blowups. They do not find the
polynomial ones, and in October 2026 two independent consumers packaging the
corpus (one timing every rule on 8,000-character runs, one timing every
condition on 50,000-character pumped inputs) each found conditions that hang
for seconds to minutes while this gate reported them clean. Three things hid
them, and each has its own fix below:

  1. Length. A quadratic condition costs about a tenth of a second at the
     1,500-3,000 characters the short inputs use, under budget, and tens of
     seconds at 50,000. Every condition is now also run on inputs of
     --long-chars characters (default 20,000), where a quadratic that costs
     0.1s at 3,000 costs over 4s. The TypeScript engine evaluates fields up to
     100,000 characters, so 20,000 is well inside what a caller can be handed.
  2. Only the first alternative was ever pumped. A blowup inside the fourth
     branch of an alternation (ATR-2026-01006 condition 2) was unreachable.
     Long inputs are now built per quantifier, not per pattern: for every
     repeat that can run long, the string that reaches it (through whichever
     branches lead there) is followed by a long run of that repeat's own body,
     then a NUL meant to fail the match (a class that admits NUL, such as
     [\s\S], swallows it, and the run then ends the input). That aims at "two adjacent
     quantifiers that can split one run" (\s+ then [^,\n]{0,60}, or <!--\s*
     then \s*) and at "a quantifier that rescans from every start" (---+,
     (?:^|\n)\s*), which together were every miss.
  3. A pattern that does not compile under `re` was skipped silently. pyatr
     falls back to the `regex` module and the TypeScript engine compiles with
     JavaScript, so such conditions can run in production without ever being
     timed here. They are now counted and listed by key, so the gap is visible
     rather than a silent 0.0.

The long inputs also include the pattern's own openers tiled -- every literal
a match can begin with, repeated to length -- and the pumped near-match tiled.
Issue #601 found the worst case of several rules this way: when every position
can start a match, a scan that is cheap once is paid at every offset, and no
single-start input shows it.

WHY THE STANDARD LIBRARY AND NOT THE regex MODULE

`regex` accepts timeout= and would make this script far simpler. It also
optimises away several of the shapes being hunted -- ATR-2026-01005 returns in
microseconds under `regex` and in four minutes under `re`. A gate built on
`regex` would report a clean corpus while every Python consumer using the
standard library hangs. So `re` it is, and since a `re` match cannot be
stopped from outside its own thread, the work runs in child processes the
parent kills.

TIMEOUTS ARE ATTRIBUTED EXACTLY, NOT BY GUESS

Conditions run in chunks across --jobs worker processes. Before every search a
worker tells the parent which condition it is about to run, over a pipe that
is written synchronously (a multiprocessing.Queue is flushed by a background
thread that cannot run while `re` holds the interpreter, so the last message
before a hang could still be sitting in the child). When one search exceeds
--wall, the parent kills that worker, records the condition it named, and
restarts the chunk after it. Before this, a timed-out chunk was bisected; with
long inputs dozens of conditions exceed the wall, and bisecting each one cost
minutes of reruns.

A NEW finding is confirmed before it fails the build: each condition over budget
that is not in the baseline is re-timed alone, with no other worker running,
and the faster run is the one judged. Parallel workers share memory bandwidth,
and a gate that fails on contention teaches people to rerun it until it passes.

BASELINE

Known debt lives in data/redos-baseline.json. The gate fails on anything not
already there, so existing slow patterns stay visible without blocking every
build, and accepting a new one is a deliberate --update-baseline commit.

Each entry carries a fingerprint of the pattern it was measured on. With a few
hundred entries keyed RULE#index, a key alone would let any edit to a baselined
condition -- including one that makes it slower -- pass forever; an edited
pattern is therefore NEW again until it is fast or re-baselined on purpose. A
baselined hang whose pattern is unchanged is not re-run (--remeasure-known
runs it): under the same generator the answer cannot differ, and each one
costs a full wall clock. A change to this script's inputs is the moment to
--update-baseline, which re-runs everything.

Usage:
    python3 scripts/gate-redos.py [--budget 0.3] [--update-baseline] [--rules DIR]
                                  [--long-chars 20000] [--jobs N]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import re
import signal
import sys
import time
from multiprocessing.connection import wait as wait_for
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

# Long inputs. See "HOW THE INPUTS ARE BUILT" for why length is its own axis.
LONG_CHARS = 20_000
# Characters a homogeneous long run is made of. The short GENERIC runs above
# stay as they are; these are the same idea at a length where a quadratic shows.
LONG_FILLERS = ("a", " ", "a ", "\n", "\t", "-", "=", "*", "{", '"', "<", ">",
                "0", "!", ".", "/", ":", "_")
# A repeat is pumped to length when it is unbounded or its maximum exceeds this.
# A small bounded repeat such as [^\n]{0,120} cannot scale with the input on
# its own; pumping it past its bound only produces the failing tail.
PUMP_FLOOR = 256
# Characters tried as the body of a pumped class, after the class's own pick.
# Space and newline matter most: nearly every miss was two whitespace-accepting
# quantifiers splitting one run between them.
RUN_PROBES = (" ", "\n", "a", "-", "0", "\t", "{", ".")
RUNS_PER_TARGET = 3
# Upper bound on long inputs per condition, so a pattern with hundreds of
# quantifiers cannot dominate the scan. Targets are taken in parse-tree order.
MAX_LONG_INPUTS = 160
# Upper bound on tiled openers per condition; a 100-way alternation of words
# would otherwise add a hundred inputs.
MAX_OPENERS = 24
# --update-baseline records every condition over this share of the budget, not
# only those over the budget itself, because readings of one condition spread
# by more than 2x across runs and machines. In reference-machine seconds,
# ATR-2026-00051#7 read between 0.13s and 0.30s alone on one laptop and at
# least 0.31s alone on a GitHub runner; calibration scales the budget for a
# machine but does not make every regex shape slow down by the same ratio. A
# margin of one half left it out and failed CI; a third covers a 3x spread.
# Contention is the other source of spread, and what absorbs it in a check is
# the re-time-alone step (a parallel reading has been seen 7x above the same
# condition alone). "Improved" uses the same line, so a few entries near it
# read as improved on any given run.
BASELINE_MARGIN = 1 / 3
_REPEATS = tuple(getattr(sre, name) for name in
                 ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") if hasattr(sre, name))


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


def generate(node, k, depth=0, groups=None):
    r"""A string the pattern almost matches, with quantifiers pumped to k.

    A positive lookbehind's own text is emitted where it stands, and a
    back-reference repeats what its group produced: otherwise no input ever
    satisfies the guard, and every quantifier behind it is unreachable --
    `(?<=key:)\s*[ \t]*\S*!` read 0.000s here and takes about 1.8s on "key:"
    and a space run.
    """
    if depth > 12:
        return ""
    groups = {} if groups is None else groups
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
        elif op in _REPEATS:
            lo, hi, sub = av
            reps = max(lo, k)
            if hi != sre.MAXREPEAT:
                reps = min(reps, hi)
            out.append(generate(sub, k, depth + 1, groups) * min(reps, 40))
        elif op is sre.SUBPATTERN:
            text = generate(av[-1], k, depth + 1, groups)
            if av[0] is not None:
                groups[av[0]] = text
            out.append(text)
        elif op is sre.BRANCH:
            branches = av[1]
            out.append(generate(branches[0], k, depth + 1, groups) if branches else "")
        elif op is sre.ATOMIC_GROUP:
            out.append(generate(av, k, depth + 1, groups))
        elif op is sre.ASSERT and av[0] < 0:
            out.append(generate(av[1], k, depth + 1, groups))
        elif op is sre.GROUPREF:
            out.append(groups.get(av, ""))
    return "".join(out)


def _class_accepts(op, av, ch, ignorecase):
    """Does the single-character item (op, av) match ch?"""
    variants = {ch, ch.lower(), ch.upper()} if ignorecase else {ch}
    if op is sre.LITERAL:
        return any(ord(v) == av for v in variants)
    if op is sre.NOT_LITERAL:
        return all(ord(v) != av for v in variants)
    if op is sre.ANY:
        return ch != "\n"
    if op is not sre.IN:
        return False
    negated = bool(av) and av[0][0] is sre.NEGATE
    hit = False
    for item_op, item_av in (av[1:] if negated else av):
        if item_op is sre.LITERAL:
            hit = any(ord(v) == item_av for v in variants)
        elif item_op is sre.RANGE:
            hit = any(item_av[0] <= ord(v) <= item_av[1] for v in variants)
        elif item_op is sre.CATEGORY:
            hit = {
                sre.CATEGORY_DIGIT: ch.isdecimal(),
                sre.CATEGORY_NOT_DIGIT: not ch.isdecimal(),
                sre.CATEGORY_SPACE: ch.isspace(),
                sre.CATEGORY_NOT_SPACE: not ch.isspace(),
                sre.CATEGORY_WORD: ch.isalnum() or ch == "_",
                sre.CATEGORY_NOT_WORD: not (ch.isalnum() or ch == "_"),
            }.get(item_av, False)
        if hit:
            break
    return hit != negated


def _run_units(sub, ignorecase):
    r"""What one iteration of a pumped repeat is made of.

    For a single-character body, the character generate() would pick plus the
    first few probe characters the class also accepts -- a run of spaces aimed
    at [^,\n]{0,60} is what collides with the \s+ beside it, and generate()
    alone would emit "{". For a longer body, its pumped form.
    """
    items = list(sub)
    if len(items) == 1 and items[0][0] in (sre.LITERAL, sre.NOT_LITERAL, sre.ANY, sre.IN):
        op, av = items[0]
        units = [generate(items, 2)]
        for probe in RUN_PROBES:
            if len(units) >= RUNS_PER_TARGET:
                break
            if probe not in units and _class_accepts(op, av, probe, ignorecase):
                units.append(probe)
        return [u for u in units if u]
    unit = generate(items, 2)
    return [unit] if unit else []


def _targets(seq, ignorecase, depth=0, groups=None):
    """(prefix, units) for every pumpable repeat reachable in this sequence.

    The prefix is the text that carries a match to the repeat: everything
    before it in the sequence, generated minimally, and inside an alternation
    only the branch that contains it. So a repeat in the fourth branch is
    reached through the fourth branch, which the short inputs never did.
    """
    if depth > 12:
        return []
    groups = {} if groups is None else groups
    found = []
    done = ""
    for op, av in seq:
        inner = []
        if op in _REPEATS:
            lo, hi, sub = av
            if hi == sre.MAXREPEAT or hi > PUMP_FLOOR:
                inner.append(("", _run_units(sub, ignorecase)))
            inner += _targets(sub, ignorecase, depth + 1, groups)
        elif op is sre.SUBPATTERN:
            inner = _targets(av[-1], ignorecase, depth + 1, groups)
        elif op is sre.BRANCH:
            for branch in av[1]:
                inner += _targets(branch, ignorecase, depth + 1, groups)
        elif op is sre.ATOMIC_GROUP:
            inner = _targets(av, ignorecase, depth + 1, groups)
        elif op in (sre.ASSERT, sre.ASSERT_NOT):
            inner = _targets(av[1], ignorecase, depth + 1, groups)
        found += [(done + prefix, units) for prefix, units in inner]
        done += generate([(op, av)], 2, depth + 1, groups)
    return found


def _openers(seq, depth=0):
    """Literal text a match can begin with, one string per leading branch.

    Issue #601's shape: an input made entirely of the pattern's own anchor,
    repeated. ATR-2026-00220 took 220x longer on 64KB of "echo" than on any
    shape tried before it. When every position starts a match, a scan that is
    cheap once is paid at every offset.
    """
    prefix = ""
    for op, av in seq:
        if op in (sre.AT, sre.ASSERT, sre.ASSERT_NOT):
            continue
        if op is sre.LITERAL:
            prefix += chr(av)
            continue
        if depth < 12 and op is sre.SUBPATTERN:
            return [prefix + o for o in _openers(av[-1], depth + 1)]
        if depth < 12 and op is sre.BRANCH:
            return [prefix + o for branch in av[1] for o in _openers(branch, depth + 1)]
        if depth < 12 and op in _REPEATS and av[0] >= 1:
            return [prefix + o for o in _openers(av[2], depth + 1)]
        break
    return [prefix]


def long_inputs(ast, flags, length):
    """Inputs of about `length` characters: homogeneous runs, then one long run
    of every pumpable repeat's own body after the text that reaches it."""
    texts = [(filler * length)[:length] for filler in LONG_FILLERS]
    # Tiled: each literal a match can open with, and the pumped near-match.
    openers = list(dict.fromkeys(o for o in _openers(list(ast)) if o))[:MAX_OPENERS]
    base = generate(ast, 2)
    for unit in openers + ([base[:-1]] if len(base) > 1 else []):
        texts.append((unit * (length // len(unit) + 1))[:length] + "\x00")
    seen = set(texts)
    pumped = 0
    for prefix, units in _targets(list(ast), bool(flags & re.IGNORECASE)):
        for unit in units:
            text = prefix + unit * max(1, (length - len(prefix)) // len(unit)) + "\x00"
            if text not in seen:
                seen.add(text)
                texts.append(text)
                pumped += 1
            if pumped >= MAX_LONG_INPUTS:
                return texts
    return texts


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


def adversarial_inputs(pattern, flags, long_chars=LONG_CHARS):
    """Every input this gate aims at one pattern. Raises re.error if `re`
    cannot parse it."""
    ast = sre_parse.parse(pattern, flags)
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
    if long_chars:
        texts += long_inputs(ast, flags, long_chars)
    return texts


def _worst(pattern, flags, budget, long_chars=LONG_CHARS, before_search=None, source=None):
    """Slowest single search over this pattern's adversarial inputs, or None
    when `re` cannot compile the pattern. With `source`, the inputs are the
    ones derived from that pattern instead -- how scripts/verify_rule_redos.py
    aims the inputs of a rule's previous pattern at its rewrite."""
    try:
        rx = re.compile(pattern, flags)
        sre_parse.parse(source or pattern, flags)
    except (re.error, OverflowError, RecursionError):
        # OverflowError: a repeat count past sre's limit, e.g. {4294967296}.
        return None
    texts = adversarial_inputs(source or pattern, flags, long_chars)
    worst = 0.0
    for text in texts:
        if before_search:
            before_search()
        started = time.monotonic()
        rx.search(text)
        elapsed = time.monotonic() - started
        if elapsed > worst:
            worst = elapsed
        if worst > budget:
            break
    return worst


def _run_chunk(items, budget, long_chars, reference, conn):
    """Child: time a chunk in order, naming each condition before every search.

    Connection.send writes from this thread. A multiprocessing.Queue would hand
    the message to a feeder thread, which cannot run while `re` holds the
    interpreter -- so the last "starting X" before a hang could stay in the
    child and the parent would blame the condition before it.

    Times are reported in reference-machine seconds: the chunk calibrates in
    this process first and divides by its own factor. One calibration at the
    start of the run was not enough. Writing a baseline on a shared machine,
    the start-of-run factor was 3.25x while the load later fell, so eleven
    conditions that are 1.05-1.6x over budget on a quiet run read as under
    half of it and were left out -- a baseline that would have failed the next
    CI run. Calibrating per chunk, in the worker that does the timing, puts
    each measurement and its yardstick under the same load.
    """
    factor = machine_factor(reference)
    for key, pattern, flags, *source in items:
        conn.send(("start", key))
        worst = _worst(pattern, flags, budget * factor, long_chars,
                       before_search=lambda key=key: conn.send(("search", key)),
                       source=source[0] if source else None)
        conn.send(("done", key, None if worst is None else round(worst / factor, 4)))
    conn.close()


def measure(items, budget, wall, long_chars=LONG_CHARS, jobs=1, reference=None):
    """Time every condition across `jobs` workers.

    `budget` and the returned times are reference-machine seconds (see
    _run_chunk); `wall` is real seconds. Returns (results, hung, uncompilable).
    A search running longer than `wall` gets its worker killed; the condition
    that worker last named is recorded as hung and the rest of its chunk is
    requeued.
    """
    results, hung, uncompilable, stalls = {}, [], [], {}
    # Small enough that every worker gets several chunks, so one slow chunk at
    # the end does not leave the others idle.
    size = max(1, min(CHUNK, -(-len(items) // (max(1, jobs) * 4))))
    pending = [items[i:i + size] for i in range(0, len(items), size)]
    running = {}
    while pending or running:
        while pending and len(running) < max(1, jobs):
            chunk = pending.pop(0)
            reader, writer = mp.Pipe(duplex=False)
            proc = mp.Process(target=_run_chunk, args=(chunk, budget, long_chars, reference, writer),
                              daemon=True)
            proc.start()
            writer.close()
            running[reader] = {"proc": proc, "chunk": chunk, "key": None,
                               "since": time.monotonic(), "done": set()}
        for reader in wait_for(list(running), timeout=0.2):
            state = running[reader]
            try:
                while reader.poll():
                    kind, key, *rest = reader.recv()
                    state["since"] = time.monotonic()
                    if kind == "done":
                        state["key"] = None
                        state["done"].add(key)
                        if rest[0] is None:
                            uncompilable.append(key)
                        else:
                            results[key] = rest[0]
                    else:
                        state["key"] = key
            except EOFError:
                state["proc"].join()
                _retire(reader, state, running, pending, results, hung, stalls)
        now = time.monotonic()
        for reader, state in list(running.items()):
            if state["key"] is not None and now - state["since"] > wall:
                state["proc"].kill()
                state["proc"].join()
                _retire(reader, state, running, pending, results, hung, stalls)
    return results, hung, uncompilable


def _retire(reader, state, running, pending, results, hung, stalls):
    """A worker is gone: record what it was running, requeue what it never got to.

    A worker that dies before naming any condition (in its calibration, at
    spawn, killed for memory) made no progress, so requeueing its chunk as is
    would loop forever. The second such death on the same chunk blames the
    chunk's first condition, which guarantees progress and fails loudly.
    """
    reader.close()
    del running[reader]
    culprit = state["key"]
    if culprit is None and not state["done"]:
        first = state["chunk"][0][0]
        stalls[first] = stalls.get(first, 0) + 1
        if stalls[first] >= 2:
            culprit = first
    if culprit is not None:
        hung.append(culprit)
        results[culprit] = float("inf")
        state["done"].add(culprit)
    rest = [it for it in state["chunk"] if it[0] not in state["done"]]
    if rest:
        pending.insert(0, rest)


def confirm(keys, by_key, budget, wall, long_chars, reference=None):
    """Re-time each condition alone, with no other worker competing."""
    out = {}
    for key in keys:
        results, _, _ = measure([by_key[key]], budget, wall, long_chars, jobs=1, reference=reference)
        out[key] = results.get(key, float("inf"))
    return out


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


def machine_factor(reference: float | None) -> float:
    """How much slower this process runs the reference workload right now."""
    if not reference:
        return 1.0
    # Clamp so a wildly noisy calibration cannot disable the gate outright or
    # make it absurdly strict.
    return min(max(calibrate() / reference, 0.5), 8.0)


def fingerprint(pattern, flags):
    """Identity of a condition's regex, so an edited pattern loses its
    baseline entry instead of inheriting it under the same RULE#index key."""
    return hashlib.sha256(f"{int(flags)}:{pattern}".encode("utf-8")).hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=float, default=0.3,
                    help="reference-machine seconds any single search may take")
    ap.add_argument("--wall", type=float, default=2.0,
                    help="seconds one search may run before its worker is killed and "
                         "the condition recorded as a hang (scaled by the machine factor)")
    ap.add_argument("--long-chars", type=int, default=LONG_CHARS,
                    help="length of the long inputs; 0 turns them off and leaves only "
                         "the short pumped inputs this gate used before")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1,
                    help="worker processes; NEW findings are re-timed alone either way")
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--baseline", type=Path, default=BASELINE)
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--remeasure-known", action="store_true",
                    help="also re-run baselined hangs whose pattern is unchanged; they "
                         "are skipped by default because the answer cannot differ")
    ap.add_argument("--recalibrate", action="store_true",
                    help="also re-measure the machine reference. Only on a quiet "
                         "machine, and only deliberately: the reference is the "
                         "anchor the budget is scaled against, so re-measuring it "
                         "on every baseline write makes the ratio always 1 and the "
                         "calibration a no-op.")
    args = ap.parse_args()
    # A SIGTERM (a caller's timeout) should take the workers down with it.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))

    doc = {}
    if args.baseline.exists():
        doc = json.loads(args.baseline.read_text(encoding="utf-8"))
    reference = doc.get("calibration_reference_seconds")
    baseline = doc.get("known", {})
    # An entry without a fingerprint vouches for nothing: every baseline this
    # script writes has them, and a key alone would exempt any later edit.
    prints = doc.get("fingerprints") or {}
    if baseline and doc.get("long_chars", args.long_chars) != args.long_chars:
        print(f"warning: {args.baseline} was written with --long-chars "
              f"{doc.get('long_chars')}, this run uses {args.long_chars}")

    # Budgets and reported times are reference-machine seconds; each worker
    # calibrates for itself (see _run_chunk). This run-level factor only
    # scales the wall clock that decides when a search has hung.
    factor = machine_factor(reference)
    if reference:
        print(f"machine calibration factor {factor:.2f}x at start; each worker "
              f"re-calibrates per chunk and times are reported in reference seconds")
    wall = max(args.wall * factor, args.budget * factor * 2)

    items = collect(Path(args.rules))
    if not items:
        print(f"no regex conditions under {args.rules}", file=sys.stderr)
        return 2
    by_key = {it[0]: it for it in items}
    current = {k: fingerprint(it[1], it[2]) for k, it in by_key.items()}
    vouched = {k for k in baseline if k in current and prints.get(k) == current[k]}
    changed = sorted(k for k in baseline if k in current and k not in vouched)

    # A baselined hang whose pattern is unchanged cannot come out differently
    # under the same generator, and each costs a worker a full wall clock.
    skipped = set()
    if not args.update_baseline and not args.remeasure_known:
        skipped = {k for k in vouched if baseline[k] == "hang"}
    todo = [it for it in items if it[0] not in skipped]
    print(f"scanning {len(todo)} regex conditions ({len(skipped)} baselined hangs with "
          f"unchanged patterns skipped), budget {args.budget:.3f}s per search, long "
          f"inputs {args.long_chars} chars, {args.jobs} worker(s)")

    started = time.monotonic()
    results, hung, uncompilable = measure(todo, args.budget, wall, args.long_chars, args.jobs,
                                          reference)
    results.update({k: float("inf") for k in skipped})
    over = {k: v for k, v in results.items() if v > args.budget}
    print(f"parallel pass took {time.monotonic() - started:.0f}s")

    # Re-time conditions alone before they count. In a check: every would-be
    # NEW finding, judged by the faster reading, so contention cannot fail it.
    # When writing the baseline: every condition within reach of the margin,
    # judged by the SLOWER reading, so that an under-read cannot leave out a
    # condition a later check will see over the budget (on a hybrid CPU a
    # chunk's calibration and its searches can land on different cores), and
    # a hang is recorded only if it also hangs alone, so a contention-inflated
    # reading is not frozen as "hang" and skipped by every later check.
    if args.update_baseline:
        line = args.budget * BASELINE_MARGIN
        retime = sorted(k for k, v in results.items() if v > line / 2)
    else:
        retime = sorted(k for k in over if k not in vouched)
    if retime:
        print(f"re-timing {len(retime)} condition(s) alone")
        for k, v in confirm(retime, by_key, args.budget, wall, args.long_chars, reference).items():
            if not args.update_baseline:
                results[k] = min(results[k], v)
            elif results[k] == float("inf"):
                results[k] = v
            else:
                results[k] = max(results[k], v)
        over = {k: v for k, v in results.items() if v > args.budget}
    near = {k: v for k, v in results.items() if v > args.budget * BASELINE_MARGIN}
    print(f"total {time.monotonic() - started:.0f}s")

    if uncompilable:
        # Not a failure: these can run under the `regex` module in pyatr or
        # under JavaScript in the TypeScript engine, neither of which this gate
        # times. Listed so the gap is visible instead of reading as clean.
        print(f"\n{len(uncompilable)} condition(s) do not compile under Python re and "
              f"were not timed: " + ", ".join(sorted(uncompilable)))

    if args.update_baseline:
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        # Keep the existing anchor unless asked to move it.
        anchor = reference if (reference and not args.recalibrate) else round(calibrate(), 6)
        args.baseline.write_text(
            json.dumps(
                {
                    "_comment": "Conditions known to backtrack badly on adversarial "
                                "input. Produced by scripts/gate-redos.py "
                                "--update-baseline. Shrinking this file is the goal; "
                                "growing it needs a reason in the commit message. "
                                "Times are reference-machine seconds: each worker "
                                "divides by its own calibration against "
                                "calibration_reference_seconds. An entry covers only "
                                "the pattern its fingerprint names; editing the "
                                "pattern makes it new again.",
                    "budget_seconds": args.budget,
                    "calibration_reference_seconds": anchor,
                    "baseline_margin": BASELINE_MARGIN,
                    "long_chars": args.long_chars,
                    "known": {k: ("hang" if v == float("inf") else v)
                              for k, v in sorted(near.items())},
                    "fingerprints": {k: current[k] for k in sorted(near)},
                },
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
        print(f"baseline written: {len(near)} known slow conditions "
              f"({len(over)} over the budget, {len(near) - len(over)} under it but "
              f"over {BASELINE_MARGIN:.2f}x)")
        return 0

    fresh = sorted(k for k in over if k not in vouched)
    fixed = sorted(k for k in baseline if k in current and k not in skipped and k not in near)

    for k in sorted(over):
        mark = "known" if k in vouched else ("NEW (pattern changed)" if k in changed else "NEW ")
        worst = results[k]
        shown = "hang" if worst == float("inf") else f"{worst:.2f}s"
        print(f"  {mark} {k:24} {shown}")
    if hung:
        print(f"\n{len(hung)} condition(s) never returned and were killed")
    if skipped:
        print(f"{len(skipped)} baselined hang(s) with unchanged patterns were not re-run "
              f"(--remeasure-known runs them)")
    if fixed:
        print(f"\n{len(fixed)} condition(s) improved and can leave the baseline: "
              + ", ".join(fixed))
    absent = sorted(k for k in baseline if k not in current)
    if absent and Path(args.rules).resolve() == Path("rules").resolve():
        # Only on a scan of the corpus itself, so a one-rule run (the semantic
        # precheck, a temp directory) does not list the whole file.
        print(f"\n{len(absent)} baseline entr(y/ies) name a condition that no longer "
              f"exists and can leave the baseline: " + ", ".join(absent))

    if fresh:
        print(f"\nFAIL: {len(fresh)} condition(s) backtrack catastrophically and are "
              f"not in {args.baseline} (or their pattern changed since)")
        return 1
    print(f"\nOK: {len(over)} known, 0 new")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
