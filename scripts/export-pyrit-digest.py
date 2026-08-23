#!/usr/bin/env python3
"""Emit a precompiled, Python-`re`-verified rule digest for downstream scorers.

Why this exists: microsoft/PyRIT#1893 added an ATR scorer that imported `pyatr`,
and the maintainer reverted it a day later (#2410) because it made PyRIT
responsible for a third-party package's release cadence. He was right, and the
published wheel proves it — `pyatr` 0.2.7 (2026-07-10) bakes in 713 rules while
this repo is well past that. A consumer that vendors an engine inherits our
release schedule; a consumer that fetches a pinned data artifact does not.

So this emits data, not code: `{rule_id: {patterns, category, severity, ...}}`,
consumed by a `RegexScorer` subclass on the PyRIT side with stdlib `re` and no
new dependency.

Two honesty properties matter more than the file itself:

1. Every pattern is `re.compile()`d here, at build time. A pattern that does not
   compile never reaches the artifact, and the reason is recorded by rule id.
   The failure mode this avoids is Microsoft's own weekly ATR sync in
   agent-governance-toolkit, which runs without `--strict-regex` and skips
   invalid patterns with a warning — so an unknown number of rules are dropped
   from a shipped product and nobody downstream can tell which.

2. Exclusions are diffed against a checked-in baseline and the build FAILS when
   the set changes. Known breakage stays visible; new breakage stops the build.
   Silence is the thing being engineered out.

Note the engine split, because quoting one number for both is wrong: Python `re`
is a backtracking engine and accepts lookahead, backreferences and fixed-width
lookbehind. RE2 (Go, Rust) accepts none of them. A pattern excluded here is a
strictly worse case than a pattern excluded from an RE2 export.

  python3 scripts/export-pyrit-digest.py
  python3 scripts/export-pyrit-digest.py --strict          # any exclusion fails
  python3 scripts/export-pyrit-digest.py --update-baseline
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys

import yaml


def _load_sigma_helpers():
    """Reuse the regex helpers from generate-sigma.py.

    Loaded by path because the filename is hyphenated and therefore not a legal
    module name. Reused rather than reimplemented on purpose: that file already
    owns the escape/character-class-aware regex walk and the inline-flag
    handling, and a second copy of that logic would drift from it silently.
    """
    import importlib.util

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generate-sigma.py")
    spec = importlib.util.spec_from_file_location("atr_generate_sigma", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_sigma = _load_sigma_helpers()
RULES_GLOB = _sigma.RULES_GLOB
strip_leading_i_flag = _sigma.strip_leading_i_flag

DEFAULT_OUT = "data/pyrit/atr-rule-digest.json"
DEFAULT_BASELINE = "data/pyrit/atr-rule-digest-exclusions.json"
DIGEST_SCHEMA_VERSION = "1"

# Fields a PyRIT scorer can actually evaluate. It is handed one MessagePiece —
# a single string — so a condition bound to anything else is not "supported but
# untested", it is unreachable. Recording that per rule rather than dropping it
# silently is the same discipline as reporting unevaluated rules instead of
# counting them clean.
TEXT_FIELDS = frozenset(
    {
        "content",
        "user_input",
        "tool_response",
        "agent_output",
        "tool_args",
        "tool_description",
        "tool_input",
    }
)


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def head_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root(),
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def compile_failure(pattern: str) -> str | None:
    """Return the reason `pattern` will not compile under Python `re`, or None."""
    try:
        re.compile(pattern)
    except re.error as exc:
        return str(exc).split(" at position")[0]
    return None


def build(rules_glob: str) -> tuple[dict, list[dict], int]:
    rules: dict[str, dict] = {}
    exclusions: list[dict] = []
    seen = 0

    for path in sorted(glob.glob(rules_glob, recursive=True)):
        try:
            with open(path, encoding="utf-8") as fh:
                rule = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as exc:
            exclusions.append({"rule": os.path.basename(path), "reason": "unreadable", "detail": str(exc)[:160]})
            continue
        if not isinstance(rule, dict):
            continue

        rid = rule.get("id")
        if not rid:
            continue
        seen += 1

        detection = rule.get("detection") or {}
        combinator = str(detection.get("condition") or "").strip().lower()
        if combinator != "any":
            # RegexScorer reports a hit when ANY named pattern matches. A rule
            # that requires all of its conditions cannot be represented without
            # inventing matches it never claimed, so it is left out rather than
            # approximated.
            exclusions.append({"rule": rid, "reason": "condition-not-any", "detail": combinator or "(absent)"})
            continue

        patterns: list[str] = []
        skipped_fields: set[str] = set()
        failed: list[dict] = []

        for cond in detection.get("conditions") or []:
            if not isinstance(cond, dict) or cond.get("operator") != "regex":
                continue
            field = str(cond.get("field"))
            value = cond.get("value")
            if not isinstance(value, str) or not value:
                continue
            if field not in TEXT_FIELDS:
                skipped_fields.add(field)
                continue
            reason = compile_failure(value)
            if reason:
                failed.append({"reason": reason, "pattern": value[:120]})
                continue
            patterns.append(value)

        for f in failed:
            exclusions.append({"rule": rid, "reason": "pattern-uncompilable", "detail": f["reason"]})

        if not patterns:
            exclusions.append(
                {
                    "rule": rid,
                    "reason": "no-usable-pattern",
                    "detail": (
                        f"{len(failed)} uncompilable, "
                        f"{len(skipped_fields)} non-text field(s): {','.join(sorted(skipped_fields)) or 'none'}"
                    ),
                }
            )
            continue

        # `(?i)` is only legal at the start of a Python pattern, so a consumer
        # that concatenates patterns would break. The flag is lifted here and
        # declared once, which keeps every pattern independently compilable.
        lifted, any_ci = [], False
        for p in patterns:
            body, had = strip_leading_i_flag(p)
            any_ci = any_ci or had
            lifted.append(body if had else p)

        rules[rid] = {
            "title": rule.get("title") or "",
            "category": os.path.basename(os.path.dirname(path)),
            "severity": rule.get("severity") or "unknown",
            "maturity": rule.get("maturity") or "unknown",
            "status": rule.get("status") or "unknown",
            "ignore_case": any_ci,
            "patterns": lifted if any_ci else patterns,
            "unreachable_fields": sorted(skipped_fields),
        }

    return rules, exclusions, seen


def exclusion_key(entries: list[dict]) -> list[list[str]]:
    """Stable, order-independent shape for baseline comparison."""
    return sorted([e["rule"], e["reason"]] for e in entries)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--baseline", default=DEFAULT_BASELINE)
    ap.add_argument(
        "--root",
        default=None,
        help="repository root to read rules from; defaults to this script's repo. Exists so the tests can run the real script against a fixture tree instead of the live corpus.",
    )
    ap.add_argument("--strict", action="store_true", help="fail if ANY rule is excluded")
    ap.add_argument("--update-baseline", action="store_true")
    args = ap.parse_args()

    os.chdir(args.root or repo_root())
    rules, exclusions, total_seen = build(RULES_GLOB)
    # A rule can be both included and carry an exclusion (one bad pattern among
    # several good ones), so these two counts deliberately overlap. Report the
    # rules that produced NOTHING separately from the total exclusion entries.
    dropped = len({e["rule"] for e in exclusions if e["reason"] in ("no-usable-pattern", "condition-not-any", "unreadable")})

    digest = {
        "$comment": "AUTO by scripts/export-pyrit-digest.py — do not edit by hand.",
        "schema_version": DIGEST_SCHEMA_VERSION,
        "engine": "python-re",
        "source_commit": head_commit(),
        "rules_total": total_seen,
        "rules_included": len(rules),
        "rules_dropped": dropped,
        "exclusion_entries": len(exclusions),
        "exclusions": sorted(exclusions, key=lambda e: (e["rule"], e["reason"])),
        "rules": dict(sorted(rules.items())),
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(digest, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    current = exclusion_key(exclusions)
    print(
        f"wrote {args.out} — {len(rules)}/{total_seen} rules included, "
        f"{dropped} dropped entirely, {len(exclusions)} exclusion entries"
    )

    if args.update_baseline:
        os.makedirs(os.path.dirname(args.baseline), exist_ok=True)
        with open(args.baseline, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "$comment": "Known exclusions from the PyRIT digest. The build fails when this set changes; update deliberately.",
                    "exclusions": current,
                },
                fh,
                ensure_ascii=False,
                indent=2,
            )
            fh.write("\n")
        print(f"baseline updated — {len(current)} known exclusions")
        return 0

    if args.strict and exclusions:
        print(f"STRICT: {len(exclusions)} exclusion(s); every rule must be representable", file=sys.stderr)
        return 1

    if not os.path.exists(args.baseline):
        print(f"no baseline at {args.baseline} — run with --update-baseline once to record the current set", file=sys.stderr)
        return 1

    with open(args.baseline, encoding="utf-8") as fh:
        known = [list(x) for x in json.load(fh).get("exclusions", [])]

    added = [x for x in current if x not in known]
    removed = [x for x in known if x not in current]
    if added or removed:
        print("\nEXCLUSION SET CHANGED — failing rather than skipping quietly.", file=sys.stderr)
        for rule, reason in added:
            print(f"  + {rule}  {reason}", file=sys.stderr)
        for rule, reason in removed:
            print(f"  - {rule}  {reason}  (fixed — rerun with --update-baseline)", file=sys.stderr)
        return 1

    print(f"exclusions match baseline ({len(known)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
