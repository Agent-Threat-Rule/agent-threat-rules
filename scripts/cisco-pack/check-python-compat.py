#!/usr/bin/env python3
"""Compile every pattern in an exported Cisco pack with Python's ``re``.

WHY THIS EXISTS

The pack is consumed by a Python scanner, but ATR rules are authored and
tested against JavaScript's regex engine. The two disagree: JavaScript accepts
variable-width look-behind and ``\\u{...}`` escapes, Python's ``re`` does not.
A pattern that Python cannot compile is silently skipped by the consumer's
``re.error`` guard, so it detects nothing while still being counted as a
shipped rule. That gap is invisible from the JavaScript side, which is why it
gets its own check rather than being folded into the exporter.

This reports; it never rewrites a pattern. A pattern in the pack is a verbatim
copy of the rule, and quietly "fixing" one here would make the pack disagree
with the rule it links to. The fix belongs in the rule.

Usage:
    python3 scripts/cisco-pack/check-python-compat.py --pack dist/cisco-pack
    python3 scripts/cisco-pack/check-python-compat.py --pack dist/cisco-pack \\
        --max-failures 28

Exit codes: 0 when the failure count is within --max-failures (default 0),
1 otherwise, and 1 if the pack contains no patterns at all — a check that
inspected nothing must not report success.
"""

from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

import yaml

MIN_MEANINGFUL_PATTERNS = 100


def load_patterns(pack_dir: Path) -> list[tuple[str, str, str]]:
    """Return (signature file name, rule id, pattern) for the whole pack."""
    signatures_dir = pack_dir / "signatures"
    if not signatures_dir.is_dir():
        raise SystemExit(f"no signatures/ directory under {pack_dir}")
    rows: list[tuple[str, str, str]] = []
    for path in sorted(signatures_dir.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for signature in doc.get("signatures") or []:
            for pattern in signature.get("patterns") or []:
                rows.append((path.name, signature.get("atr_id", "?"), pattern))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", required=True, type=Path)
    parser.add_argument(
        "--max-failures",
        type=int,
        default=0,
        help="accept up to this many uncompilable patterns (a known baseline)",
    )
    args = parser.parse_args()

    rows = load_patterns(args.pack)
    if len(rows) < MIN_MEANINGFUL_PATTERNS:
        print(
            f"CONTROL FAILED: only {len(rows)} patterns found under {args.pack}; "
            "refusing to report a pass",
            file=sys.stderr,
        )
        return 1

    failures: list[tuple[str, str, str, str]] = []
    for file_name, rule_id, pattern in rows:
        try:
            re.compile(pattern)
        except re.error as exc:
            failures.append((file_name, rule_id, str(exc), pattern))

    by_reason: collections.Counter[str] = collections.Counter()
    for _, _, reason, _ in failures:
        by_reason[re.sub(r" at position \d+", "", reason)] += 1

    affected = sorted({rule_id for _, rule_id, _, _ in failures})
    print(f"patterns checked: {len(rows)}")
    print(f"uncompilable under Python re: {len(failures)} in {len(affected)} rule(s)")
    for reason, count in by_reason.most_common():
        print(f"  {count:>4}  {reason}")
    if affected:
        print(f"  rules: {', '.join(affected)}")

    if len(failures) > args.max_failures:
        print(
            f"FAIL: {len(failures)} uncompilable pattern(s) exceeds --max-failures "
            f"{args.max_failures}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
