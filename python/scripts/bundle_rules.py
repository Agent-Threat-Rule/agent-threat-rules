#!/usr/bin/env python3
"""Bundle the canonical ATR rule set into pyatr for distribution.

pyatr's engine matches against ATR rules, but the published wheel must be
self-contained: a pip-installed pyatr has no access to the repository's
``rules/`` directory. This script compiles the canonical YAML rules into a
single ``pyatr/_bundled_rules.json`` that ships inside the package and is
loaded via :func:`importlib.resources` at runtime.

Only the fields the engine actually consumes are kept, so the bundle stays
small (the rich compliance / references metadata is dropped).

Run manually for local development::

    python scripts/bundle_rules.py

The PyPI publish workflow runs it automatically before building.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Fields consumed by pyatr.engine._parse_rule / _evaluate_rule. Everything
# else in a rule file (compliance, references, provenance, author, ...) is
# irrelevant to Layer-1 matching and is intentionally excluded.
ENGINE_FIELDS = ("id", "title", "severity", "description", "status", "detection", "tags")


def find_rules_dir() -> Path | None:
    """Locate the canonical rules/ directory (repo root, two levels up)."""
    candidate = Path(__file__).resolve().parents[2] / "rules"
    return candidate if candidate.is_dir() else None


def collect(rules_dir: Path) -> list[dict]:
    """Load every .yaml/.yml rule under *rules_dir*, slimmed to engine fields."""
    import yaml  # imported lazily so the no-op path needs no yaml at build time

    out: list[dict] = []
    for root, _dirs, files in os.walk(rules_dir):
        for fname in sorted(files):
            if not fname.endswith((".yaml", ".yml")):
                continue
            try:
                data = yaml.safe_load((Path(root) / fname).read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(data, dict) or "id" not in data or "detection" not in data:
                continue
            out.append({k: data[k] for k in ENGINE_FIELDS if k in data})
    out.sort(key=lambda r: str(r.get("id", "")))
    return out


def main() -> int:
    target = Path(__file__).resolve().parents[1] / "pyatr" / "_bundled_rules.json"
    rules_dir = find_rules_dir()
    if rules_dir is None:
        # Building from an sdist (canonical rules/ not present). Keep the
        # bundle that was already generated and shipped inside the sdist.
        if target.is_file():
            print(f"bundle_rules: canonical rules/ not found; keeping existing {target.name}")
            return 0
        print("bundle_rules: ERROR rules/ not found and no existing bundle present", file=sys.stderr)
        return 1
    rules = collect(rules_dir)
    if not rules:
        print(f"bundle_rules: ERROR no rules collected from {rules_dir}", file=sys.stderr)
        return 1
    target.write_text(json.dumps(rules, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    size_kb = target.stat().st_size / 1024
    print(f"bundle_rules: wrote {len(rules)} rules -> {target} ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
