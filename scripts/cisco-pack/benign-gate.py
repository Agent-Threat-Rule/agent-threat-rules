#!/usr/bin/env python3
"""Run an exported ATR pack inside Cisco Skill Scanner over benign skills.

ATR's own benign checks run ATR's engine on ATR's event shape. The exported
pack runs somewhere else: Skill Scanner applies each pattern to every line of a
skill's files, compiled by Python ``re``. A rule can be clean in one and fire on
most skills in the other, so this measures the pack where it actually runs and
records every ATR rule that fires on a benign skill. export-cisco-pack.ts
--benign-gate then leaves those rules out.

Run it with the interpreter of a Skill Scanner checkout, so the scanner and its
dependencies import from there:

    /path/to/skill-scanner/.venv/bin/python scripts/cisco-pack/benign-gate.py \\
        --scanner /path/to/skill-scanner --pack dist/cisco-pack \\
        --corpus data/skill-benchmark/benign --out data/cisco-pack-benign-gate.json

The corpus is a directory of Markdown files, one skill each; each is scanned as
the SKILL.md of its own skill directory. A rule counts as firing on a record
when it produces any finding there, whatever its severity: the pack's severity
is ATR's, and a downstream threshold should not hide a rule that matches benign
text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scanner", required=True, type=Path, help="Skill Scanner checkout")
    parser.add_argument("--pack", required=True, type=Path, help="exported pack directory (has signatures/)")
    parser.add_argument("--corpus", required=True, type=Path, help="directory of benign skill .md files")
    parser.add_argument("--out", required=True, type=Path, help="where to write the gate result JSON")
    return parser.parse_args(argv)


def corpus_digest(files: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.name.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii") + b"\n")
    return digest.hexdigest()


def scanner_commit(scanner: Path) -> str:
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(scanner), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    commit = result.stdout.strip()
    if result.returncode != 0 or len(commit) != 40:
        raise SystemExit(f"benign-gate: {scanner} is not a git checkout")
    return commit


def build_scanner(scanner: Path, signatures: Path):
    sys.path.insert(0, str(scanner))
    from skill_scanner.core.analyzer_factory import build_analyzers
    from skill_scanner.core.rule_registry import PackLoader
    from skill_scanner.core.scan_policy import ScanPolicy
    from skill_scanner.core.scanner import SkillScanner

    policy = ScanPolicy.from_preset("balanced")
    analyzers = build_analyzers(policy, extra_rules_dirs=[signatures])
    return SkillScanner(analyzers=analyzers, policy=policy, rule_registry=PackLoader().build_registry())


def atr_rule_id(signature_id: str) -> str | None:
    """``ATR_2026_00099`` -> ``ATR-2026-00099``; None for a non-ATR finding."""
    if not signature_id.startswith("ATR_"):
        return None
    return signature_id.replace("_", "-")


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    signatures = args.pack / "signatures"
    if not signatures.is_dir():
        raise SystemExit(f"benign-gate: no signatures/ under {args.pack}")
    files = sorted(args.corpus.glob("*.md"))
    if not files:
        raise SystemExit(f"benign-gate: no .md files under {args.corpus}")

    os.environ["SKILL_SCANNER_DISABLE_NETWORK"] = "1"
    scanner = build_scanner(args.scanner.resolve(), signatures.resolve())
    hits: Counter[str] = Counter()
    with tempfile.TemporaryDirectory(prefix="atr-benign-gate-") as tmp:
        for path in files:
            skill = Path(tmp) / path.stem
            skill.mkdir()
            (skill / "SKILL.md").write_bytes(path.read_bytes())
            result = scanner.scan_skill(skill)
            fired = {atr_rule_id(str(f.rule_id)) for f in result.findings} - {None}
            hits.update(fired)

    out = {
        "scanner": {"repo": "cisco-ai-defense/skill-scanner", "commit": scanner_commit(args.scanner)},
        "corpus": {"path": args.corpus.as_posix(), "records": len(files), "sha256": corpus_digest(files)},
        "hits": dict(sorted(hits.items())),
    }
    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"benign-gate: {len(hits)} rules fire on {len(files)} benign skills -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
