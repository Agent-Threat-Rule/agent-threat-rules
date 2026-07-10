#!/usr/bin/env python3
"""Build the ATR skill-security benchmark as a HF-loadable JSONL.

Reads the SKILL.md corpus (benign + malicious) from the ATR repo and emits one
JSON object per sample with a stable, documented schema. Pure stdlib; no
mutation of the source corpus.

Schema per line:
  id             filename stem
  text           full SKILL.md content
  label          "benign" | "malicious"
  source_family  curation family (adv / ninja / openclaw / snyk / real / ...)
  attack_type    for malicious: the attack described (parsed from the name);
                 for benign: null

Usage:
  python build_dataset.py <corpus_dir> <out.jsonl>
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Known curation-family prefixes, longest first so "ninja-evasive" and
# "evasive-stub" win over a bare "ninja"/"evasive" split.
_FAMILIES = (
    "ninja-evasive",
    "evasive-stub",
    "mcp-official",
    "adv",
    "ninja",
    "openclaw",
    "snyk",
    "real",
)

_LEADING_INDEX = re.compile(r"^(?:\d+-)")


def _family(stem: str) -> str:
    for fam in _FAMILIES:
        if stem == fam or stem.startswith(fam + "-"):
            return fam
    return "other"


def _attack_type(stem: str, family: str) -> str:
    """Strip the '<family>-<NNN>-' prefix to leave the attack descriptor."""
    rest = stem[len(family):].lstrip("-")
    rest = _LEADING_INDEX.sub("", rest)
    return rest or "unspecified"


def _record(path: Path, label: str) -> dict:
    stem = path.stem
    family = _family(stem)
    return {
        "id": stem,
        "text": path.read_text(encoding="utf-8", errors="replace"),
        "label": label,
        "source_family": family,
        "attack_type": _attack_type(stem, family) if label == "malicious" else None,
    }


def build(corpus_dir: Path, out_path: Path) -> dict:
    if not corpus_dir.is_dir():
        raise SystemExit(f"corpus dir not found: {corpus_dir}")

    records: list[dict] = []
    for label in ("benign", "malicious"):
        sub = corpus_dir / label
        if not sub.is_dir():
            raise SystemExit(f"missing subdir: {sub}")
        for md in sorted(sub.rglob("*.md")):
            records.append(_record(md, label))

    with out_path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    counts: dict[str, int] = {}
    for rec in records:
        counts[rec["label"]] = counts.get(rec["label"], 0) + 1
    return {"total": len(records), "by_label": counts, "out": str(out_path)}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: build_dataset.py <corpus_dir> <out.jsonl>")
    summary = build(Path(sys.argv[1]), Path(sys.argv[2]))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
