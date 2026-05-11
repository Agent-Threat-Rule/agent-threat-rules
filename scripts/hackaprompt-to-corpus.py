#!/usr/bin/env python3
"""
HackAPrompt → ATR corpus converter.

Downloads the HackAPrompt dataset from HuggingFace, samples representative
adversarial prompts, and emits a JSON file in the shape ATR's eval harness
expects (text/category/label/source/language).

Usage:
    python3 scripts/hackaprompt-to-corpus.py --sample 5000

Output: data/hackaprompt/hackaprompt-corpus.json
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

from datasets import load_dataset


def to_corpus_record(row: dict, idx: int) -> dict | None:
    """Map a HackAPrompt row to ATR corpus shape.

    Every HackAPrompt submission is by construction an adversarial prompt
    (the user is trying to break the system prompt). So `label=True` for
    every row. Category derived from `correct` field:
      - correct=True  → successful jailbreak/injection (high confidence attack)
      - correct=False → attempted but failed (still adversarial intent)
    """
    user_input = (row.get("user_input") or "").strip()
    if not user_input or len(user_input) < 3:
        return None
    # Cap individual prompts to 4 KB to keep eval runtime sensible
    text = user_input[:4096]
    correct = bool(row.get("correct", False))
    level = row.get("level", -1)
    return {
        "id": f"hap-{idx:07d}",
        "text": text,
        "category": "jailbreak" if correct else "prompt-injection",
        "label": True,
        "source": "hackaprompt",
        "language": "en",
        "metadata": {
            "level": level,
            "correct": correct,
            "model": row.get("model", "unknown"),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=int, default=5000,
                        help="number of samples to draw (default 5000)")
    parser.add_argument("--seed", type=int, default=20260511,
                        help="random seed for reproducibility")
    parser.add_argument("--out", type=str, default="data/hackaprompt/hackaprompt-corpus.json")
    parser.add_argument("--full", action="store_true",
                        help="export full dataset instead of sample")
    args = parser.parse_args()

    print(f"Loading hackaprompt/hackaprompt-dataset from HuggingFace...", flush=True)
    ds = load_dataset("hackaprompt/hackaprompt-dataset", split="train")
    total = len(ds)
    print(f"  loaded {total:,} rows", flush=True)

    if args.full:
        indices = range(total)
        print(f"Exporting all {total:,} rows...", flush=True)
    else:
        random.seed(args.seed)
        indices = sorted(random.sample(range(total), min(args.sample, total)))
        print(f"Sampling {len(indices):,} rows with seed={args.seed}...", flush=True)

    records: list[dict] = []
    dropped = 0
    for idx in indices:
        rec = to_corpus_record(ds[idx], idx)
        if rec is None:
            dropped += 1
            continue
        records.append(rec)

    print(f"  emitted {len(records):,} records ({dropped} dropped as empty/short)", flush=True)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    print(f"Wrote {out_path}", flush=True)

    # quick stat dump
    by_correct = {"true": 0, "false": 0}
    by_level: dict[str, int] = {}
    for r in records:
        c = "true" if r["metadata"]["correct"] else "false"
        by_correct[c] += 1
        lvl = str(r["metadata"]["level"])
        by_level[lvl] = by_level.get(lvl, 0) + 1
    print(f"  by correct: {by_correct}")
    print(f"  by level:   {dict(sorted(by_level.items()))}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
