#!/usr/bin/env python3
"""
HackAPrompt → ATR corpus converter.

Downloads the HackAPrompt dataset from HuggingFace, samples representative
adversarial prompts, and emits a JSON file in the shape ATR's eval harness
expects (text/category/label/source/language).

Usage:
    python3 scripts/hackaprompt-to-corpus.py --sample 5000

Output: data/hackaprompt/hackaprompt-corpus.json (gitignored: the dataset is
gated on HuggingFace and not redistributable) plus
data/hackaprompt/hackaprompt-corpus.manifest.json (committed: dataset id,
pinned revision, seed, the selected row indices and SHA-256 digests, so a
re-run can be checked byte for byte without redistributing any prompt text).

The defaults reproduce the 4,780-sample set first measured in PR #51
(2026-05-11): revision 25b87fbe..., seed 20260511, 5,000 indices drawn with
random.sample over all 601,757 rows, rows whose stripped user_input is
shorter than 3 characters dropped (220), text capped at 4,096 characters.
"""

from __future__ import annotations

import argparse
import hashlib
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


DATASET_ID = "hackaprompt/hackaprompt-dataset"
# HuggingFace commit of the dataset repo. Unchanged since 2024-01-24; it is the
# revision the PR #51 corpus was drawn from. Pin it so a new upstream commit
# cannot silently change the sample.
DEFAULT_REVISION = "25b87fbedfb86840abaf8cd09af7a029208a971a"
DEFAULT_MANIFEST = "data/hackaprompt/hackaprompt-corpus.manifest.json"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def corpus_bytes(records: list[dict]) -> bytes:
    """The exact bytes written to the corpus file (and hashed in the manifest)."""
    return json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")


def build_manifest(records: list[dict], *, revision: str, seed: int, sample: int,
                   total: int, dropped: int, full: bool, body: bytes) -> dict:
    ids = [r["id"] for r in records]
    return {
        "dataset_id": DATASET_ID,
        "dataset_revision": revision,
        "split": "train",
        "rows_total": total,
        "selection": "full" if full else f"random.seed({seed}); sorted(random.sample(range({total}), {sample}))",
        "seed": None if full else seed,
        "requested": total if full else sample,
        "dropped_short_or_empty": dropped,
        "filter": "user_input.strip() of length >= 3; text = user_input.strip()[:4096]; label = true for every row",
        "samples": len(records),
        "corpus_sha256": sha256_hex(body),
        "sample_ids_sha256": sha256_hex("\n".join(ids).encode("utf-8")),
        "sample_ids_sha256_input": "sample ids joined by a single newline, no trailing newline",
        "row_indices": [int(i.split("-")[1]) for i in ids],
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
    parser.add_argument("--revision", type=str, default=DEFAULT_REVISION,
                        help="HuggingFace dataset commit to load (default: the pinned revision)")
    parser.add_argument("--manifest", type=str, default=DEFAULT_MANIFEST,
                        help="where to write the provenance manifest")
    args = parser.parse_args()

    print(f"Loading {DATASET_ID}@{args.revision} from HuggingFace...", flush=True)
    ds = load_dataset(DATASET_ID, split="train", revision=args.revision)
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
    body = corpus_bytes(records)
    out_path.write_bytes(body)
    print(f"Wrote {out_path}", flush=True)

    manifest = build_manifest(records, revision=args.revision, seed=args.seed, sample=args.sample,
                              total=total, dropped=dropped, full=args.full, body=body)
    manifest_path = Path(args.manifest)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {manifest_path} (corpus sha256 {manifest['corpus_sha256']})", flush=True)

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
