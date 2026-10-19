#!/usr/bin/env python3
"""
HackAPrompt -> ATR corpus converter, and the check that the committed sample
set is still the one it describes.

Two modes:

  check (default when the committed manifest exists)
      Downloads the dataset's parquet file at the pinned revision, verifies its
      SHA-256 against the documented value, re-draws the sample and compares
      corpus_sha256 and sample_ids_sha256 (and the row indices) with the
      committed manifest. On any mismatch it exits 1 and writes nothing. On a
      match it writes the corpus file the runner reads (gitignored) and leaves
      the manifest untouched.

  --write
      Regenerates the corpus and rewrites the manifest. Use it only to pin a
      new sample set on purpose; the diff of the manifest is then the record of
      that change.

Usage:
    python3 scripts/hackaprompt-to-corpus.py            # check, then write the corpus
    python3 scripts/hackaprompt-to-corpus.py --write    # re-pin (rewrites the manifest)

Output: data/hackaprompt/hackaprompt-corpus.json (gitignored: the dataset is
gated on HuggingFace and not redistributable) and, with --write,
data/hackaprompt/hackaprompt-corpus.manifest.json (committed: dataset id,
pinned revision, parquet SHA-256, seed, the selected row indices and SHA-256
digests, so a re-run can be checked byte for byte without redistributing any
prompt text).

The defaults reproduce the 4,780-sample set first measured in PR #51
(2026-05-11): revision 25b87fbe..., seed 20260511, 5,000 indices drawn with
random.sample over all 601,757 rows, rows whose stripped user_input is
shorter than 3 characters dropped (220), text capped at 4,096 characters.

Requires huggingface_hub and pyarrow (imported only when the dataset is read),
and HuggingFace access to the gated dataset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path
from typing import Callable, Sequence

DATASET_ID = "hackaprompt/hackaprompt-dataset"
# HuggingFace commit of the dataset repo. Unchanged since 2024-01-24; it is the
# revision the PR #51 corpus was drawn from. Pin it so a new upstream commit
# cannot silently change the sample.
DEFAULT_REVISION = "25b87fbedfb86840abaf8cd09af7a029208a971a"
PARQUET_FILENAME = "hackaprompt.parquet"
# SHA-256 of hackaprompt.parquet at each revision this script knows. The value
# for the pinned revision is the LFS object id HuggingFace reports for it
# (150,419,795 bytes). A revision missing here cannot be checked.
PARQUET_SHA256 = {
    DEFAULT_REVISION: "bedca308fbd71be57793930e4e4a0dcfbda2a27b6d0f2ad3191bb20a6a315928",
}
DEFAULT_OUT = "data/hackaprompt/hackaprompt-corpus.json"
DEFAULT_MANIFEST = "data/hackaprompt/hackaprompt-corpus.manifest.json"
# What check mode compares. Anything else in the manifest is descriptive.
CHECKED_KEYS = ("dataset_id", "dataset_revision", "parquet_sha256", "seed", "samples",
                "row_indices", "corpus_sha256", "sample_ids_sha256")


def to_corpus_record(row: dict, idx: int) -> dict | None:
    """Map a HackAPrompt row to ATR corpus shape.

    Every HackAPrompt submission is by construction an adversarial prompt (the
    user is trying to break the system prompt), so `label=True` for every row.

    `category` is kept byte-for-byte as PR #51 wrote it ("jailbreak" when the
    row's `correct` is true, else "prompt-injection") so the corpus digest stays
    that of the published set. It is NOT an attack type: HackAPrompt's
    `correct` means the submission made its target model produce the level's
    target output, i.e. the attack succeeded. The runner groups results by that
    outcome (src/eval/hackaprompt-corpus.ts), not by this label.
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


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def corpus_bytes(records: list[dict]) -> bytes:
    """The exact bytes written to the corpus file (and hashed in the manifest)."""
    return json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")


def select_indices(total: int, *, sample: int, seed: int, full: bool) -> Sequence[int]:
    if full:
        return range(total)
    random.seed(seed)
    return sorted(random.sample(range(total), min(sample, total)))


def build_records(get_row: Callable[[int], dict], indices: Sequence[int]) -> tuple[list[dict], int]:
    records: list[dict] = []
    dropped = 0
    for idx in indices:
        rec = to_corpus_record(get_row(idx), idx)
        if rec is None:
            dropped += 1
            continue
        records.append(rec)
    return records, dropped


def build_manifest(records: list[dict], *, revision: str, parquet_sha256: str, seed: int, sample: int,
                   total: int, dropped: int, full: bool, body: bytes) -> dict:
    ids = [r["id"] for r in records]
    return {
        "dataset_id": DATASET_ID,
        "dataset_revision": revision,
        "split": "train",
        "parquet_file": PARQUET_FILENAME,
        "parquet_sha256": parquet_sha256,
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


def compare_to_manifest(fresh: dict, committed: dict) -> list[str]:
    """Every checked key on which the re-drawn sample differs from the committed manifest."""
    problems = []
    for key in CHECKED_KEYS:
        if key not in committed:
            problems.append(f"committed manifest has no {key}")
        elif fresh.get(key) != committed[key]:
            if key == "row_indices":
                problems.append("row_indices differ")
            else:
                problems.append(f"{key}: re-drawn {fresh.get(key)!r}, committed {committed[key]!r}")
    return problems


def fetch_parquet(revision: str) -> Path:
    """The dataset's parquet file at `revision`, from the local HuggingFace cache or the Hub."""
    from huggingface_hub import hf_hub_download

    return Path(hf_hub_download(DATASET_ID, PARQUET_FILENAME, repo_type="dataset", revision=revision))


class ParquetRows:
    """Row access by index over the parquet file, the same rows `datasets` serves for split `train`."""

    def __init__(self, path: Path):
        import pyarrow.parquet as pq

        self._table = pq.read_table(path)

    def __len__(self) -> int:
        return self._table.num_rows

    def __call__(self, idx: int) -> dict:
        return self._table.slice(idx, 1).to_pylist()[0]


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--sample", type=int, default=5000, help="number of samples to draw (default 5000)")
    parser.add_argument("--seed", type=int, default=20260511, help="random seed for reproducibility")
    parser.add_argument("--out", type=str, default=DEFAULT_OUT)
    parser.add_argument("--full", action="store_true", help="export full dataset instead of sample")
    parser.add_argument("--revision", type=str, default=DEFAULT_REVISION,
                        help="HuggingFace dataset commit to load (default: the pinned revision)")
    parser.add_argument("--manifest", type=str, default=DEFAULT_MANIFEST,
                        help="the committed provenance manifest")
    parser.add_argument("--write", action="store_true",
                        help="rewrite the manifest instead of checking against it")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None, *,
         fetch: Callable[[str], Path] = fetch_parquet,
         read_rows: Callable[[Path], ParquetRows] = ParquetRows) -> int:
    args = parse_args(argv)
    manifest_path = Path(args.manifest)
    check = not args.write
    if check and not manifest_path.exists():
        print(f"error: {manifest_path} does not exist; nothing to check against. "
              "Pass --write to pin a new sample set.", file=sys.stderr)
        return 1

    expected_parquet = PARQUET_SHA256.get(args.revision)
    if expected_parquet is None:
        print(f"error: no documented parquet sha256 for revision {args.revision}; "
              "add it to PARQUET_SHA256 after verifying it on the Hub.", file=sys.stderr)
        return 1

    print(f"Fetching {DATASET_ID}@{args.revision}/{PARQUET_FILENAME}...", flush=True)
    parquet = fetch(args.revision)
    parquet_sha = sha256_file(parquet)
    if parquet_sha != expected_parquet:
        print(f"error: {parquet} has sha256 {parquet_sha}, the pinned revision's file is "
              f"{expected_parquet}. Nothing written.", file=sys.stderr)
        return 1
    print(f"  parquet sha256 {parquet_sha} (matches the pinned value)", flush=True)

    rows = read_rows(parquet)
    total = len(rows)
    indices = select_indices(total, sample=args.sample, seed=args.seed, full=args.full)
    records, dropped = build_records(rows, indices)
    body = corpus_bytes(records)
    fresh = build_manifest(records, revision=args.revision, parquet_sha256=parquet_sha, seed=args.seed,
                           sample=args.sample, total=total, dropped=dropped, full=args.full, body=body)
    print(f"  {total:,} rows; {len(records):,} records ({dropped} dropped as empty/short); "
          f"corpus sha256 {fresh['corpus_sha256']}", flush=True)

    if check:
        committed = json.loads(manifest_path.read_text(encoding="utf-8"))
        problems = compare_to_manifest(fresh, committed)
        if problems:
            print(f"error: the re-drawn sample does not match {manifest_path}. Nothing written.", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            return 1
        print(f"  matches {manifest_path} (corpus_sha256, sample_ids_sha256, row_indices)", flush=True)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(body)
    print(f"Wrote {out_path}", flush=True)

    if not check:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(fresh, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {manifest_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
