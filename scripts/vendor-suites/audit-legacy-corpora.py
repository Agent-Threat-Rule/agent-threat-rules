#!/usr/bin/env python3
"""
audit-legacy-corpora.py — is each sample of the 2026-05-12 vendor corpora actually in the vendor's repo?

data/test-corpora/{llm-guard,nemo-guardrails,promptfoo}/corpus.json (44 + 6 + 44 = 94 samples, extracted
2026-05-12) each name a `source_file`. This script looks every sample up in that vendor's repo at the
last upstream commit before the extraction date (the pins labelled import-era in sources.json; llm-guard's
tests/ did not change between 2025-09-03 and its current head, so its single pin serves) and classifies it:

  verbatim-in-source-file   the text occurs in the named file. Comparison folds whitespace runs to one space,
                            typographic quotes to ASCII and TS/MD escapes; a .py file is compared on its parsed
                            string constants, so implicit concatenation and \n escapes do not hide a match
  verbatim-elsewhere-in-repo      in another file of the same repo at the same commit
  verbatim-in-other-vendor-suite  another vendor's test case (samples.jsonl), attributed to the wrong vendor
  truncated-or-edited-tail-...    its opening (40-120 chars) is in the named file, the rest is cut or differs
  edited-from-source-file         no verbatim copy; the closest string in the named file has difflib ratio >= 0.6
  edited-from-other-vendor-suite  the closest string (ratio >= 0.6) is another vendor's test case
  not-in-vendor-repo              none of the above: the vendor never shipped this text

Writes data/test-corpora/vendor-guardrail-suites/legacy-corpora-provenance.json.
Uses the same cache and pins as fetch-vendor-suites.py.
"""
from __future__ import annotations

import ast
import difflib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fvs", HERE / "fetch-vendor-suites.py")
fvs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fvs)  # type: ignore[union-attr]

LEGACY = {"llm-guard": "llm-guard", "nemo-guardrails": "nemo-guardrails", "promptfoo": "promptfoo"}
OUT = fvs.CORPUS_DIR / "legacy-corpora-provenance.json"
EDIT_THRESHOLD = 0.6


QUOTES = str.maketrans({"\u201c": '"', "\u201d": '"', "\u201e": '"', "\u2018": "'", "\u2019": "'", "\u00a0": " "})


def py_strings(src: str) -> str:
    """Every string constant of a Python file (implicit concatenation already merged by the parser)."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return src
    return "\n\u241e\n".join(n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def norm(s: str) -> str:
    s = s.translate(QUOTES)
    s = s.replace("\\`", "`").replace("\\$", "$").replace('\\"', '"').replace("\\'", "'").replace("\\n", " ")
    s = re.sub(r"\\([*_`])", r"\1", s)
    return re.sub(r"\s+", " ", s).strip()


def repo_files(repo: Path, commit: str) -> list[str]:
    out = subprocess.run(["git", "ls-tree", "-r", "--name-only", commit], cwd=repo, capture_output=True, text=True)
    keep = (".py", ".ts", ".tsx", ".md", ".mdx", ".yaml", ".yml", ".json", ".txt", ".co", ".jsonl", ".csv")
    return [p for p in out.stdout.splitlines() if p.endswith(keep)]


def candidates(raw: str, path: str) -> list[str]:
    """Units a sample could have been copied from: string constants (.py) or lines (anything else)."""
    if path.endswith(".py"):
        try:
            tree = ast.parse(raw)
            units = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        except SyntaxError:
            units = raw.splitlines()
    else:
        units = raw.splitlines()
    return [u for u in (norm(x) for x in units) if len(u) >= 12]


def best_edit(needle: str, units: list[str]) -> tuple[float, str | None]:
    best, unit = 0.0, None
    for u in units:
        sm = difflib.SequenceMatcher(None, needle, u, autojunk=False)
        if sm.real_quick_ratio() <= best or sm.quick_ratio() <= best:
            continue
        r = sm.ratio()
        if r > best:
            best, unit = r, u
    return best, unit


STATUSES = ("verbatim-in-source-file", "verbatim-elsewhere-in-repo", "verbatim-in-other-vendor-suite",
            "truncated-or-edited-tail-from-source-file", "edited-from-source-file", "edited-from-other-vendor-suite",
            "not-in-vendor-repo")


def main() -> int:
    sources = {v["vendor"]: v for v in json.loads(fvs.SOURCES.read_text())["vendors"]}
    extracted = [json.loads(l) for l in fvs.SAMPLES.read_text().splitlines()]
    by_norm = {norm(r["text"]): r for r in extracted}
    report = {"generated_by": "scripts/vendor-suites/audit-legacy-corpora.py",
              "statuses": {
                  "verbatim-in-source-file": "text occurs in the file the corpus names",
                  "verbatim-elsewhere-in-repo": "text occurs in another file of the same vendor repo at the same commit",
                  "verbatim-in-other-vendor-suite": "text is another vendor's test case (attributed to the wrong vendor)",
                  "edited-from-source-file": f"no verbatim occurrence; closest string in the named file has difflib ratio >= {EDIT_THRESHOLD} "
                                             "(truncated, translated parts removed, a token replaced, ...)",
                  "truncated-or-edited-tail-from-source-file": "its first characters (up to 120, at least 40, trailing \"...\" dropped) occur in the named file; the rest is cut or differs",
                  "edited-from-other-vendor-suite": f"closest match (ratio >= {EDIT_THRESHOLD}, or the same opening characters) is another vendor's test case",
                  "not-in-vendor-repo": "no verbatim occurrence anywhere in the vendor repo and no close string in the named file",
              },
              "comparison": "whitespace runs folded to one space, typographic quotes folded to ASCII, TS/markdown escapes "
                            "removed; .py files compared on their parsed string constants",
              "corpora": {}}
    for vendor, folder in LEGACY.items():
        corpus = json.loads((fvs.REPO_ROOT / "data" / "test-corpora" / folder / "corpus.json").read_text())
        v = sources[vendor]
        pin = next((p for p in v["pins"] if p["label"].startswith("import-era")), v["pins"][0])
        repo = fvs.ensure_commit(v["repo"], pin["commit"])
        raw_cache: dict[str, str] = {}
        cache: dict[str, str] = {}

        def raw_of(path: str) -> str:
            if path not in raw_cache:
                raw_cache[path] = fvs.show(repo, pin["commit"], path) or ""
            return raw_cache[path]

        def text_of(path: str) -> str:
            if path not in cache:
                raw = raw_of(path)
                cache[path] = norm(py_strings(raw) if path.endswith(".py") else raw)
            return cache[path]

        all_files = None
        rows, tally = [], {k: 0 for k in STATUSES}
        for a in corpus["attacks"]:
            needle = norm(a["text"])
            status, found_in, ratio = "not-in-vendor-repo", None, None
            if needle and needle in text_of(a["source_file"]):
                status, found_in = "verbatim-in-source-file", a["source_file"]
            else:
                if all_files is None:
                    all_files = repo_files(repo, pin["commit"])
                for f in all_files:
                    if needle and needle in text_of(f):
                        status, found_in = "verbatim-elsewhere-in-repo", f
                        break
                other = by_norm.get(needle)
                if status == "not-in-vendor-repo" and other is not None and other["vendor"] != vendor:
                    p0 = json.loads(fvs.MANIFEST.read_text())["provenance"][other["id"]][0]
                    status, found_in = "verbatim-in-other-vendor-suite", f"{p0['vendor']}:{p0['path']}@{p0['commit'][:12]}"
                head = needle.rstrip(".\u2026 ")[:120]  # a copy cut short, often with a trailing "..."
                if status == "not-in-vendor-repo" and len(head) >= 40 and head in text_of(a["source_file"]):
                    status, found_in = "truncated-or-edited-tail-from-source-file", a["source_file"]
                if status == "not-in-vendor-repo":
                    r, _unit = best_edit(needle, candidates(raw_of(a["source_file"]), a["source_file"]))
                    ratio = round(r, 3)
                    if r >= EDIT_THRESHOLD:
                        status, found_in = "edited-from-source-file", a["source_file"]
                if status == "not-in-vendor-repo":
                    others = [x for x in extracted if x["vendor"] != vendor]
                    r, unit = best_edit(needle, [norm(x["text"]) for x in others])
                    pre = [norm(x["text"]) for x in others if len(head) >= 40 and norm(x["text"]).startswith(head)]
                    if pre:
                        r, unit = max(r, EDIT_THRESHOLD), pre[0]
                    if r >= EDIT_THRESHOLD:
                        hit = next(x for x in others if norm(x["text"]) == unit)
                        p0 = json.loads(fvs.MANIFEST.read_text())["provenance"][hit["id"]][0]
                        status, ratio = "edited-from-other-vendor-suite", round(r, 3)
                        found_in = f"{p0['vendor']}:{p0['path']}@{p0['commit'][:12]}"
            tally[status] += 1
            rows.append({"sha256": fvs.sha(a["text"]), "claimed_source_file": a["source_file"], "label": a.get("label"),
                         "attack_family": a.get("attack_family"), "status": status, "found_in": found_in,
                         "closest_ratio_in_claimed_file": ratio, "text_prefix": a["text"][:80]})
        report["corpora"][vendor] = {"corpus_file": f"data/test-corpora/{folder}/corpus.json",
                                     "extraction_date": corpus.get("extraction_date"), "samples": len(rows),
                                     "checked_against": {"repo": v["repo"], "commit": pin["commit"], "pin": pin["label"]},
                                     "tally": tally, "samples_detail": rows}
        print(f"{vendor}: {len(rows)} samples — {tally}")
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
