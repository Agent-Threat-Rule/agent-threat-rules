#!/usr/bin/env python3
"""
fetch-vendor-suites.py — rebuild the vendor guardrail test-suite corpus from pinned upstream commits.

Reads  data/test-corpora/vendor-guardrail-suites/sources.json
Writes data/test-corpora/vendor-guardrail-suites/samples.jsonl   (one sample per line, sorted, deduplicated)
       data/test-corpora/vendor-guardrail-suites/manifest.json   (repo + commit + path + line for every sample,
                                                                  counts, and the sha256 of samples.jsonl)
       data/test-corpora/vendor-guardrail-suites/LICENSES/       (each vendor's license file, verbatim from its
                                                                  pinned commits; sha256 in manifest.json)

Nothing in samples.jsonl is typed by hand: every text is read with `git show <commit>:<path>` from a
depth-1 fetch of the pinned commit and selected by the deterministic selector named in sources.json.

  python3 scripts/vendor-suites/fetch-vendor-suites.py            # fetch + write
  python3 scripts/vendor-suites/fetch-vendor-suites.py --check    # fetch + compare with the committed files, exit 1 on drift
                                                                   # (samples.jsonl, manifest digests, LICENSES/ copies)

Needs: python3 >= 3.9, git, network access to github.com. Cache: $VENDOR_SUITES_CACHE or ./.cache/vendor-suites.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import warnings
from pathlib import Path

# Vendor test files contain invalid escape sequences; ast.parse warns about them, harmlessly.
warnings.filterwarnings("ignore", category=SyntaxWarning)

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO_ROOT / "data" / "test-corpora" / "vendor-guardrail-suites"
SOURCES = CORPUS_DIR / "sources.json"
SAMPLES = CORPUS_DIR / "samples.jsonl"
MANIFEST = CORPUS_DIR / "manifest.json"
LICENSES_DIR = CORPUS_DIR / "LICENSES"
CACHE = Path(os.environ.get("VENDOR_SUITES_CACHE", REPO_ROOT / ".cache" / "vendor-suites"))


# --------------------------------------------------------------------------- git

def run(cmd: list[str], cwd: Path) -> str:
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed in {cwd}: {res.stderr.strip()}")
    return res.stdout


def ensure_commit(repo_url: str, commit: str) -> Path:
    """A bare cache repo per upstream, holding at least `commit` (depth-1 fetch by sha)."""
    name = repo_url.rstrip("/").split("/")[-2] + "__" + repo_url.rstrip("/").split("/")[-1]
    path = CACHE / name
    if not path.exists():
        path.mkdir(parents=True)
        run(["git", "init", "-q", "--bare"], path)
        run(["git", "remote", "add", "origin", repo_url], path)
    has = subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=path, capture_output=True)
    if has.returncode != 0:
        for attempt in range(3):
            try:
                run(["git", "fetch", "-q", "--depth", "1", "origin", commit], path)
                break
            except RuntimeError:
                if attempt == 2:
                    raise
    return path


def show_bytes(repo: Path, commit: str, path: str) -> bytes | None:
    res = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=repo, capture_output=True)
    if res.returncode != 0:
        return None
    return res.stdout


def show(repo: Path, commit: str, path: str) -> str | None:
    raw = show_bytes(repo, commit, path)
    return None if raw is None else raw.decode("utf-8")


def license_copy_name(vendor: str, license_file: str) -> str:
    """File name of a vendor's license copy under LICENSES/ (one per vendor: identical across its pins, or the build fails)."""
    return f"{vendor}.{license_file}"


# --------------------------------------------------------------------- extractors
# Each returns a list of (text, line, label, extraction_note).

def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def ex_pytest_parametrize(src: str, sel: dict) -> list[tuple]:
    """@pytest.mark.parametrize("a,prompt,expected_valid,...", [(...), ...]) — label from expected_valid."""
    out = []
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "parametrize"):
            continue
        names = _const_str(node.args[0])
        if names is None or not isinstance(node.args[1], ast.List):
            continue
        cols = [c.strip() for c in names.split(",")]
        if sel["text_arg"] not in cols or sel["valid_arg"] not in cols:
            continue
        ti, vi = cols.index(sel["text_arg"]), cols.index(sel["valid_arg"])
        for row in node.args[1].elts:
            if not isinstance(row, ast.Tuple):
                continue
            text = _const_str(row.elts[ti])
            valid = row.elts[vi]
            if text is None or not (isinstance(valid, ast.Constant) and isinstance(valid.value, bool)):
                continue
            label = "benign" if valid.value else "attack"
            out.append((text, row.lineno, label, f"pytest.mark.parametrize row, {sel['valid_arg']}={valid.value}"))
    return out


def ex_py_assign(src: str, sel: dict) -> list[tuple]:
    """String assigned to one of `names` (module or function scope)."""
    out = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            text = _const_str(node.value)
            if name in sel["names"] and text is not None:
                out.append((text, node.lineno, sel["label"], f"string assigned to `{name}`"))
    return out


def ex_py_literal_prefix(src: str, sel: dict) -> list[tuple]:
    """String constants starting with (or equal to, when exact) one of `prefixes`."""
    out, seen = [], set()
    for node in ast.walk(ast.parse(src)):
        text = _const_str(node)
        if text is None or text in seen:
            continue
        for p in sel["prefixes"]:
            if (text == p) if sel.get("exact") else text.startswith(p):
                seen.add(text)
                out.append((text, node.lineno, sel["label"], f"string literal matching selector prefix {p[:40]!r}"))
                break
    return out


def _ts_unescape(s: str) -> str:
    return s.replace("\\`", "`").replace("\\$", "$").replace("\\\\", "\\")


def _line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def ex_promptfoo_default_examples(src: str, sel: dict) -> list[tuple]:
    """`<Example>` blocks inside the plugin's DEFAULT_EXAMPLES template: `Prompt:` line, `PromptBlock:` block,
    or the `userB` turn of a JSON `Test:` (cross-session leak — userA only plants the secret)."""
    m = re.search(r"const DEFAULT_EXAMPLES = dedent`(.*?)(?<!\\)`;", src, re.S)
    if not m:
        return []
    out = []
    body, base = m.group(1), m.start(1)
    for ex in re.finditer(r"<Example>(.*?)</Example>", body, re.S):
        block, off = ex.group(1), base + ex.start(1)
        pb = re.search(r"PromptBlock:\s*(.*)", block, re.S)
        p = re.search(r"^\s*Prompt:\s*(.*?)\s*$", block, re.M)
        t = re.search(r"Test:\s*(\{.*\})", block, re.S)
        if pb:
            text, at = pb.group(1), off + pb.start(1)
            note = "DEFAULT_EXAMPLES <Example> PromptBlock"
        elif p:
            text, at = p.group(1), off + p.start(1)
            note = "DEFAULT_EXAMPLES <Example> Prompt line"
        elif t:
            try:
                obj = json.loads(_ts_unescape(t.group(1)))
            except json.JSONDecodeError:
                continue
            if "userB" not in obj:
                continue
            text, at = obj["userB"], off + t.start(1)
            note = "DEFAULT_EXAMPLES <Example> Test.userB (the extraction turn)"
        else:
            continue
        text = "\n".join(line.strip() for line in _ts_unescape(text).strip().splitlines())
        out.append((text, _line_of(src, at), "attack", note))
    return out


def ex_promptfoo_docs_examples(src: str, sel: dict) -> list[tuple]:
    """Numbered items under `## Example Test Cases`: `1. Label: "quoted prompt"` (markdown escapes removed)."""
    m = re.search(r"^## Example Test Cases\s*$(.*?)(?=^## )", src, re.S | re.M)
    if not m:
        return []
    out = []
    for item in re.finditer(r'^\d+\.\s+([^:\n]+):\s+"(.*)"\s*$', m.group(1), re.M):
        if item.group(1).strip().lower() == "user a":
            continue  # cross-session leak: User A only plants the secret; the User B turn is the attack
        text = re.sub(r"\\([*_`\\])", r"\1", item.group(2))  # markdown backslash escapes
        out.append((text, _line_of(src, m.start(1) + item.start(2)), "attack",
                    "docs '## Example Test Cases' numbered item, quoted prompt"))
    return out


def ex_promptfoo_docs_blockquote(src: str, sel: dict) -> list[tuple]:
    """Blockquoted injected instruction under `## Example`."""
    m = re.search(r"^## Example\s*$(.*?)(?=^## )", src, re.S | re.M)
    if not m:
        return []
    return [(q.group(1).strip(), _line_of(src, m.start(1) + q.start(1)), "attack",
             "docs '## Example' blockquote (injected web-page instruction)")
            for q in re.finditer(r"^>\s+(.+)$", m.group(1), re.M)]


EXFIL_URL = re.compile(r"!?\[[^\]]*\]\(https?://[^)]*\?[^)]*\)")


def ex_md_backtick_cells(src: str, sel: dict) -> list[tuple]:
    """Backticked markdown image/link payloads carrying a query string (exfil URL patterns table)."""
    return [(c.group(1), _line_of(src, c.start(1)), "attack", "docs table cell, backticked exfil payload")
            for c in re.finditer(r"`([^`\n]+)`", src) if EXFIL_URL.fullmatch(c.group(1))]


def ex_ts_rubric_backticks(src: str, sel: dict) -> list[tuple]:
    """Escaped-backtick exfil payloads quoted in the grader rubric (\\`...\\`)."""
    return [(_ts_unescape(c.group(1)), _line_of(src, c.start(1)), "attack", "grader rubric, quoted exfil payload")
            for c in re.finditer(r"\\`([^`\n]+?)\\`", src) if EXFIL_URL.fullmatch(_ts_unescape(c.group(1)))]


EXTRACTORS = {
    "pytest-parametrize": ex_pytest_parametrize,
    "py-assign": ex_py_assign,
    "py-literal-prefix": ex_py_literal_prefix,
    "promptfoo-default-examples": ex_promptfoo_default_examples,
    "promptfoo-docs-examples": ex_promptfoo_docs_examples,
    "promptfoo-docs-blockquote": ex_promptfoo_docs_blockquote,
    "md-backtick-cells": ex_md_backtick_cells,
    "ts-rubric-backticks": ex_ts_rubric_backticks,
}


# ------------------------------------------------------------------------- build

def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build() -> tuple[str, dict, dict[str, bytes]]:
    sources = json.loads(SOURCES.read_text())
    merged: dict[str, dict] = {}       # key: sha256(text)
    occurrences = 0
    missing_paths = []
    license_check = []
    license_copies: dict[str, bytes] = {}   # LICENSES/<name> -> verbatim bytes at the pinned commits
    for v in sources["vendors"]:
        for pin in v["pins"]:
            repo = ensure_commit(v["repo"], pin["commit"])
            raw = show_bytes(repo, pin["commit"], v["license_file"])
            if raw is None:
                raise SystemExit(f"{v['vendor']}@{pin['commit']}: {v['license_file']} not found")
            lic = raw.decode("utf-8")
            copy = license_copy_name(v["vendor"], v["license_file"])
            if copy in license_copies and license_copies[copy] != raw:
                raise SystemExit(f"{v['vendor']}: {v['license_file']} differs between pins; keep one copy per pin")
            license_copies[copy] = raw
            license_check.append({"vendor": v["vendor"], "commit": pin["commit"], "license_file": v["license_file"],
                                  "declared": v["license"], "license_file_sha256": sha(lic),
                                  "copy": f"data/test-corpora/vendor-guardrail-suites/LICENSES/{copy}",
                                  "first_line": lic.strip().splitlines()[0] if lic.strip() else None})
            for sel in v["selectors"]:
                src = show(repo, pin["commit"], sel["path"])
                if src is None:
                    missing_paths.append({"vendor": v["vendor"], "pin": pin["label"], "path": sel["path"]})
                    continue
                for text, line, label, note in EXTRACTORS[sel["kind"]](src, sel):
                    text = text.strip()
                    if not text:
                        continue
                    occurrences += 1
                    key = sha(text)
                    rec = merged.setdefault(key, {
                        "id": "vgs-" + key[:12], "sha256": key, "text": text, "label": label,
                        "vendor": v["vendor"], "category": sel["category"], "role": sel["role"], "provenance": [],
                    })
                    if rec["label"] != label:
                        raise SystemExit(f"label conflict for {key[:12]}: {rec['label']} vs {label}")
                    prov = {"vendor": v["vendor"], "repo": v["repo"], "commit": pin["commit"], "pin": pin["label"],
                            "path": sel["path"], "line": line, "selector": sel["kind"], "extraction": note,
                            "category": sel["category"], "role": sel["role"]}
                    if prov not in rec["provenance"]:
                        rec["provenance"].append(prov)
    samples = sorted(merged.values(), key=lambda r: (r["vendor"], r["label"], r["category"], r["sha256"]))
    # a text shared by two vendors keeps its first vendor as primary; all vendors are listed
    for r in samples:
        r["vendors"] = sorted({p["vendor"] for p in r["provenance"]})
        r["pins"] = sorted({f"{p['vendor']}@{p['pin']}" for p in r["provenance"]})
    lines = "".join(json.dumps({k: r[k] for k in ("id", "sha256", "vendor", "vendors", "label", "category", "role",
                                                  "pins", "text")}, ensure_ascii=False) + "\n" for r in samples)

    def count(pred, key):
        out: dict[str, int] = {}
        for r in samples:
            if pred(r):
                out[r[key]] = out.get(r[key], 0) + 1
        return dict(sorted(out.items()))

    by_vendor_cat: dict[str, dict] = {}
    for r in samples:
        d = by_vendor_cat.setdefault(r["vendor"], {}).setdefault(r["category"], {"attack": 0, "benign": 0})
        d[r["label"]] += 1
    manifest = {
        "schema": "vendor-guardrail-suites/manifest/v1",
        "generated_by": "scripts/vendor-suites/fetch-vendor-suites.py",
        "samples_file": "data/test-corpora/vendor-guardrail-suites/samples.jsonl",
        "samples_sha256": sha(lines),
        "dedup": "exact text after strip(); identical texts from several pins/paths/vendors are one sample "
                 "with every occurrence listed under provenance",
        "occurrences_extracted": occurrences,
        "samples": len(samples),
        "attacks": sum(r["label"] == "attack" for r in samples),
        "benign": sum(r["label"] == "benign" for r in samples),
        "attacks_by_vendor": count(lambda r: r["label"] == "attack", "vendor"),
        "benign_by_vendor": count(lambda r: r["label"] == "benign", "vendor"),
        "by_vendor_category": by_vendor_cat,
        "cross_vendor_duplicates": [r["id"] for r in samples if len(r["vendors"]) > 1],
        "selector_paths_absent_at_pin": missing_paths,
        "licenses": license_check,
        "redistribution": "Each sample is the vendor's text, redistributed under the license in LICENSES/ that "
                          "its repository carried at the pinned commit. Strings the vendor did not attribute to "
                          "a third party are redistributed under that repository license, with no further claim "
                          "about their origin.",
        "sources": sources["vendors"],
        "inclusion_policy": sources["inclusion_policy"],
        "provenance": {r["id"]: r["provenance"] for r in samples},
    }
    return lines, manifest, license_copies


def license_problems(manifest: dict, copies: dict[str, bytes], committed: dict | None) -> list[str]:
    """Every way the committed LICENSES/ copies or the manifest's license digests disagree with upstream."""
    problems = []
    for name, raw in sorted(copies.items()):
        path = LICENSES_DIR / name
        if not path.exists():
            problems.append(f"LICENSES/{name} missing")
        elif path.read_bytes() != raw:
            problems.append(f"LICENSES/{name} is not the upstream file (sha256 {hashlib.sha256(path.read_bytes()).hexdigest()})")
    for entry in manifest["licenses"]:
        copy = REPO_ROOT / entry["copy"]
        if copy.exists() and hashlib.sha256(copy.read_bytes()).hexdigest() != entry["license_file_sha256"]:
            problems.append(f"{entry['copy']} sha256 != license_file_sha256 for {entry['vendor']}@{entry['commit'][:12]}")
    extra = sorted(p.name for p in LICENSES_DIR.glob("*")) if LICENSES_DIR.exists() else []
    problems += [f"LICENSES/{n} is not a vendor license this corpus uses" for n in extra if n not in copies]
    if committed is not None and committed.get("licenses") != manifest["licenses"]:
        problems.append("manifest.json licenses[] differs from upstream (commit, file or sha256)")
    return problems


def main() -> int:
    check = "--check" in sys.argv
    lines, manifest, license_copies = build()
    text_manifest = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    if check:
        committed = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else None
        ok = SAMPLES.exists() and SAMPLES.read_text() == lines
        ok = ok and committed is not None and committed["samples_sha256"] == manifest["samples_sha256"]
        print(f"samples sha256 {manifest['samples_sha256']} — {'MATCH' if ok else 'DRIFT'}")
        lic = license_problems(manifest, license_copies, committed)
        for p in lic:
            print(f"license: {p}")
        if not lic:
            print(f"licenses: {len(license_copies)} copies in LICENSES/ match the pinned upstream files")
        return 0 if ok and not lic else 1
    SAMPLES.write_text(lines)
    MANIFEST.write_text(text_manifest)
    LICENSES_DIR.mkdir(exist_ok=True)
    for name, raw in license_copies.items():
        (LICENSES_DIR / name).write_bytes(raw)
    print(f"{manifest['samples']} samples ({manifest['attacks']} attack / {manifest['benign']} benign) "
          f"from {manifest['occurrences_extracted']} extracted occurrences")
    print(f"attacks by vendor: {manifest['attacks_by_vendor']}  benign by vendor: {manifest['benign_by_vendor']}")
    print(f"samples.jsonl sha256 {manifest['samples_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
