#!/usr/bin/env python3
"""
fetch-tools-list-corpus.py — rebuild the benign MCP tools/list corpus from pinned upstream commits.

Reads  data/test-corpora/mcp-tools-list-benign/sources.json
Writes data/test-corpora/mcp-tools-list-benign/tools/<server>.json   one reconstructed tools/list document per
                                                                    server whose licence allows redistribution
       data/test-corpora/mcp-tools-list-benign/manifest.json        repo + commit + licence + file + line of every
                                                                    tool, how it was extracted, what could not be
                                                                    folded, and the sha256 of every document
       data/test-corpora/mcp-tools-list-benign/LICENSES/            the licence (and NOTICE) files of every
                                                                    redistributed source, verbatim from its pin;
                                                                    a LICENSE / COPYING / NOTICE file in the repo
                                                                    root or a directory above an extracted file
                                                                    that sources.json does not list fails the run
       <cache>/documents/<server>.json                              every document, redistributable or not (the
                                                                    measurement reads the non-redistributable ones
                                                                    from here)

Nothing from an upstream repository is installed, imported or executed. Each pinned commit is fetched
at depth 1 into a bare cache repository, the files the extractor needs are exported with `git archive`,
and the tool definitions are read statically:
  ts          scripts/mcp-tools-list/extract-ts-tools.ts (TypeScript compiler API parse + constant folding)
  py          scripts/mcp-tools-list/extract_py_tools.py (ast parse + constant folding)
  toolsnaps   JSON tool snapshots the server repository commits (github-mcp-server __toolsnaps__)
  json-array  a committed JSON array of tool definitions (sentry-mcp toolDefinitions.json)

  python3 scripts/mcp-tools-list/fetch-tools-list-corpus.py            # fetch + extract + write
  python3 scripts/mcp-tools-list/fetch-tools-list-corpus.py --check    # fetch + extract + compare with the
                                                                       # committed files, exit 1 on any drift

Needs: python3 >= 3.9, git, node >= 18 with `npm ci` done (for tsx and typescript), network access to
github.com. Cache: $MCP_TOOLS_LIST_CACHE or ./.cache/mcp-tools-list.
"""
from __future__ import annotations

import fnmatch
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = Path(__file__).resolve().parent
CORPUS_DIR = REPO_ROOT / "data" / "test-corpora" / "mcp-tools-list-benign"
SOURCES = CORPUS_DIR / "sources.json"
MANIFEST = CORPUS_DIR / "manifest.json"
TOOLS_DIR = CORPUS_DIR / "tools"
LICENSES_DIR = CORPUS_DIR / "LICENSES"
CACHE = Path(os.environ.get("MCP_TOOLS_LIST_CACHE", REPO_ROOT / ".cache" / "mcp-tools-list"))
TOOL_KEYS = ("name", "title", "description", "inputSchema", "annotations")

_spec = importlib.util.spec_from_file_location("extract_py_tools", SCRIPTS / "extract_py_tools.py")
extract_py = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(extract_py)


# --------------------------------------------------------------------------- git

def run(cmd: list[str], cwd: Path) -> bytes:
    res = subprocess.run(cmd, cwd=cwd, capture_output=True)
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed in {cwd}: {res.stderr.decode(errors='replace').strip()}")
    return res.stdout


def ensure_commit(repo_url: str, commit: str) -> Path:
    """A bare cache repo per upstream holding `commit` (depth-1 fetch by sha)."""
    owner, name = repo_url.rstrip("/").split("/")[-2:]
    path = CACHE / "git" / f"{owner}__{name}"
    if not path.exists():
        path.mkdir(parents=True)
        run(["git", "init", "-q", "--bare"], path)
        run(["git", "remote", "add", "origin", repo_url], path)
    if subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=path, capture_output=True).returncode != 0:
        for attempt in range(3):
            try:
                run(["git", "fetch", "-q", "--depth", "1", "origin", commit], path)
                break
            except RuntimeError:
                if attempt == 2:
                    raise
    return path


def ls_tree(bare: Path, commit: str) -> list[str]:
    return run(["git", "ls-tree", "-r", "--name-only", commit], bare).decode().splitlines()


def show_bytes(bare: Path, commit: str, path: str) -> bytes:
    return run(["git", "show", f"{commit}:{path}"], bare)


def checkout(bare: Path, commit: str, prefixes: list[str]) -> Path:
    """Export the files under `prefixes` at `commit` (git archive, regular files only) into the cache."""
    dest = CACHE / "checkouts" / f"{bare.name}@{commit[:12]}"
    stamp = dest / ".prefixes"
    want = "\n".join(sorted(prefixes))
    if stamp.exists() and stamp.read_text() == want:
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    data = run(["git", "archive", "--format=tar", commit, *prefixes], bare)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar.getmembers():
            target = (dest / member.name).resolve()
            if not member.isfile() or not str(target).startswith(str(dest.resolve())):
                continue  # regular files only, never outside dest
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tar.extractfile(member).read())
    stamp.write_text(want)
    return dest


# --------------------------------------------------------------------------- selection

def select_files(tree: list[str], server: dict) -> list[str]:
    files = list(server.get("files", []))
    for pattern in server.get("files_glob", []):
        files.extend(p for p in tree if fnmatch.fnmatchcase(p, pattern))
    excluded = server.get("exclude_globs", [])
    files = [f for f in files if not any(fnmatch.fnmatchcase(f, e) for e in excluded)]
    missing = [f for f in server.get("files", []) if f not in tree]
    if missing:
        raise RuntimeError(f"{server['id']}: files not in the pinned tree: {missing}")
    seen: set[str] = set()
    return [f for f in files if not (f in seen or seen.add(f))]


def checkout_prefixes(server: dict, files: list[str]) -> list[str]:
    """The directories an extractor may read: each selected file's top two path segments (imports stay inside)."""
    if server["extractor"] in ("toolsnaps", "json-array"):
        return files
    prefixes = {"/".join(f.split("/")[:2]) for f in files}
    for target in server.get("aliases", {}).values():
        prefixes.add(target.rstrip("/"))
    return sorted(prefixes)


# --------------------------------------------------------------------------- extraction

def extract(server: dict, repo: dict, bare: Path, files: list[str]) -> list[dict]:
    commit = repo["commit"]
    kind = server["extractor"]
    if kind == "toolsnaps":
        out = []
        for f in sorted(files):
            tool = json.loads(show_bytes(bare, commit, f))
            out.append({**tool, "_extraction": {"path": f, "line": 1, "shape": "toolsnap", "unresolved": []}})
        return out
    if kind == "json-array":
        out = []
        keep = server.get("keep_keys")
        for f in files:
            for i, tool in enumerate(json.loads(show_bytes(bare, commit, f))):
                kept = {k: tool[k] for k in keep if k in tool} if keep else tool
                out.append({**kept, "_extraction": {"path": f, "line": i, "shape": "json-array-index", "unresolved": []}})
        return out
    root = checkout(bare, commit, checkout_prefixes(server, files))
    if kind == "py":
        tools = []
        for f in files:
            tools.extend(extract_py.discover((root / f).resolve(), root.resolve(), server.get("substitutions", {})))
        return tools
    if kind == "ts":
        cmd = ["npx", "tsx", str(SCRIPTS / "extract-ts-tools.ts"), "--root", str(root)]
        for prefix, target in server.get("aliases", {}).items():
            cmd += ["--alias", f"{prefix}={target}"]
        res = subprocess.run(cmd + files, cwd=REPO_ROOT, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"{server['id']}: extract-ts-tools failed: {res.stderr[-2000:]}")
        return json.loads(res.stdout)
    raise ValueError(f"unknown extractor {kind}")


def names_from(spec: dict, repos: dict) -> set[str]:
    repo = repos[spec["repo_id"]]
    bare = ensure_commit(repo["repo"], repo["commit"])
    text = show_bytes(bare, repo["commit"], spec["path"]).decode()
    return set(re.findall(spec["pattern"], text, flags=re.M))


def canonical(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


LICENSE_NAME = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE)(\.[A-Za-z0-9-]+)?$", re.I)


def unlisted_license_files(tree: list[str], files: list[str], listed: set[str]) -> list[str]:
    """LICENSE / NOTICE files in the repository root or in any directory above a selected file that the
    sources do not list: a redistributed text must carry every licence and notice that covers it."""
    in_tree = set(tree)
    dirs = {""}
    for f in files:
        parts = f.split("/")[:-1]
        dirs.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
    found = {p for p in in_tree if "/".join(p.split("/")[:-1]) in dirs and LICENSE_NAME.match(p.split("/")[-1])}
    return sorted(found - listed)


def build_server(server: dict, repos: dict) -> tuple[dict, dict]:
    repo = repos[server["repo_id"]]
    bare = ensure_commit(repo["repo"], repo["commit"])
    tree = ls_tree(bare, repo["commit"])
    files = select_files(tree, server)
    if not files:
        raise RuntimeError(f"{server['id']}: no files selected")
    if repo["redistribute"]:
        missing = unlisted_license_files(tree, files, set(repo["license_files"]) | set(server.get("license_files", [])))
        if missing:
            raise RuntimeError(f"{server['id']}: licence files that cover the extracted text are not listed in sources.json: {missing}")
    raw = extract(server, repo, bare, files)
    allow = names_from(server["include_names_from"], repos) if "include_names_from" in server else None
    exclude = set(server.get("exclude_names", []))
    kept, provenance, duplicates, dropped = [], [], [], []
    seen: set[str] = set()
    for tool in raw:
        name = tool.get("name")
        if name in seen:
            duplicates.append(name)
            continue
        if name in exclude or (allow is not None and name not in allow):
            dropped.append(name)
            continue
        seen.add(name)
        definition = {k: tool[k] for k in TOOL_KEYS if k in tool and tool[k] is not None}
        definition.update({k: v for k, v in tool.items() if k not in TOOL_KEYS and not k.startswith("_")})
        kept.append(definition)
        provenance.append({**tool["_extraction"], "name": name, "definition_sha256": sha256_text(canonical(definition))})
    if allow is not None and allow - seen:
        raise RuntimeError(f"{server['id']}: tools named by {server['include_names_from']['path']} not extracted: {sorted(allow - seen)}")
    document = {"tools": kept}
    entry = {
        "id": server["id"],
        "repo": repo["repo"],
        "commit": repo["commit"],
        "license": repo["license"],
        "redistributed": repo["redistribute"],
        "extractor": server["extractor"],
        "files": files,
        "tools": len(kept),
        "document": f"tools/{server['id']}.json" if repo["redistribute"] else None,
        "document_sha256": sha256_text(canonical(document)),
        "tools_with_unresolved_text": sorted(p["name"] for p in provenance if p["unresolved"]),
        "duplicates_dropped": duplicates,
        "names_excluded": sorted(set(dropped)),
        "provenance": provenance,
        **({"note": server["note"]} if "note" in server else {}),
    }
    return document, entry


# --------------------------------------------------------------------------- licences

def license_copies(sources: dict, repos: dict) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for repo in sources["repos"]:
        if not repo["redistribute"]:
            continue
        bare = ensure_commit(repo["repo"], repo["commit"])
        for f in repo["license_files"]:
            out[f"{repo['id']}.{Path(f).name}"] = show_bytes(bare, repo["commit"], f)
    for server in sources["servers"]:
        repo = repos[server["repo_id"]]
        if not repo["redistribute"]:
            continue
        bare = ensure_commit(repo["repo"], repo["commit"])
        for f in server.get("license_files", []):
            out[f"{server['id']}.{Path(f).name}"] = show_bytes(bare, repo["commit"], f)
    return out


# --------------------------------------------------------------------------- main

def build(sources: dict) -> tuple[dict[str, str], dict, dict[str, bytes]]:
    repos = {r["id"]: r for r in sources["repos"]}
    documents: dict[str, str] = {}
    entries = []
    for server in sources["servers"]:
        document, entry = build_server(server, repos)
        documents[server["id"]] = canonical(document)
        entries.append(entry)
        print(f"  {server['id']}: {entry['tools']} tools"
              f"{' (unresolved text in ' + str(len(entry['tools_with_unresolved_text'])) + ')' if entry['tools_with_unresolved_text'] else ''}",
              file=sys.stderr)
    licenses = license_copies(sources, repos)
    manifest = {
        "schema": "mcp-tools-list-benign/manifest/v1",
        "generated_by": "scripts/mcp-tools-list/fetch-tools-list-corpus.py",
        "sources_sha256": sha256_text(SOURCES.read_text(encoding="utf-8")),
        "counts": {
            "servers": len(entries),
            "tools": sum(e["tools"] for e in entries),
            "unique_definitions": len({p["definition_sha256"] for e in entries for p in e["provenance"]}),
            "redistributed_servers": sum(1 for e in entries if e["redistributed"]),
        },
        "licenses": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(licenses.items())},
        "servers": entries,
    }
    return documents, manifest, licenses


def main() -> int:
    check = "--check" in sys.argv[1:]
    sources = json.loads(SOURCES.read_text(encoding="utf-8"))
    documents, manifest, licenses = build(sources)
    redistributed = {e["id"] for e in manifest["servers"] if e["redistributed"]}
    cache_docs = CACHE / "documents"
    cache_docs.mkdir(parents=True, exist_ok=True)
    for sid, text in documents.items():
        (cache_docs / f"{sid}.json").write_text(text, encoding="utf-8")
    manifest_text = canonical(manifest)
    if check:
        drift = []
        for sid in redistributed:
            path = TOOLS_DIR / f"{sid}.json"
            if not path.exists() or path.read_text(encoding="utf-8") != documents[sid]:
                drift.append(str(path.relative_to(REPO_ROOT)))
        stray = {p.stem for p in TOOLS_DIR.glob("*.json")} - redistributed if TOOLS_DIR.exists() else set()
        drift += [f"stray tools/{s}.json" for s in sorted(stray)]
        if not MANIFEST.exists() or MANIFEST.read_text(encoding="utf-8") != manifest_text:
            drift.append(str(MANIFEST.relative_to(REPO_ROOT)))
        for name, data in licenses.items():
            path = LICENSES_DIR / name
            if not path.exists() or path.read_bytes() != data:
                drift.append(str(path.relative_to(REPO_ROOT)))
        stray_lic = {p.name for p in LICENSES_DIR.iterdir()} - set(licenses) if LICENSES_DIR.exists() else set()
        drift += [f"stray LICENSES/{s}" for s in sorted(stray_lic)]
        if drift:
            print("DRIFT: " + ", ".join(drift), file=sys.stderr)
            return 1
        print(f"corpus unchanged: {manifest['counts']}", file=sys.stderr)
        return 0
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    LICENSES_DIR.mkdir(parents=True, exist_ok=True)
    for sid in redistributed:
        (TOOLS_DIR / f"{sid}.json").write_text(documents[sid], encoding="utf-8")
    for name, data in licenses.items():
        (LICENSES_DIR / name).write_bytes(data)
    MANIFEST.write_text(manifest_text, encoding="utf-8")
    print(f"wrote {manifest['counts']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
