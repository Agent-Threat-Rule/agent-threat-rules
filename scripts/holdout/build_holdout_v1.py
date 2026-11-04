#!/usr/bin/env python3
"""Build holdout v1: the corpus ATR rules are judged on, and never written from.

WHY THIS EXISTS

Every number the enforce lane has published so far was measured on a corpus
the rules had already seen. The benign gate a rule must pass before merge is
the same corpus its FP rate is then quoted on, and the attack benchmarks
(PINT, garak, hackaprompt, ...) are the corpora `fn-mine` writes new rules
from. A 0 FP on the gate corpus and a recall on a mined benchmark are both
in-sample numbers. The 2026-09-19 retraction of the per-lane FP numbers (the
benign gate turned out to contain real jailbreaks) is the same defect seen
from the other side.

Holdout v1 is built from public datasets that appear nowhere in this
repository, then screened against every text the repository already holds
(rule test cases, evasion tests, benign gate corpora, attack corpora, mined
proposals). A sample that the repository already contains, verbatim or
nearly, is dropped and counted. What remains is out of sample by
construction, and the manifest records how much had to be removed.

WHAT THIS SCRIPT DOES NOT DO

It does not screen benign samples with attack-marker regexes. That is the
filter scripts/build-benign-conversation-corpus.py applies, and it is
circular here: a benign corpus with every attack-looking sample removed
cannot produce the false positives a blocking lane has to be measured
against. Benign labels come from the source dataset or from how the text was
produced (a tool schema, a documented shell example). A benign sample a rule
fires on stays a false positive; if review shows it is really an attack, the
fix is a new holdout version, never an edit to this one -- see DATACARD.md.

INPUT

A directory of raw source files, fetched at the pinned revisions in
SOURCES below. The script never downloads; fetch_sources() prints the
commands. Parquet files need pyarrow (`pip install pyarrow numpy pyyaml`).

Usage:
  python3 scripts/holdout/build_holdout_v1.py --raw <dir> --print-fetch
  python3 scripts/holdout/build_holdout_v1.py --raw <dir> [--repo .]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
import unicodedata
from pathlib import Path

VERSION = "holdout-v1"
SEED = 20261104
SHINGLE = 5
CONTAINMENT_DROP = 0.5
MAX_CHARS = 50_000
MIN_CHARS = 8

# Pinned sources. Revision = Hugging Face dataset commit / git commit.
SOURCES = {
    "jailbreak-classification": {
        "dataset": "jackhhao/jailbreak-classification",
        "revision": "2f2ceeb39658696fd3f462403562b6eea5306287",
        "license": "Apache-2.0",
        "files": {
            "train": "https://huggingface.co/api/datasets/jackhhao/jailbreak-classification/parquet/default/train/0.parquet",
            "test": "https://huggingface.co/api/datasets/jackhhao/jailbreak-classification/parquet/default/test/0.parquet",
        },
    },
    "mosscap": {
        "dataset": "Lakera/mosscap_prompt_injection",
        "revision": "b7e495ff63373ff7f7dabc1e9390cf62b5838570",
        "license": "MIT",
        "files": {
            "test": "https://huggingface.co/api/datasets/Lakera/mosscap_prompt_injection/parquet/default/test/0.parquet",
        },
    },
    "spml": {
        "dataset": "reshabhs/SPML_Chatbot_Prompt_Injection",
        "revision": "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
        "license": "MIT",
        "files": {
            "train": "https://huggingface.co/api/datasets/reshabhs/SPML_Chatbot_Prompt_Injection/parquet/default/train/0.parquet",
        },
    },
    "glaive": {
        "dataset": "glaiveai/glaive-function-calling-v2",
        "revision": "e7f4b6456019f5d8bcb991ef0dd67d8ff23221ac",
        "license": "Apache-2.0",
        "files": {
            "train": "https://huggingface.co/api/datasets/glaiveai/glaive-function-calling-v2/parquet/default/train/0.parquet",
        },
    },
    "toolace": {
        "dataset": "Team-ACE/ToolACE",
        "revision": "6bda777c88d21e5a204703c1ee45597a8fa4f734",
        "license": "Apache-2.0",
        "files": {
            "train": "https://huggingface.co/api/datasets/Team-ACE/ToolACE/parquet/default/train/0.parquet",
        },
    },
    "hermes": {
        "dataset": "NousResearch/hermes-function-calling-v1",
        "revision": "dae3e1d28cfbcf4b915c04ea1e072030529b4bda",
        "license": "Apache-2.0",
        "files": {
            "singleturn": "https://huggingface.co/api/datasets/NousResearch/hermes-function-calling-v1/parquet/func_calling_singleturn/train/0.parquet",
        },
    },
    "nemotron": {
        "dataset": "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1",
        "revision": "d738d4f361cc38bb4d7a42b9066776dade5332f5",
        "license": "CC-BY-4.0",
        "files": {
            "train": "https://huggingface.co/api/datasets/nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1/parquet/default/train/0.parquet",
        },
    },
    "aib": {
        "dataset": "sincpp/AgentInjectionBench",
        "revision": "6041b9e757b834c2c60b3c046d18de2daf0f5e27",
        "license": "Apache-2.0",
        "files": {
            "jsonl": "https://huggingface.co/datasets/sincpp/AgentInjectionBench/resolve/6041b9e757b834c2c60b3c046d18de2daf0f5e27/data/agent_injection_bench.jsonl",
        },
    },
    "mcptp": {
        "dataset": "fevziegeyurtsevenler/mcp-tool-poisoning",
        "revision": "9b7a1088526d424c518d856ba5204f935a279727",
        "license": "Apache-2.0",
        "files": {
            "train": "https://huggingface.co/api/datasets/fevziegeyurtsevenler/mcp-tool-poisoning/parquet/default/train/0.parquet",
        },
    },
    "slabs": {
        "dataset": "S-Labs/prompt-injection-dataset",
        "revision": "002a9dd18514abd021869823d6b0429b38606d99",
        "license": "MIT",
        "files": {
            "train": "https://huggingface.co/api/datasets/S-Labs/prompt-injection-dataset/parquet/default/train/0.parquet",
            "validation": "https://huggingface.co/api/datasets/S-Labs/prompt-injection-dataset/parquet/default/validation/0.parquet",
            "test": "https://huggingface.co/api/datasets/S-Labs/prompt-injection-dataset/parquet/default/test/0.parquet",
        },
    },
    "rikka": {
        "dataset": "rikka-snow/prompt-injection-multilingual",
        "revision": "f1ad1f3dd44581f53a4c67e96a9dde2fb419ee5b",
        "license": "MIT",
        "files": {
            "train": "https://huggingface.co/api/datasets/rikka-snow/prompt-injection-multilingual/parquet/default/train/0.parquet",
            "test": "https://huggingface.co/api/datasets/rikka-snow/prompt-injection-multilingual/parquet/default/test/0.parquet",
        },
    },
    "tldr": {
        "dataset": "tldr-pages/tldr",
        "revision": "aad0d0980df9e398bc269e8c31ffaeb936731d48",
        "license": "CC-BY-4.0",
        "files": {
            "tarball": "https://codeload.github.com/tldr-pages/tldr/tar.gz/aad0d0980df9e398bc269e8c31ffaeb936731d48",
        },
    },
}

# How many samples each slice keeps after dedup and contamination screening.
# None = keep all.
SLICE_TARGETS = {
    "A1-jailbreak-prompts": None,
    "A2-secret-extraction-attempts": 3000,
    "A3-agent-indirect-injections": None,
    "A4-tool-output-injections": None,
    "A5-poisoned-tool-descriptions": None,
    "A6-labeled-prompt-injections": 3000,
    "B1-chat-prompts": None,
    "B2-system-prompts": 1500,
    "B3-tool-call-args": 1500,
    "B4-tool-descriptions": 2000,
    "B5-tool-responses": 2000,
    "B6-shell-commands": 3000,
    "B7-chat-user-turns": 1500,
    "B8-labeled-benign-prompts": 3000,
}

SURFACES = {
    "A1-jailbreak-prompts": "user_prompt",
    "A2-secret-extraction-attempts": "user_prompt",
    "A3-agent-indirect-injections": "tool_response",
    "A4-tool-output-injections": "tool_response",
    "A5-poisoned-tool-descriptions": "tool_description",
    "A6-labeled-prompt-injections": "user_prompt",
    "B1-chat-prompts": "user_prompt",
    "B2-system-prompts": "system_prompt",
    "B3-tool-call-args": "tool_args",
    "B4-tool-descriptions": "tool_description",
    "B5-tool-responses": "tool_response",
    "B6-shell-commands": "tool_args",
    "B7-chat-user-turns": "user_prompt",
    "B8-labeled-benign-prompts": "user_prompt",
}

REPO_TEXT_DIRS = ("data", "rules", "proposals", "tests", "examples", "conformance", "spec", "docs")
REPO_TEXT_EXT = {".json", ".jsonl", ".yaml", ".yml", ".md", ".txt", ".csv"}
REPO_SKIP_PARTS = {"node_modules", ".git", "holdout"}
REPO_SKIP_FILES = {"attack-embeddings.json"}
WORD = re.compile(r"\w+", re.UNICODE)


# ---------------------------------------------------------------------------
# text normalisation and shingles
# ---------------------------------------------------------------------------

def normalize(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).lower().split())


def shingles(text: str) -> list[int]:
    words = WORD.findall(normalize(text))
    if not words:
        return []
    if len(words) < SHINGLE:
        return [_h(" ".join(words))]
    return [_h(" ".join(words[i:i + SHINGLE])) for i in range(len(words) - SHINGLE + 1)]


def _h(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "little")


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# repository index: every text the rules could have been written from
# ---------------------------------------------------------------------------

def _strings(node, out: list[str]) -> None:
    if isinstance(node, str):
        if len(node) >= MIN_CHARS:
            out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _strings(v, out)
    elif isinstance(node, list):
        for v in node:
            _strings(v, out)


def repo_texts(repo: Path):
    import yaml  # noqa: PLC0415

    for top in REPO_TEXT_DIRS:
        base = repo / top
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix not in REPO_TEXT_EXT:
                continue
            if REPO_SKIP_PARTS & set(path.relative_to(repo).parts) or path.name in REPO_SKIP_FILES:
                continue
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            found: list[str] = [raw]
            try:
                if path.suffix == ".json":
                    _strings(json.loads(raw), found)
                elif path.suffix == ".jsonl":
                    for line in raw.splitlines():
                        if line.strip():
                            try:
                                _strings(json.loads(line), found)
                            except json.JSONDecodeError:
                                pass
                elif path.suffix in (".yaml", ".yml"):
                    for doc in yaml.safe_load_all(raw):
                        _strings(doc, found)
            except Exception:  # noqa: BLE001 - unparseable files still count as raw text
                pass
            yield path, found


def build_repo_index(repo: Path):
    import numpy as np  # noqa: PLC0415

    chunks = []
    exact: set[str] = set()
    files = 0
    for _path, texts in repo_texts(repo):
        files += 1
        for t in texts:
            sh = shingles(t)
            if sh:
                chunks.append(np.fromiter(sh, dtype=np.uint64, count=len(sh)))
            if len(t) <= 2000:
                exact.add(normalize(t))
    index = np.unique(np.concatenate(chunks)) if chunks else np.zeros(0, dtype=np.uint64)
    return index, exact, files


def containment(text: str, index) -> float:
    import numpy as np  # noqa: PLC0415

    sh = shingles(text)
    if not sh or index.size == 0:
        return 0.0
    arr = np.fromiter(sh, dtype=np.uint64, count=len(sh))
    pos = np.searchsorted(index, arr)
    pos[pos >= index.size] = index.size - 1
    return float(np.mean(index[pos] == arr))


# ---------------------------------------------------------------------------
# source readers -> (slice, text, source_row)
# ---------------------------------------------------------------------------

def _parquet(path: Path) -> list[dict]:
    import pyarrow.parquet as pq  # noqa: PLC0415

    return pq.read_table(path).to_pylist()


def read_jailbreak_classification(raw: Path):
    for split in ("train", "test"):
        for i, r in enumerate(_parquet(raw / "jackhhao" / f"{split}.parquet")):
            label = r.get("type")
            if label == "jailbreak":
                yield "A1-jailbreak-prompts", r["prompt"], f"{split}:{i}"
            elif label == "benign":
                yield "B1-chat-prompts", r["prompt"], f"{split}:{i}"


def read_mosscap(raw: Path):
    for i, r in enumerate(_parquet(raw / "mosscap" / "test.parquet")):
        yield "A2-secret-extraction-attempts", r["prompt"], f"test:{i}"


def read_spml(raw: Path):
    seen_sys: set[str] = set()
    for i, r in enumerate(_parquet(raw / "spml" / "train.parquet")):
        # Gandalf-sourced rows are excluded: Gandalf data is referenced by
        # existing rules. Only rows the dataset labels non-injection are used,
        # because SPML's injection label marks system-prompt policy violations
        # ("convince me to take high-risk investments"), not the attack class
        # ATR rules describe. Its injection rows are neither attack nor benign
        # for this purpose, so they are left out entirely.
        if r.get("Source") == "Gandalf":
            continue
        if r.get("Prompt injection") == 0 and r.get("Degree") == 0:
            yield "B1-chat-prompts", r["User Prompt"], f"train:{i}:user"
            sp = r.get("System Prompt") or ""
            if sp and sp not in seen_sys:
                seen_sys.add(sp)
                yield "B2-system-prompts", sp, f"train:{i}:system"


GLAIVE_TURN = re.compile(r"\s*(USER|ASSISTANT|FUNCTION RESPONSE):\s*")
GLAIVE_EOT = "<|endoftext|>"


def glaive_turns(chat: str) -> list[tuple[str, str]]:
    """Split a glaive chat into (role, text) turns.

    `<|endoftext|>` is glaive's turn terminator, part of the file format and
    never of what a user or tool said, so it is removed. Leaving it in made
    every user turn carry the next assistant turn and a chat-template token,
    which chat-template-injection rules then (correctly) fired on.
    """
    parts = GLAIVE_TURN.split(chat)
    turns = []
    for k in range(1, len(parts) - 1, 2):
        text = parts[k + 1].replace(GLAIVE_EOT, "").strip()
        if text:
            turns.append((parts[k], text))
    return turns


def read_glaive(raw: Path):
    for i, r in enumerate(_parquet(raw / "glaive" / "train.parquet")):
        for j, (role, text) in enumerate(glaive_turns(r.get("chat") or "")):
            if role == "USER":
                yield "B7-chat-user-turns", text, f"train:{i}:turn{j}"
            elif role == "FUNCTION RESPONSE":
                yield "B5-tool-responses", text, f"train:{i}:turn{j}"
            elif role == "ASSISTANT" and text.startswith("<functioncall>"):
                yield "B3-tool-call-args", text[len("<functioncall>"):].strip(), f"train:{i}:turn{j}"


def read_toolace(raw: Path):
    for i, r in enumerate(_parquet(raw / "toolace" / "train.parquet")):
        for j, turn in enumerate(r.get("conversations") or []):
            if turn.get("from") == "tool":
                yield "B5-tool-responses", turn.get("value") or "", f"train:{i}:tool{j}"


def read_hermes(raw: Path):
    for i, r in enumerate(_parquet(raw / "hermes" / "singleturn.parquet")):
        try:
            tools = json.loads(r.get("tools") or "[]")
        except json.JSONDecodeError:
            continue
        for j, tool in enumerate(tools):
            fn = tool.get("function", tool) if isinstance(tool, dict) else None
            if isinstance(fn, dict) and fn.get("description"):
                yield "B4-tool-descriptions", json.dumps(fn, ensure_ascii=False), f"train:{i}:tool{j}"


def _injected_field(env: str, payload: str) -> str | None:
    """The tool-record field the payload was planted in, as the agent reads it."""
    try:
        doc = json.loads(env)
    except (json.JSONDecodeError, TypeError):
        return None
    found: list[str] = []
    _strings(doc, found)
    hits = [f for f in found if payload.strip()[:60] in f]
    return min(hits, key=len) if hits else None


# Nemotron's 1,272 rows use 14 injection templates, one of them 970 times. A
# rule that matches that template would score 970 detections for one idea, so
# each template contributes at most this many rows (the first, by row order).
NEMOTRON_PER_TEMPLATE = 20


def read_nemotron(raw: Path):
    per_template: dict[str, int] = {}
    for i, r in enumerate(_parquet(raw / "nemotron" / "train.parquet")):
        inj = r.get("injection") or {}
        payload = inj.get("injection_text") or ""
        template = payload.replace(inj.get("goal") or "", "<GOAL>").strip()[:300]
        if per_template.get(template, 0) >= NEMOTRON_PER_TEMPLATE:
            continue
        per_template[template] = per_template.get(template, 0) + 1
        field = _injected_field(r.get("environment") or "", payload) if payload else None
        yield "A3-agent-indirect-injections", field or payload, f"train:{i}"


def read_aib(raw: Path):
    path = raw / "aib" / "agent_injection_bench.jsonl"
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        r = json.loads(line)
        if r.get("ground_truth") != "unsafe":
            continue
        for j, turn in enumerate(r.get("conversation") or []):
            if turn.get("role") == "tool_result":
                yield "A4-tool-output-injections", turn.get("content") or "", f"{r.get('id', i)}:turn{j}"


def read_mcptp(raw: Path):
    for i, r in enumerate(_parquet(raw / "mcptp" / "train.parquet")):
        yield "A5-poisoned-tool-descriptions", r.get("poisoned_description") or "", f"train:{i}:poisoned"
        yield "B4-tool-descriptions", r.get("benign_description") or "", f"train:{i}:benign"


def _labeled(raw: Path, key: str, splits: tuple[str, ...]):
    for split in splits:
        for i, r in enumerate(_parquet(raw / key / f"{split}.parquet")):
            label = r.get("label")
            if label == 1:
                yield "A6-labeled-prompt-injections", r.get("text") or "", f"{split}:{i}"
            elif label == 0:
                yield "B8-labeled-benign-prompts", r.get("text") or "", f"{split}:{i}"


def read_slabs(raw: Path):
    yield from _labeled(raw, "slabs", ("train", "validation", "test"))


def read_rikka(raw: Path):
    yield from _labeled(raw, "rikka", ("train", "test"))


TLDR_CMD = re.compile(r"^`(.+)`\s*$")


def read_tldr(raw: Path):
    roots = sorted((raw / "tldr" / "x").glob("*/pages"))
    for root in roots:
        for platform in ("common", "linux", "osx"):
            for page in sorted((root / platform).glob("*.md")):
                for n, line in enumerate(page.read_text(encoding="utf-8").splitlines()):
                    m = TLDR_CMD.match(line.strip())
                    if m:
                        # {{placeholder}} is tldr's own notation; strip the braces so
                        # the command reads as it would be typed.
                        cmd = m.group(1).replace("{{", "").replace("}}", "")
                        yield "B6-shell-commands", cmd, f"{platform}/{page.name}:{n + 1}"


READERS = {
    "jailbreak-classification": read_jailbreak_classification,
    "mosscap": read_mosscap,
    "spml": read_spml,
    "glaive": read_glaive,
    "toolace": read_toolace,
    "hermes": read_hermes,
    "nemotron": read_nemotron,
    "aib": read_aib,
    "mcptp": read_mcptp,
    "slabs": read_slabs,
    "rikka": read_rikka,
    "tldr": read_tldr,
}


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def label_of(slice_name: str) -> str:
    return "attack" if slice_name.startswith("A") else "benign"


def cached_repo_index(repo: Path, cache: Path | None):
    """build_repo_index, optionally memoised on disk for repeated local builds."""
    import numpy as np  # noqa: PLC0415

    if cache is not None and (cache / "shingles.npy").exists():
        meta = json.loads((cache / "meta.json").read_text(encoding="utf-8"))
        return np.load(cache / "shingles.npy"), set(meta["exact"]), meta["files"]
    index, exact, files = build_repo_index(repo)
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        np.save(cache / "shingles.npy", index)
        (cache / "meta.json").write_text(json.dumps({"exact": sorted(exact), "files": files}), encoding="utf-8")
    return index, exact, files


def build(raw: Path, repo: Path, out: Path, cache: Path | None = None) -> dict:
    index, exact, files = cached_repo_index(repo, cache)
    print(f"repo index: {files} files, {index.size} distinct shingles, {len(exact)} short exact texts", file=sys.stderr)

    rng = random.Random(SEED)
    stats: dict[str, dict[str, int]] = {}
    pools: dict[str, list[dict]] = {}
    seen: dict[str, str] = {}
    conflicts: set[str] = set()

    for key, reader in READERS.items():
        for slice_name, text, row in reader(raw):
            st = stats.setdefault(slice_name, {"read": 0, "too_short_or_long": 0, "duplicate": 0,
                                               "label_conflict": 0, "in_repo_exact": 0, "in_repo_near": 0, "kept_pool": 0})
            st["read"] += 1
            text = (text or "").strip()
            if not (MIN_CHARS <= len(text) <= MAX_CHARS):
                st["too_short_or_long"] += 1
                continue
            norm = normalize(text)
            lab = label_of(slice_name)
            if norm in seen:
                if seen[norm] != lab:
                    conflicts.add(norm)
                st["duplicate"] += 1
                continue
            seen[norm] = lab
            if norm in exact:
                st["in_repo_exact"] += 1
                continue
            if containment(text, index) >= CONTAINMENT_DROP:
                st["in_repo_near"] += 1
                continue
            src = SOURCES[key]
            pools.setdefault(slice_name, []).append({
                "slice": slice_name,
                "label": lab,
                "surface": SURFACES[slice_name],
                "text": text,
                "source": {"dataset": src["dataset"], "revision": src["revision"], "row": row},
                "license": src["license"],
                "_norm": norm,
            })
            st["kept_pool"] += 1

    records: dict[str, list[dict]] = {"attack": [], "benign": []}
    for slice_name in sorted(pools):
        pool = [p for p in pools[slice_name] if p["_norm"] not in conflicts]
        stats[slice_name]["label_conflict"] = len(pools[slice_name]) - len(pool)
        target = SLICE_TARGETS.get(slice_name)
        chosen = pool if target is None or len(pool) <= target else rng.sample(pool, target)
        chosen.sort(key=lambda p: p["source"]["row"])
        prefix = slice_name.split("-")[0].lower()
        for n, p in enumerate(chosen):
            p.pop("_norm")
            p["id"] = f"hv1-{prefix}-{n:05d}"
            records[p["label"]].append({k: p[k] for k in ("id", "label", "slice", "surface", "text", "source", "license")})
        stats[slice_name]["kept"] = len(chosen)

    out.mkdir(parents=True, exist_ok=True)
    digests = {}
    for lab, rows in records.items():
        path = out / f"{lab}.jsonl"
        body = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows)
        path.write_text(body, encoding="utf-8")
        digests[path.name] = {"sha256": sha256_text(body), "samples": len(rows)}

    manifest = {
        "version": VERSION,
        "seed": SEED,
        "files": digests,
        "slices": {k: {"label": label_of(k), "surface": SURFACES[k], **v} for k, v in sorted(stats.items())},
        "screen": {
            "shingle_words": SHINGLE,
            "containment_drop": CONTAINMENT_DROP,
            "repo_files_indexed": files,
            "repo_distinct_shingles": int(index.size),
            "repo_dirs": list(REPO_TEXT_DIRS),
        },
        "sources": {k: {kk: vv for kk, vv in v.items() if kk != "files"} for k, v in SOURCES.items()},
        "builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def print_fetch(raw: Path) -> None:
    dirs = {"jailbreak-classification": "jackhhao"}
    for key, src in SOURCES.items():
        d = raw / dirs.get(key, key)
        for name, url in src["files"].items():
            ext = {"tarball": "tar.gz", "jsonl": "jsonl"}.get(name, "parquet")
            stem = {"tldr": "tldr", "aib": "agent_injection_bench"}.get(key, name)
            target = d / f"{stem}.{ext}"
            print(f"mkdir -p '{d}' && curl -sL -o '{target}' '{url}'")
    print(f"mkdir -p '{raw}/tldr/x' && tar -xzf '{raw}/tldr/tldr.tar.gz' -C '{raw}/tldr/x' "
          "--include='*/pages/common/*' --include='*/pages/linux/*' --include='*/pages/osx/*' --include='*/LICENSE.md'")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--raw", required=True, type=Path)
    ap.add_argument("--repo", default=Path(__file__).resolve().parents[2], type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--print-fetch", action="store_true")
    ap.add_argument("--index-cache", type=Path, help="reuse the repository index between local builds")
    args = ap.parse_args()
    if args.print_fetch:
        print_fetch(args.raw)
        return 0
    out = args.out or args.repo / "data" / "holdout" / "v1"
    manifest = build(args.raw, args.repo, out, args.index_cache)
    print(json.dumps({k: v.get("kept") for k, v in manifest["slices"].items()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
