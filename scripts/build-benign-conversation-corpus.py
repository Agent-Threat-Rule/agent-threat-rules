#!/usr/bin/env python3
"""Build a benign conversational corpus slice from OpenAssistant/oasst1 (Apache-2.0).

Why this exists: ~50% of ATR rules target `llm_io`, and the benign corpus that
gates them contains skill manifests and paper abstracts — no conversation at all.
A prompt-matching rule cleared against a skill manifest has not been measured.

Contamination discipline (learned the hard way — the 65K benign gate turned out
to contain real jailbreaks): a sample is kept only if it clears BOTH the
dataset's own moderation signals AND an independent attack-marker screen here.
When in doubt the sample is dropped; corpus size is worth less than corpus trust.
"""
import json
import re
import sys
import time
import urllib.parse
import urllib.request

DATASET = "OpenAssistant/oasst1"
PAGE = 100
TARGET_PAGES = int(sys.argv[1]) if len(sys.argv) > 1 else 40

# Dataset-side moderation thresholds. detoxify scores are 0..1.
TOX_MAX = {
    "toxicity": 0.05,
    "severe_toxicity": 0.01,
    "obscene": 0.05,
    "identity_attack": 0.05,
    "insult": 0.05,
    "threat": 0.02,
    "sexual_explicit": 0.02,
}
# Human labels we refuse outright, at any confidence above this.
LABEL_MAX = {
    "spam": 0.1,
    "not_appropriate": 0.1,
    "hate_speech": 0.05,
    "sexual_content": 0.05,
    "violence": 0.1,
    "toxicity": 0.05,
}

# Independent screen. These are the shapes ATR rules look for. A benign corpus
# that contains them is not benign — it is an unlabelled attack corpus, and it
# would teach the gate to accept the exact rules that should fail.
ATTACK_MARKERS = [
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instruction|prompt|rule|direction)",
    r"disregard\s+(all\s+)?(previous|prior|above|your)\s+",
    r"forget\s+(all\s+)?(previous|prior|your)\s+(instruction|training|rule)",
    r"you\s+are\s+now\s+(a|an|in)\s+",
    r"\bDAN\b.{0,40}\b(mode|jailbreak)\b",
    r"developer\s+mode",
    r"jailbreak",
    r"prompt\s+injection",
    r"system\s+prompt",
    r"\bsudo\s+mode\b",
    r"pretend\s+(you|to\s+be)\s+.{0,30}(unrestricted|no\s+rules|without\s+restrictions)",
    r"</?(system|instruction)>",
    r"\[\[?\s*SYSTEM\s*[:\]]",
    r"reveal\s+your\s+(instruction|prompt|system)",
    r"base64|atob\(|eval\(|exec\(",
    r"/etc/passwd|\.ssh/id_rsa|\.aws/credentials|\.env\b",
    r"reverse\s+shell|/dev/tcp/|nc\s+-e\b",
    r"curl\s+[^\n|]{0,80}\|\s*(ba)?sh",
]
ATTACK_RE = [re.compile(p, re.I) for p in ATTACK_MARKERS]


def fetch(offset: int, attempts: int = 5):
    """Fetch one page, backing off on 429.

    The public datasets-server rate-limits well below the throughput a naive
    loop asks for. Without backoff a long run silently returns a smaller corpus
    than it reports having attempted, which is the failure mode that makes a
    benign gate look adequate when it is not.
    """
    url = (
        "https://datasets-server.huggingface.co/rows?"
        + urllib.parse.urlencode(
            {
                "dataset": DATASET,
                "config": "default",
                "split": "train",
                "offset": offset,
                "length": PAGE,
            }
        )
    )
    delay = 2.0
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=45) as r:
                return json.load(r).get("rows", [])
        except urllib.error.HTTPError as e:
            if e.code != 429 or attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay *= 2
    return []


def label_value(labels, name):
    """oasst1 labels arrive as {'name': [...], 'value': [...], 'count': [...]}."""
    if not isinstance(labels, dict):
        return None
    names = labels.get("name") or []
    values = labels.get("value") or []
    if name in names:
        i = names.index(name)
        if i < len(values):
            return values[i]
    return None


def keep(row):
    if row.get("lang") != "en":
        return False, "lang"
    if row.get("deleted"):
        return False, "deleted"
    if row.get("review_result") is not True:
        return False, "unreviewed"
    if row.get("synthetic"):
        return False, "synthetic"

    text = (row.get("text") or "").strip()
    if not (20 <= len(text) <= 2000):
        return False, "length"

    tox = row.get("detoxify") or {}
    for k, lim in TOX_MAX.items():
        v = tox.get(k)
        if isinstance(v, (int, float)) and v > lim:
            return False, f"detoxify:{k}"

    labels = row.get("labels")
    for k, lim in LABEL_MAX.items():
        v = label_value(labels, k)
        if isinstance(v, (int, float)) and v > lim:
            return False, f"label:{k}"

    for rx in ATTACK_RE:
        if rx.search(text):
            return False, "attack-marker"

    return True, "ok"


def main():
    kept, drops = [], {}
    seen = set()
    for p in range(TARGET_PAGES):
        try:
            rows = fetch(p * PAGE)
        except Exception as e:  # network hiccup: report, do not silently shrink
            print(f"  page {p} failed: {e}", file=sys.stderr)
            continue
        if not rows:
            break
        for r in rows:
            row = r.get("row", {})
            ok, why = keep(row)
            drops[why] = drops.get(why, 0) + 1
            if not ok:
                continue
            text = row["text"].strip()
            if text in seen:
                drops["dupe"] = drops.get("dupe", 0) + 1
                continue
            seen.add(text)
            kept.append(
                {
                    "text": text,
                    "source": "oasst1",
                    "category": f"conversation-{row.get('role', 'unknown')}",
                    "license": "apache-2.0",
                    "source_dataset": DATASET,
                }
            )
        time.sleep(0.6)

    out = sys.argv[2] if len(sys.argv) > 2 else "oasst-benign.jsonl"
    with open(out, "w") as f:
        for s in kept:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"kept {len(kept)}")
    for k, v in sorted(drops.items(), key=lambda x: -x[1]):
        print(f"  {k:<22}{v}")


if __name__ == "__main__":
    main()
