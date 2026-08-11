#!/usr/bin/env python3
"""
Rebuild the exact 5,352-sample benign corpus that data/benign-fp-measurement.json
was measured against: the three directories named in MEASUREMENT_CORPORA
(src/quality/action-eligibility.ts), walked recursively, .jsonl `text` fields plus
whole .md files -- the same walk as loadCorpusTexts() in scripts/gate-promotion-fp.ts.
"""
import os, json, sys
WT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORPORA=["data/skill-benchmark/benign","data/benign-corpus-extended","data/benign-code"]
texts=[]; prov=[]
for c in CORPORA:
    root=os.path.join(WT,c)
    files=[]
    for dp,_,fns in os.walk(root):
        for fn in sorted(fns):
            if fn.endswith(".jsonl") or fn.endswith(".md"):
                files.append(os.path.join(dp,fn))
    for f in sorted(files):
        raw=open(f,encoding="utf-8",errors="replace").read()
        if f.endswith(".md"):
            texts.append(raw); prov.append(os.path.relpath(f,WT)); continue
        for line in raw.split("\n"):
            t=line.strip()
            if not t: continue
            try: o=json.loads(t)
            except Exception: continue
            if isinstance(o.get("text"),str) and o["text"]:
                texts.append(o["text"]); prov.append(os.path.relpath(f,WT))
print("samples:",len(texts))
import collections
print(collections.Counter(p.split('/')[1] if p.startswith('data/') else p for p in prov))
print(collections.Counter(prov).most_common(12))
json.dump({"texts":texts,"prov":prov}, open(os.path.join(os.path.dirname(__file__), "corpus.json"), "w"))
