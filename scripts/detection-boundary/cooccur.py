#!/usr/bin/env python3
"""
A-match: how many benign samples contain, simultaneously, at least one member of
EVERY required anchor set of a rule.

Every genuine regex match is an A-match, so A upper-bounds the rule's true match
count on this corpus.  A == 0 PROVES the corpus can never fire the rule -- its
zero FP is vacuous.  Conditions the parser cannot pin down are treated as
matching everything, so A is never under-stated.
"""
import json, functools
import visibility as V

TEXTS = V.TEXTS
N = len(TEXTS)
ALL = frozenset(range(N))
BIG = "\x00".join(TEXTS)

@functools.lru_cache(maxsize=None)
def hits(tok):
    if tok not in BIG: return frozenset()
    return frozenset(i for i, t in enumerate(TEXTS) if tok in t)

def cond_hits(pattern):
    sets = V.required_anchor_sets(pattern)
    if not sets: return ALL, 0
    acc = ALL
    for s in sets:
        u = set()
        for tok in s: u |= hits(tok)
        acc = acc & u
        if not acc: break
    return acc, len(sets)

HERE = __import__("os").path.dirname(__file__)
rules = json.load(open(__import__("os").path.join(HERE, "rules-dump.json")))
out = {}
for r in rules:
    cs = V.conds(r["detection"])
    top = r["detection"].get("condition", "any") if isinstance(r["detection"], dict) else "any"
    per = [cond_hits(c["value"]) if isinstance(c.get("value"), str) else (ALL, 0) for c in cs]
    if not per:
        agg, pinned = ALL, 0
    elif top == "all":
        agg = ALL
        for b, _ in per: agg = agg & b
        pinned = sum(1 for _, k in per if k)
    else:
        agg = set()
        for b, _ in per: agg |= b
        pinned = sum(1 for _, k in per if k)
    out[r["id"]] = {"A": len(agg), "pinned_conds": pinned, "n_cond": len(cs), "top": top,
                    "sample_idx": sorted(agg)[:5]}
json.dump(out, open(__import__("os").path.join(HERE, "cooccur.json"), "w"))
print("done", len(out))
