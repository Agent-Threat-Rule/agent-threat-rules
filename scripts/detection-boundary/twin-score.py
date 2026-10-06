#!/usr/bin/env python3
"""
Artifact-type vs judgment-type, decided WITHOUT looking at the false-positive
counts.

Signal: the rule author's own true_negative test cases.  Every ATR rule ships
true_positives (strings that must fire) and true_negatives (strings that must
not).  If an author had to write a true_negative that is lexically almost the
same sentence as the true_positive, then the thing separating attack from
legitimate use is NOT in the string -- it is context the layer cannot see.
That is a judgment-type rule, and it is a property of the rule file alone.

Score = max Jaccard token overlap over all (TP, TN) pairs.
"""
import json, re, sys, statistics

STOP = set("""a an the this that these those is are was were be been being am do does did
to of in on at by for with from as and or but if then than so such not no is it its it's
you your we our they their he she i me my will would can could should shall may might must
please make made get got use used using need needs when what which who whom how why where
here there all any some each other into out up down over under again more most very just
also only own same too s t don now d ll m o re ve y one two file files data
""".split())

TOKRE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-/]{1,}|[一-鿿]")

PAYLOAD_KEYS = ("input", "content", "user_input", "tool_args", "tool_response",
                "tool_description", "tool_name", "tool_call", "agent_output",
                "agent_message", "tool_input", "event")

def flatten(v):
    if v is None: return ""
    if isinstance(v, str): return v
    if isinstance(v, (int, float, bool)): return str(v)
    if isinstance(v, list): return " ".join(flatten(x) for x in v)
    if isinstance(v, dict): return " ".join(flatten(x) for x in v.values())
    return ""

def case_text(case):
    """Every payload-bearing field of a test case, minus its prose annotations."""
    if not isinstance(case, dict): return flatten(case)
    parts = [flatten(case[k]) for k in PAYLOAD_KEYS if k in case]
    if not parts:
        parts = [flatten(v) for k, v in case.items()
                 if k not in ("expected", "description", "notes", "bypass_technique")]
    return " ".join(p for p in parts if p)

def toks(s):
    return {t.lower().strip("./-") for t in TOKRE.findall(s or "")} - STOP - {""}

def jac(a, b):
    if not a or not b: return 0.0
    return len(a & b) / len(a | b)

HERE = __import__("os").path.dirname(__file__)
ROOT = __import__("os").path.abspath(__import__("os").path.join(HERE, "..", ".."))
rules = {r["id"]: r for r in json.load(open(__import__("os").path.join(HERE, "rules-dump.json")))}
meas = json.load(open(__import__("os").path.join(ROOT, "data/benign-fp-measurement.json")))["rules"]

out = {}
for rid in meas:
    tc = rules[rid].get("test_cases") or {}
    tps = [toks(case_text(x)) for x in (tc.get("true_positives") or [])]
    tns = [toks(case_text(x)) for x in (tc.get("true_negatives") or [])]
    tps = [t for t in tps if t]; tns = [t for t in tns if t]
    best, pair = 0.0, None
    for i, a in enumerate(tps):
        for j, b in enumerate(tns):
            v = jac(a, b)
            if v > best: best, pair = v, (i, j)
    out[rid] = {"twin": round(best, 4), "n_tp": len(tps), "n_tn": len(tns), "pair": pair}

json.dump(out, open(__import__("os").path.join(HERE, "twin.json"), "w"))

vals = sorted(v["twin"] for v in out.values())
print("rules scored:", len(out))
print("twin-score quantiles: min %.3f  p25 %.3f  median %.3f  p75 %.3f  p90 %.3f  max %.3f" % (
    vals[0], vals[len(vals)//4], statistics.median(vals), vals[3*len(vals)//4], vals[int(.9*len(vals))], vals[-1]))

# FP behaviour as a function of the score, in deciles -- no threshold chosen yet
import collections
dec = collections.defaultdict(list)
for rid, v in out.items():
    d = min(9, int(v["twin"] * 10))
    dec[d].append(meas[rid]["fp_count"])
print()
print(f"{'twin-score band':<16}{'rules':>6}{'dirty':>7}{'dirty%':>8}{'total FP':>10}{'median FP(dirty)':>18}")
for d in range(10):
    c = dec[d]
    if not c: continue
    dirty = [x for x in c if x > 0]
    print(f"{f'{d/10:.1f}-{(d+1)/10:.1f}':<16}{len(c):>6}{len(dirty):>7}{100*len(dirty)/len(c):>7.1f}%{sum(c):>10}"
          f"{(statistics.median(dirty) if dirty else 0):>18.0f}")
