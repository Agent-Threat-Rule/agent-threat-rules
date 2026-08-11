#!/usr/bin/env python3
"""
Corpus-visibility analyser.

For every rule condition regex, work out the LITERAL strings a match is
REQUIRED to contain, then ask the benign corpus whether it contains them.

Conservative by construction: whenever the parser cannot prove a literal is
required, it reports "uninformative" rather than "invisible".  So a rule
reported INVISIBLE is proven invisible; a rule reported VISIBLE is merely
not-proven-invisible.
"""
import json, re, sys, functools

MIN_LIT = 4

# ---------------------------------------------------------------- regex parse
class Uninformative(Exception):
    pass

def _split_top_alternation(p):
    parts, depth, cls, buf, i = [], 0, False, [], 0
    while i < len(p):
        c = p[i]
        if c == "\\":
            buf.append(p[i:i+2]); i += 2; continue
        if cls:
            buf.append(c)
            if c == "]": cls = False
            i += 1; continue
        if c == "[": cls = True; buf.append(c); i += 1; continue
        if c == "(": depth += 1
        elif c == ")": depth -= 1
        if c == "|" and depth == 0:
            parts.append("".join(buf)); buf = []; i += 1; continue
        buf.append(c); i += 1
    parts.append("".join(buf))
    return parts

ESCAPE_LITERAL = set(".-/_+*?()[]{}^$|\\@#:;,'\"!=~& ")

def _units(p):
    """Yield (kind, payload, quantifier) for depth-0 units of pattern p."""
    out, i, n = [], 0, len(p)
    lit = []
    def flush():
        if lit:
            out.append(("lit", "".join(lit), ""))
            lit.clear()
    while i < n:
        c = p[i]
        if c == "\\":
            nxt = p[i+1] if i+1 < n else ""
            m = re.match(r"\\(?:u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{2,3})", p[i:])
            if m:
                try: ch = eval('"' + m.group(0) + '"')
                except Exception: ch = "\uFFFF"
                lit.append(ch); i += len(m.group(0)); continue
            if nxt in ESCAPE_LITERAL:
                lit.append(nxt); i += 2; continue
            flush(); out.append(("wild", "\\"+nxt, "")); i += 2; continue
        if c == "[":
            flush()
            j, cls_depth = i+1, 0
            while j < n:
                if p[j] == "\\": j += 2; continue
                if p[j] == "]": break
                j += 1
            out.append(("wild", p[i:j+1], "")); i = j+1; continue
        if c == "(":
            flush()
            depth, j = 1, i+1
            while j < n and depth:
                if p[j] == "\\": j += 2; continue
                if p[j] == "[":
                    while j < n and p[j] != "]":
                        j += 2 if p[j] == "\\" else 1
                elif p[j] == "(": depth += 1
                elif p[j] == ")": depth -= 1
                j += 1
            inner = p[i+1:j-1]
            m = re.match(r"^\?(?:i|m|s|x|is|im|si)*\)?", inner)
            if inner.startswith("?:"): inner = inner[2:]
            elif re.match(r"^\?P?<[A-Za-z_][A-Za-z0-9_]*>", inner):
                inner = re.sub(r"^\?P?<[A-Za-z_][A-Za-z0-9_]*>", "", inner)
            elif inner.startswith("?=") or inner.startswith("?!") or inner.startswith("?<=") or inner.startswith("?<!"):
                out.append(("wild", "(look)", "")); i = j; continue
            elif re.fullmatch(r"\?[ims]+", inner):
                i = j; continue          # inline flag group
            out.append(("grp", inner, "")); i = j; continue
        if c in "^$":
            flush(); out.append(("anchor", c, "")); i += 1; continue
        if c in ".":
            flush(); out.append(("wild", ".", "")); i += 1; continue
        if c in "*+?":
            # quantifier applies to previous unit (or last literal char)
            if lit:
                ch = lit.pop()
                flush()
                out.append(("lit", ch, c))
            elif out:
                k, pay, _ = out[-1]; out[-1] = (k, pay, c)
            i += 1
            if i < n and p[i] == "?": i += 1
            continue
        if c == "{":
            j = p.find("}", i)
            q = p[i:j+1] if j != -1 else "{"
            if lit:
                ch = lit.pop(); flush(); out.append(("lit", ch, q))
            elif out:
                k, pay, _ = out[-1]; out[-1] = (k, pay, q)
            i = (j+1) if j != -1 else i+1
            continue
        lit.append(c); i += 1
    flush()
    return out

def _optional(q):
    if q in ("?", "*"): return True
    m = re.fullmatch(r"\{(\d+)(,\d*)?\}", q or "")
    if m and m.group(1) == "0": return True
    return False

def required_anchor_sets(pattern):
    """
    Return a list of 'anchor sets'.  A match must contain, for EVERY set in the
    list, at least ONE of the strings in that set.  Sets that cannot be pinned
    down are simply omitted (conservative).
    """
    pattern = re.sub(r"\(\?[ims]+\)", "", pattern)
    branches = _split_top_alternation(pattern)
    if len(branches) > 1:
        # top-level alternation: union of each branch's *first* reliable set
        per = []
        for b in branches:
            s = required_anchor_sets(b)
            if not s: return []            # one branch unpinnable -> unpinnable
            per.append(set().union(*s))
        return [set().union(*per)]
    sets = []
    for kind, payload, q in _units(pattern):
        if _optional(q): continue
        if kind == "lit":
            t = payload.strip()
            if len(t) >= MIN_LIT: sets.append({t.lower()})
        elif kind == "grp":
            sub = _split_top_alternation(payload)
            acc, ok = set(), True
            for b in sub:
                s = required_anchor_sets(b)
                if not s: ok = False; break
                acc |= set().union(*s)
            if ok and acc: sets.append(acc)
    return sets

# ---------------------------------------------------------------- corpus side
HERE = __import__("os").path.dirname(__file__)
d = json.load(open(__import__("os").path.join(HERE, "corpus.json")))
TEXTS = [t.lower() for t in d["texts"]]
N = len(TEXTS)

@functools.lru_cache(maxsize=None)
def doc_freq(tok):
    c = 0
    for t in TEXTS:
        if tok in t: c += 1
    return c

def visibility(pattern):
    sets = required_anchor_sets(pattern)
    if not sets: return None, []
    vals = []
    for s in sets:
        vals.append((max(doc_freq(tok) for tok in s), sorted(s, key=lambda x: -doc_freq(x))[0]))
    v = min(vals, key=lambda x: x[0])
    return v[0], [x[1] for x in vals]


def conds(det, out=None):
    if out is None: out = []
    if isinstance(det, dict):
        if "operator" in det and "value" in det: out.append(det)
        for k in ("conditions", "any", "all", "trace", "sequence"):
            v = det.get(k)
            if isinstance(v, list):
                for x in v: conds(x, out)
            elif isinstance(v, dict): conds(v, out)
    elif isinstance(det, list):
        for x in det: conds(x, out)
    return out

# ---------------------------------------------------------------- rules side
if __name__ == '__main__':

    rules = json.load(open(__import__("os").path.join(HERE, "rules-dump.json")))
    meas = json.load(open(sys.argv[1]))["rules"] if len(sys.argv) > 1 else {}

    def conds(det, out=None):
        if out is None: out = []
        if isinstance(det, dict):
            if "operator" in det and "value" in det: out.append(det)
            for k in ("conditions", "any", "all", "trace", "sequence"):
                v = det.get(k)
                if isinstance(v, list):
                    for x in v: conds(x, out)
                elif isinstance(v, dict): conds(v, out)
        elif isinstance(det, list):
            for x in det: conds(x, out)
        return out

    res = {}
    for r in rules:
        cs = conds(r["detection"])
        top = r["detection"].get("condition", "any") if isinstance(r["detection"], dict) else "any"
        per = []
        for c in cs:
            val = c.get("value")
            if not isinstance(val, str): per.append((None, [], c.get("field"))); continue
            v, toks = visibility(val)
            per.append((v, toks, c.get("field")))
        known = [p for p in per if p[0] is not None]
        if not known:
            rule_v = None
        elif top == "all":
            rule_v = min(p[0] for p in known) if len(known) == len(per) else min(p[0] for p in known)
        elif len(known) < len(per):
            rule_v = None            # `any`: one unpinnable arm -> blindness unprovable
        else:
            rule_v = max(p[0] for p in known)
        res[r["id"]] = {
            "v": rule_v, "n_cond": len(cs), "n_pinned": len(known),
            "top": top,
            "per": [{"v": p[0], "tok": p[1][:4], "field": p[2]} for p in per],
        }

    json.dump(res, open(__import__("os").path.join(HERE, "visibility.json"), "w"))
    print("rules analysed:", len(res))
    pin = [k for k, v in res.items() if v["v"] is not None]
    print("pinned (>=1 condition with a provable required literal):", len(pin))
    print("unpinnable:", len(res) - len(pin))
