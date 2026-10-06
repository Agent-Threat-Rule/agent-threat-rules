#!/usr/bin/env python3
"""
Artifact-type vs judgment-type, decided from the RULE FILE ONLY.

Criterion (stated so it can be attacked):

  A rule is ARTIFACT-TYPE if there exists at least one required anchor set in
  which EVERY alternative is a non-word -- a token absent from the system
  English dictionary and not a plain technical noun.  Such a rule cannot fire
  unless the text carries a machine artifact: rot13, a base64 envelope, an
  .onion host, an AKIA key prefix, a zero-width run.

  A rule is JUDGMENT-TYPE if every required anchor set contains at least one
  ordinary English word.  Such a rule can fire on a sentence made entirely of
  words a legitimate user might write, so whatever separates attack from
  legitimate use is not in the vocabulary.

No false-positive count is consulted.  /usr/share/dict/words is an external
artifact, not something this project tuned.
"""
import json, re, collections, statistics
import visibility as V

WORDS = {w.strip().lower() for w in open("/usr/share/dict/words", encoding="utf-8", errors="replace")}
# plain technical nouns that any English dictionary predates; treating them as
# artifacts would let ordinary prose count as a machine signature.
TECH = set("""http https url uri api json yaml html xml css sql http url ssh sudo curl wget
bash shell python node npm pip git repo repository config configs env environment
token tokens auth authorization credential credentials password passwords secret secrets
apikey api_key access_key endpoint endpoints server servers client clients database
filesystem localhost webhook webhooks upload uploads download downloads download
username userid hostname filename filepath pathname runtime plugin plugins prompt prompts
system_prompt agent agents llm chatbot dataset datasets metadata namespace
javascript typescript golang docker kubernetes jenkins gitlab github bitbucket
readme changelog dotenv base64 encode encoded encoding decode decoded decoding
exfiltrate exfiltration bypass jailbreak injection unauthorized untrusted
frontend backend middleware webapp devops""".split())

def is_word(tok):
    t = tok.lower().strip("./-_ ")
    if not t: return True
    if t in TECH: return True
    if t in WORDS: return True
    # hyphen / underscore / dot compounds made of dictionary words
    parts = [p for p in re.split(r"[^a-z0-9]+", t) if p]
    if parts and all(p in WORDS or p in TECH or p.isdigit() for p in parts): return True
    return False

HERE = __import__("os").path.dirname(__file__)
ROOT = __import__("os").path.abspath(__import__("os").path.join(HERE, "..", ".."))
rules = {r["id"]: r for r in json.load(open(__import__("os").path.join(HERE, "rules-dump.json")))}
meas = json.load(open(__import__("os").path.join(ROOT, "data/benign-fp-measurement.json")))["rules"]

fam = {}
for rid in meas:
    r = rules[rid]
    cs = V.conds(r["detection"])
    top = r["detection"].get("condition", "any")
    per = []
    for c in cs:
        val = c.get("value")
        if not isinstance(val, str): per.append(None); continue
        sets = V.required_anchor_sets(val)
        if not sets: per.append(None); continue
        # artifact if ANY required set is all-non-word
        art = [s for s in sets if all(not is_word(t) for t in s)]
        per.append({"artifact": bool(art), "witness": sorted(art[0])[:3] if art else [],
                    "n_sets": len(sets)})
    known = [p for p in per if p]
    if not known:
        cls, wit = "unclassifiable", []
    elif top == "all":
        # `all`: one artifact-gated condition is enough to gate the whole rule
        art = [p for p in known if p["artifact"]]
        cls, wit = ("artifact", art[0]["witness"]) if art else ("judgment", [])
    else:
        # `any`: the rule is only artifact-gated if EVERY arm is, including
        # arms the parser could not pin down (those could match plain prose)
        if len(known) < len(per): cls, wit = "judgment", []
        else:
            art = all(p["artifact"] for p in known)
            cls = "artifact" if art else "judgment"
            wit = known[0]["witness"] if art else []
    fam[rid] = {"family": cls, "witness": wit}

json.dump(fam, open(__import__("os").path.join(HERE, "family.json"), "w"))

tab = collections.Counter(); fp = collections.defaultdict(list)
for rid, f in fam.items():
    tab[f["family"]] += 1
    fp[f["family"]].append(meas[rid]["fp_count"])
print(f"{'family':<16}{'rules':>7}{'dirty':>7}{'dirty%':>8}{'total FP':>10}{'FP/rule':>9}{'max FP':>8}")
for k in ("artifact", "judgment", "unclassifiable"):
    c = fp[k]
    if not c: continue
    d = [x for x in c if x > 0]
    print(f"{k:<16}{len(c):>7}{len(d):>7}{100*len(d)/len(c):>7.1f}%{sum(c):>10}{sum(c)/len(c):>9.1f}{max(c):>8}")
