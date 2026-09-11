import json
ID = r"[A-Za-z_][A-Za-z0-9_]{1,40}"
# The content asks an ASSISTANT/AGENT to emit the call. Bare "call the X function with"
# is excluded on purpose: that is how API reference documentation reads.
AGENTASK = (r"(?:\bI\s+(?:would\s+like|want|need|am\s+asking)\s+(?:you|the\s+(?:assistant|agent|ai|model|bot))\s+to\s+(?:call|invoke|execute|run|trigger|use)\b"
            r"|\b(?:can|could|would|will)\s+you\s+(?:please\s+)?(?:construct|build|create|assemble|prepare|produce|form)\b[^.\n]{0,80}?\b(?:argument|parameter)s?\b[^.\n]{0,80}?\b(?:call|invoke|execute|trigger)\b"
            r"|\b(?:have|let|ask)\s+the\s+(?:assistant|agent|ai|model|bot)\s+(?:to\s+)?(?:call|invoke|execute|trigger)\b"
            r"|\bthe\s+(?:assistant|agent|ai|model|bot)\s+(?:should|must|needs\s+to|is\s+to)\s+(?:call|invoke|execute|trigger)\s+the\s+" + ID + r"\s+(?:function|tool|api|method|endpoint|command)\b)")
# One named-parameter binding, in either of the two orders the payloads use.
BIND = (r"(?:\bthe\s+" + ID + r"\s+(?:parameter|argument|field)\b"
        r"|\b(?:parameter|argument|field)\s+" + ID + r"\s+(?:set\s+to|=|as|to)\b"
        r"|\bpassing\s+[^.\n]{0,60}?\bto\s+the\s+" + ID + r"\s+(?:parameter|argument|field)\b)")
TWOBIND = BIND + r"[\s\S]{0,300}?" + BIND
out=[{"name":"agent-directed-call-request","value":AGENTASK},
     {"name":"two-named-parameter-bindings","value":TWOBIND}]
json.dump(out, open(".scratch-p2/r3-pat.json","w"), indent=1)
for o in out: open(".scratch-p2/r3-%s.txt"%o["name"],"w").write(o["value"])
print({o["name"]:len(o["value"]) for o in out}, "| apostrophe-free:", all("'" not in o["value"] for o in out))
