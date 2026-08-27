import json
HALT = r"\b(?:halt|stop|cease|abort|abandon|discontinue)\b"
YOU  = r"(?:you\s+are|you[\x27’]re|youre|you\s+were)"
YOUDO = (r"(?:\b(?:what|whatever|everything|anything)\s+(?:it\s+is\s+)?(?:" + YOU + r"|you)\s*(?:currently\s+)?"
         r"(?:doing|working\s+on|processing|executing)"
         r"|\byour\s+(?:current|ongoing|present)\s+(?:task|action|work|operation|process|job|request))")
URG = (r"(?:right\s+now|immediately|at\s+once|this\s+instant|without\s+delay|straight\s+away"
       r"|extremely\s+important|very\s+important|really\s+important|matters?\s+enormously"
       r"|this\s+is\s+urgent|urgently)")
Q = r"[\x22\x27\x60‘’“”]"
NQ = r"[^\x22\x27\x60‘’“”\n]"
SUB = r"(?:instead|only|and\s+nothing\s+else|nothing\s+else|and\s+stop\s+doing\s+anything\s+else|and\s+do\s+nothing\s+else)"
CANNED  = r"\b(?:answer|reply|respond|output|return|say)\b[^.!?\n]{0,35}?\bwith\s+" + Q + NQ + r"{1,45}" + Q + r"[^.!?\n]{0,30}?\b" + SUB + r"\b"
CANNED2 = r"\b(?:just|simply|only)\s+(?:answer|reply|respond|output|return|say)\s+" + Q + NQ + r"{1,45}" + Q + r"[^.!?\n]{0,45}?\b(?:" + SUB + r"|to\s+the\s+user)\b"
PROX = (r"(?:" + HALT + r"[^.!?\n]{0,40}?" + URG + r"[^.!?\n]{0,40}?" + YOUDO +
        r"|"   + HALT + r"[^.!?\n]{0,70}?" + YOUDO + r"[^.!?\n]{0,60}?" + URG +
        r"|"   + URG  + r"[^.!?\n]{0,40}?" + HALT + r"[^.!?\n]{0,40}?" + YOUDO + r")" +
        r"[\s\S]{0,220}?(?:" + CANNED + r"|" + CANNED2 + r")")
AGENT = (r"(?:\bto\s+you,?\s+(?:the\s+)?(?:assistant|agent|ai\b|model|llm|chatbot|copilot)"
         r"|\b(?:" + YOU + r")\s+(?:an?\s+|the\s+)?(?:ai\b|a\.i\.|assistant|agent|language\s+model|chatbot|llm)"
         r"|\b(?:dear|hello|hey)\s+(?:ai\b|assistant|agent|model)"
         r"|\b(?:assistant|ai\s+agent|ai\s+assistant)\s*[:,]\s"
         r"|\bfor\s+the\s+(?:ai\s+)?(?:assistant|agent)\s+reading\s+this"
         r"|\bnote\s+(?:to|for)\s+(?:the\s+)?(?:ai\b|assistant|agent|model))")
json.dump([{"name":"prox","value":PROX},{"name":"agent","value":AGENT}],
          open(".scratch-p2/r1-pat.json","w"), indent=1)
open(".scratch-p2/r1-prox.txt","w").write(PROX)
open(".scratch-p2/r1-agent.txt","w").write(AGENT)
print("prox", len(PROX), "agent", len(AGENT))
print("apostrophes in prox:", "'" in PROX, " in agent:", "'" in AGENT)
