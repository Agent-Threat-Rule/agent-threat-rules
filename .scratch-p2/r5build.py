import json
NOAPPROVE = (r"(?:\b(?:proceed|continue|go\s+ahead|act|execute|complete\s+(?:this|it)|carry\s+on|do\s+(?:this|it))\b[^.\n]{0,45}?"
             r"\bwithout\s+(?:asking|requesting|seeking|obtaining|waiting\s+for|needing|first\s+asking)\b[^.\n]{0,45}?"
             r"(?:confirmation|approval|authoris\w+|authoriz\w+|consent|permission|sign-?off)"
             r"|\bno\s+(?:user|human|further|additional|explicit|prior|separate|account[\s-]holder)\s*[\w\s-]{0,25}?"
             r"(?:confirmation|approval|authoris\w+|authoriz\w+|consent|permission|sign-?off|authentication)\b[^.\n]{0,40}?\b(?:is\s+|are\s+)?(?:needed|required|necessary)\b"
             r"|\b(?:you|the\s+(?:assistant|agent|ai|bot|model))\s+(?:do(?:es)?\s+not\s+need|need\s+not|are\s+not\s+required|is\s+not\s+required)\s+to\s+"
             r"(?:ask|request|seek|obtain|wait|confirm|verify))")
AUTONOMY = (r"(?:\bthis\s+is\s+an?\s+(?:fully\s+)?autonomous\s+(?:action|operation|step|transaction)"
            r"|\bautonomous\s+action\s+(?:taken\s+)?(?:purely\s+)?by\s+the\s+(?:agent|assistant|ai|bot)"
            r"|\b(?:taken|performed|executed|carried\s+out)\s+(?:purely\s+|solely\s+|entirely\s+)?by\s+the\s+(?:agent|assistant|ai\s+agent|bot)\b"
            r"|\bthe\s+(?:assistant|agent|ai|bot|model)\s+(?:may|can|is\s+(?:permitted|authoris\w+|authoriz\w+|allowed|cleared))\s+(?:to\s+)?"
            r"(?:act|proceed|complete|execute|continue|finalis\w+|finaliz\w+)\b[^.\n]{0,60}?\b(?:autonomous\w*|independently|unilaterally|on\s+its\s+own|without)"
            r"|\b(?:logistical|system|protocol|compliance|operational)\s+override\b)")
out=[{"name":"approval-not-needed-assertion","value":NOAPPROVE},
     {"name":"agent-autonomy-grant","value":AUTONOMY}]
json.dump(out, open(".scratch-p2/r5-pat.json","w"), indent=1)
print({o["name"]:len(o["value"]) for o in out}, "| apostrophe-free:", all("'" not in o["value"] for o in out))
