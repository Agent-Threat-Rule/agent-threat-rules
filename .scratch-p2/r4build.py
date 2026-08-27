import json
FM   = r"(?:^|\n)-{3,}[ \t]*\r?\n"
NAME = r"[\s\S]{0,500}?\bname:[ \t]*[\x22\x27]?[A-Za-z0-9_.\-]{2,60}"
META = r"[\s\S]{0,500}?\bmetadata:[ \t]*"
CAT  = r"[\s\S]{0,300}?\n[ \t]+(?:category|type|class|kind|purpose):[ \t]*[\x22\x27]?(?:attack|jailbreak|exploit|offensive|red[_\-]?team[_\-]?payload)[\x22\x27]?[ \t]*(?:\r?\n|$)"
cond = FM + NAME + META + CAT
json.dump([{"name":"skill-frontmatter-declares-attack","value":cond}], open(".scratch-p2/r4-pat.json","w"), indent=1)
open(".scratch-p2/r4-cond.txt","w").write(cond)
print(len(cond), "| apostrophe-free:", "'" not in cond)
