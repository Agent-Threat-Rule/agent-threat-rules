import json
# Destination must be a HARDCODED PUBLIC host: starts with a letter and has a dot.
# Excludes localhost:8000 (no dot) and 127.0.0.1 (starts with a digit) by construction.
URLLIT = r"[\x22\x27\x60]https?://[A-Za-z][A-Za-z0-9-]{0,40}(?:\.[A-Za-z0-9-]{1,40}){1,4}[/:\x22\x27\x60]"
POSTFN = (r"(?:\brequests?\.(?:post|put|patch)|\bhttpx\.(?:post|put)|\bsession\.(?:post|put)"
          r"|\baxios\.(?:post|put)|\bfetch|\burlopen|\burllib\.request\.(?:urlopen|Request)|\.post)")
SINKURL = POSTFN + r"\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]{0,20}\s*=\s*)?" + URLLIT
ENVDUMP = (r"(?:\bdict\s*\(\s*os\.environ\s*\)|\bos\.environ\.copy\s*\(\s*\)|\{\s*\*\*\s*os\.environ"
           r"|\bjson\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ|\bstr\s*\(\s*os\.environ\s*\)"
           r"|JSON\.stringify\s*\(\s*process\.env|Object\.entries\s*\(\s*process\.env"
           r"|Object\.assign\s*\(\s*\{\s*\}\s*,\s*process\.env|\{\s*\.\.\.\s*process\.env\s*\})")
# cond1: whole-environment dump bound as an ARGUMENT of a call to a hardcoded public URL
cond1 = r"(?:" + SINKURL + r"[^\n]{0,150}?" + ENVDUMP + r"|" + ENVDUMP + r"[^\n]{0,150}?" + SINKURL + r")"
# cond2: shell env dump PIPED (same line) into an outbound transport
cond2 = (r"\b(?:printenv|env|set)\b[^\n|]{0,40}?\|[^\n]{0,60}?"
         r"\b(?:curl|wget|nc|ncat|openssl\s+s_client|base64)\b[^\n]{0,120}?"
         r"(?:https?://|\s-d\b|--data|-X\s*POST|--post-data|--upload-file|\|\s*(?:curl|wget|nc)\b)")
# cond3: network destination produced by decoding an obfuscated literal at runtime
B64DEC = r"(?:(?:base64\.)?b64decode|atob|Buffer\.from)"
cond3 = (r"(?:" + POSTFN + r"\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]{0,20}\s*=\s*)?" + B64DEC + r"\s*\("
         r"|" + B64DEC + r"\s*\(\s*[\x22\x27\x60](?:aHR0cHM6Ly9|aHR0cDovL)[A-Za-z0-9+/=]{2,}[\x22\x27\x60][\s\S]{0,200}?" + POSTFN + r"\s*\("
         r"|" + POSTFN + r"\s*\([\s\S]{0,120}?" + B64DEC + r"\s*\(\s*[\x22\x27\x60](?:aHR0cHM6Ly9|aHR0cDovL))")
out = [{"name":"envdump-to-hardcoded-url","value":cond1},
       {"name":"shell-env-piped-out","value":cond2},
       {"name":"obfuscated-destination","value":cond3}]
json.dump(out, open(".scratch-p2/r2-pat.json","w"), indent=1)
for o in out: open(".scratch-p2/r2-%s.txt" % o["name"], "w").write(o["value"])
print({o["name"]: len(o["value"]) for o in out})
print("apostrophe-free:", all("'" not in o["value"] for o in out))
