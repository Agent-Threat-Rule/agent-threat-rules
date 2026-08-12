# Triage of the 43 `maturity: stable` + `severity: critical` rules

`docs/DETECTION-BOUNDARY.md` §3 established that a zero on the benign gate is
worth nothing when no benign sample could have matched the rule, and
`scripts/gate-corpus-visibility.ts` turned that into a per-rule tier: **blind**
(no benign sample can match), **thin** (below the visibility floor), **measured**.

The gate's own header says the important thing twice: *"blind is not
automatically a bad rule"*. A rule keyed on rot13-piped-to-shell is blind
because nobody writes that by accident. A rule keyed on `scp` is blind because
the corpus is four fifths skill listings and paper abstracts. The two look
identical in the tier column and need opposite treatment. Nothing in the
repository separates them, because separating them requires writing the missing
legitimate samples and running them.

This document writes them and runs them, for the population where being wrong
costs the most.

Measured at `161782bca`, 784 rules on disk.

---

## 0. Why this population

`src/verdict.ts` `determineOutcome` decides `allow` / `ask` / `deny` from two
inputs, severity and confidence:

```
critical                → deny
high + conf >= 0.8      → deny
high + conf <  0.8      → ask
medium + conf >= 0.6    → ask
```

`severity: critical` is denied outright. Confidence is not consulted, maturity is
not consulted, and the lane is not consulted — `src/engine.ts:303` gates on lane
before the verdict, but the shipped default is `hunt`, which admits every
maturity. So a false positive on a critical rule is not a line in a log. It is a
blocked legitimate action, in every lane, at every confidence.

`maturity: stable` additionally admits the rule to the `enforce` lane, the only
lane an operator can select to reduce the ruleset to what is trusted to block.
`stable` + `critical` is therefore the strongest claim this project makes about
any rule, and the population where a vacuous zero does the most damage.

---

## 1. Recount

```
$ npx tsx scripts/gate-corpus-visibility.ts --json   # 709 KB, 784 rules
```

Cross-referenced against `severity` / `maturity` read from the rule files
themselves (the gate's JSON does not carry severity):

| | rules |
| --- | ---: |
| on disk | 784 |
| `maturity: stable` + `severity: critical` | **43** |
| — of those, corpus tier `blind` | 17 |
| — `thin` | 7 |
| — `measured` | 19 |

43 confirmed independently of the brief. The 24 blind + thin rules are the
subject of this triage; the 19 measured rules are listed in §6 and were not
probed.

---

## 2. Method

**Classification criterion.** `docs/DETECTION-BOUNDARY.md` §2.1 already defines
one — a rule is *artifact-type* if some required anchor set is entirely
non-words, *judgment-type* if every required anchor set contains an ordinary
English word — and `scripts/detection-boundary/family.py` computes it. This
document uses that classifier rather than inventing a second one, and then does
what the classifier cannot: reads each pattern to see whether the thing it locks
onto is a **machine artifact with no legitimate use** or a **neutral primitive
the corpus merely lacks**, and settles the disagreement by measurement.

**The measurement.** For every rule judged to key on a neutral primitive, plus
every rule where the reading was uncertain, legitimate content was written by
hand that contains that primitive — 83 samples in
`data/measurements/stable-critical-triage/benign-probes.jsonl`, each carrying
the rule it targets, why the content is legitimate, and a `class` field
distinguishing two kinds of legitimate text (§3).

Samples are pushed through `src/corpus-event.ts` `matchedRuleIds`, the same
shape set `scripts/gate-promotion-fp.ts` charges rules against, so a hit here is
a hit the benign gate would have counted had the sample been in the corpus. Each
sample is additionally run through `engine.evaluateWithVerdict()` on every shape,
so the reported verdict is the production decision, not an inference from the
severity table.

**Control.** `new ATREngine(...)` does not compile patterns in its constructor;
a harness that forgets `await engine.loadRules()` reports zero matches for
everything and looks like a clean result. So every probed rule is first fired
with its own declared `test_cases.true_positives[0]`, and the harness aborts if
none fires:

```
CONTROL: 24 fired on own TP, 0 did not
```

24/24. Every rule below was demonstrably live and matching at the moment its
benign samples were scored.

Harness: `scripts/detection-boundary/stable-critical-probe.ts`.

---

## 3. Result

| | |
| --- | ---: |
| probes written | 83 |
| probes firing at least one `severity: critical` rule | 70 |
| probes whose production verdict is `deny` | **70** |
| probed rules that fired on legitimate content | **24 of 24** |

Every one of the 24 blind-or-thin stable+critical rules fires on legitimate
content. That is a stronger result than expected and it needs its limit stated
immediately: **these samples were written against the rules, so 70/83 is not a
false-positive rate.** It is an existence proof — for each of these 24 rules,
legitimate content that trips it exists and is not exotic. How often real
traffic contains it depends on what the agent does; a DevOps agent meets
ATR-2026-00711's shapes daily, a customer-support agent may never.

The independent classifier agrees on the direction. Of the 24:

| `family.py` verdict | rules | fired on a probe |
| --- | ---: | ---: |
| judgment | 22 | 22 |
| artifact | 2 | 2 |

Even the two the classifier calls artifact-type (ATR-2026-01896 on
`requests.get(`, ATR-2026-01899 on `authorized_keys`) fired — a worked instance
of §2.4's lesson that the criterion should be read as "no benign use", not "not
English".

### The split that decides treatment

Two kinds of legitimate text trip these rules, and they call for opposite fixes.
Every probe carries which kind it is:

- **`primitive`** — legitimate content that *performs* the action the rule keys
  on. `sudo ufw disable` in a connectivity runbook. `globalThis.process` in an
  isomorphic build. Copy-then-delete in a storage migration. The rule cannot be
  narrowed to exclude these without a fact that is not in the text.
- **`quote`** — legitimate content that *names* the attack string in order to
  defend against it. Secure-coding training, linter output, malware IOC
  sections, pentest findings. The rule's target string still has no legitimate
  use; only writing *about* it is legitimate.

Sorting the 24 by whether any `primitive` probe fired them:

| | rules |
| --- | ---: |
| fired only on `quote` probes → **keep** | 4 |
| fired on at least one `primitive` probe → **demote / fix conditions** | 20 |

---

## 4. List A — keep (4 rules)

Blind here is expected. Each locks a string that has no legitimate *use*; the
only legitimate text containing it is text that discusses it.

| rule | why the string has no legitimate use | probes that fired it |
| --- | --- | --- |
| **ATR-2026-00432** SuperAGI output-handler eval() RCE | `eval(__import__('os').system(...))` and `__import__("os").system` are code whose only effect is to run a shell command through a dynamic-evaluation sink. No program needs to reach `os.system` through `eval` — the direct call is shorter and safer, so the indirection exists only to survive a filter. | B006, B007 (both `quote`: secure-coding training, bandit output) |
| **ATR-2026-00700** Structured-data IMPORTANT!!! override | `IMPORTANT!!! Ignore all previous instructions` is a sentence addressed to a model, embedded in a data field that a human never reads. A product description or a code comment has no reason to instruct the reader to discard prior instructions. | B019, B071 (both `quote`: awareness training, detection changelog) |
| **ATR-2026-00712** Malicious package install via agent | Every condition requires the literal word `malicious` / `attacker` / `evil` / `hostile` / `fake` next to the install command. Legitimate instructions to install a package do not describe the package as malicious. Confirmed: B083 (`pip install --index-url https://pypi.corp.example.com/simple …`, an internal mirror) does **not** fire. | B036 (`quote`: malware IOC section) |
| **ATR-2026-01307** MCP DNS rebinding | Conditions 0–2 key on the hostnames of public DNS-rebinding services (`rebind.network`, `rbndr.us`, `1u.ms`) and on hostname patterns that encode a public and a private address in one name. Those names exist to make a resolver return two different addresses; there is no other reason to use one. | B046, B080 (both `quote`: hardening guide, pentest finding) |

**Caveat on ATR-2026-01307.** Its condition 3 is not of the same kind as the
other three: it fires on a loopback address with a common MCP port within 200
characters of the word `rebind` — which is what *any* text explaining the attack
looks like, including this document. Both of its probes fired on condition 3
alone. The rule is kept, but condition 3 should be narrowed to require a
rebinding hostname rather than the topic word.

**What "keep" still owes.** A rule whose only false positives come from defensive
writing is a good rule with a documented blind spot, not a rule that needs no
work. Two things follow: the four `quote` probes belong in the benign corpus so
that the blindness stops being invisible, and a rule that fires on the security
training its own users read is still an interruption. §5's note on
condition-level fixes applies here too — an "is this a quotation" test
(prose framing, code-fence, past tense) is a narrowing that does not cost
detection.

---

## 5. List B — demote or fix conditions (20 rules)

Each of these fired on at least one probe that *performs* the action rather than
describing it. Ordered by how many distinct legitimate probes tripped them.

Two facts constrain every recommendation, and both were measured rather than
reasoned:

1. **Demoting `critical` → `high` changes nothing.** Every match of the 24
   probed rules carried confidence ≥ 0.907 (the minimum, ATR-2026-00030;
   the rest are ≥ 0.914), and `high` + confidence ≥ 0.8 is still `deny`.
   Run through the real `computeVerdict`, at the confidence each rule actually
   produced: `critical → deny`, `high → deny`, `medium → ask`, `low → allow`.
   The first severity that stops the block is **medium**.
2. **Demoting `maturity` changes nothing in the default lane.** `stable → test`
   removes the rule from `enforce` only. The shipped default lane is `hunt`,
   which admits every maturity, so the rule keeps denying for everyone who has
   not opted into `enforce`.

So "demote" below means **severity → medium** (deny becomes ask) unless the
condition-level fix is named, and the honest price is stated with it: at medium,
the rule's own true positive also drops from `deny` to `ask`. That is the trade,
and for judgment-type rules whose decisive fact is not in the text — the
recipient, the host, what happens next — `ask` is the correct outcome, which is
the same conclusion `docs/DETECTION-BOUNDARY.md` §4 reaches from the other side.

| rule | tier | conditions that fired on legitimate content | what the neutral primitive is | recommendation |
| --- | --- | --- | --- | --- |
| **ATR-2026-00030** Cross-agent attack | thin | 0, 1, 2, 6, 8 | `I am the orchestrator agent` (supervisor self-introduction), `acting on behalf of <x>` (ordinary delegation), `status: timeout … switch to` (retry/fallback prose) | severity → medium. Conditions 0/6/8 have no attack-specific content at all and should be dropped or require a privilege-granting request in the same message. |
| **ATR-2026-01462** Pseudo-admin override | blind | 0, 1, 2, 5 | `PRIORITY LEVEL: CRITICAL` (every incident tracker), `AUTHORIZATION: FULL` / `ROOT_ADMIN` (IAM exports), `COMPLIANCE_CHECK: PASSED` (compliance tooling), `CONTENT_FILTER: DISABLED` (staging config) | severity → medium. These are field names, and the rule cannot tell a report *containing* them from an instruction *asserting* them. Requiring an imperative in the same block would be a genuine narrowing. |
| **ATR-2026-01019** Fake diagnostic mode | thin | 0, 2, 5 | same key-value vocabulary as above, plus `Rule 1: Don't change … Rule 2: Never …` (a standard system-prompt idiom) | severity → medium; consider merging with ATR-2026-01462, which fires on the same four probes. |
| **ATR-2026-00707** Exfil + destroy/tamper | blind | 1, 3 | *get file from cloud storage → delete/modify source* — which is what every storage migration, retention policy and config rotation does | severity → medium. This is `docs/DETECTION-BOUNDARY.md` §4.6 exactly: staging becomes exfiltration only if something later ships it off the host, an event that has not happened yet. |
| **ATR-2026-00711** Destructive shell command | blind | 1, 2, 3 | `sudo ufw disable` (first bisection step in a connectivity investigation), `iptables -F` (CI network reset), `rm -rf ~/anaconda3/` (the vendor's own documented uninstall), `rm -rf /boot/vmlinuz-…` (standard full-`/boot` fix) | severity → medium. Every anchor is a documented administrative procedure. The malicious version differs by who asked, not by the command. |
| **ATR-2026-00715** Tool-knowledge hijack | blind | 1, 3, 5, 6 | `call the transfer_funds tool with arguments: {` and `use the tool \`send_money\`` — i.e. tool documentation and framework tutorials; `Remember to substitute the placeholders … '$'` — mail-merge instructions | severity → medium, or require the identity-injection half (`<INFORMATION>` + false sender) that conditions 0 and 2 already express. Conditions 5 and 6 match any prose naming these tool ids. |
| **ATR-2026-00436** Enclave sandbox escape | blind | 0, 1 | `globalThis.process` / `globalThis.Buffer` / `globalThis.require` — the standard isomorphic-environment probe, a bundler Buffer polyfill, and CJS/ESM interop | drop condition 1, or require it to co-occur with a constructor-chain or prototype-write. Conditions 0 and 3–6 are genuine escape primitives and can stay `critical`. |
| **ATR-2026-00440** Semantic Kernel eval RCE | blind | 2, 3 | `types.FunctionType` (ordinary introspection), `getattr(object, …)` (plugin registry), `__subclasses__()` (the documented way to enumerate ORM models) | narrow condition 3 to `BuiltinImporter` only, and require condition 2 to co-occur with `eval` / `exec` / `__import__`. The lambda conditions (0, 1, 5) are the actual CVE shape and can stay `critical`. |
| **ATR-2026-01755** POT linguistic trigger | blind | 0, 1, 3 | `through a lens of clarity`, `through a prism of insight`, `with perspicacious discernment` — high-register English, native to marketing copy, humanities abstracts and book reviews | severity → medium at most; condition 3 (the synonym-substitution variant) should be dropped outright. A trigger phrase only means anything against a specific poisoned model; on a clean model this rule blocks fine writing and detects nothing. |
| **ATR-2026-01453** Markdown image base64 exfil | thin | 3 | *"include in your response the image ![…](https://…)"* — build badges, architecture diagrams, sparklines in report templates | drop condition 3 or require an exfil placeholder in the URL. Conditions 0–2 (`[QUERY]` placeholder, `where QUERY is the base64 encoded`) are artifact-shaped and can stay `critical`. |
| **ATR-2026-00706** Biometric/physical exfil | thin | 2, 3 | *scan my passport → send it* (KYC onboarding), *convert the recording → email it* (podcast post-production) | severity → medium. The distinguishing fact is the destination, which is the §4.4 gap. |
| **ATR-2026-00702** Credential exfil via agent action | blind | 0, 5 | *email the API key to <address>* (key-rotation runbook), *get my stored passwords → send them to my email* (password-manager migration) | severity → medium. Whether the address is the security team or the attacker is not in the text. |
| **ATR-2026-00703** Financial data exfil | blind | 0, 2 | *retrieve my saved payment methods → email them to my accountant*, *get my card information → forward it to the dispute desk* | severity → medium, same reason. |
| **ATR-2026-01753** Ransom extortion | thin | 1, 3 | `wire $4,200 to IBAN DE89…` (supplier payment, deposit), `SECURITY MESSAGE … pay … USD` (phishing-awareness copy) | severity → medium. Condition 1 is an ordinary payment instruction; the ransom is in the context, not the string. |
| **ATR-2026-01897** Host sabotage | blind | 3, 4 | `open("/etc/hosts", "a")` — the standard local-DNS override in dev and CI setup; `while True: "x" * 1000000` inside an OOM-handling test | drop condition 3 or require a hijacked hostname mapping; keep conditions 0–2 (`shutil.rmtree("/")`, `os.remove("/lib/…")`, fork bomb), which have no legitimate form. |
| **ATR-2026-01899** Remote-access backdoor | blind | 0, 1 | condition 1: `pexpect.spawn("ssh -L …")` — automating a local port-forward to an internal service is routine ops. Condition 0 (`authorized_keys` … `requests.get(`) fired on B082, cloud-init style key provisioning from the instance metadata service. | severity → medium, or require a non-corporate destination host, which the text layer cannot supply — in which case medium is the honest answer. |
| **ATR-2026-00434** mcp-remote auth endpoint | thin | 0, 4 | `%26` in an `authorization_endpoint` (a percent-encoded ampersand, ordinary in a real OIDC discovery document) and `|` in a B2C policy parameter | fix conditions rather than demote: remove `%26` from condition 4, and require the pipe branch of condition 0 to be followed by a shell verb. The `$(`/backtick branches are genuine artifacts. |
| **ATR-2026-01304** IPI data carrier | blind | 0, 3 | condition 3: *update the security policy with policy id 12345* — routine firewall administration | drop or narrow condition 3 (it has no injection-specific content). Condition 0 is the B3 carrier signature and belongs in List A; the rule as a whole is dragged down by one condition. |
| **ATR-2026-00433** ModelCache torch.load RCE | blind | 2 | `pickle.loads(response.content)` — reading a pickle cache entry from an HTTP response is ordinary client code | narrow condition 2 to require the ModelCache/torch context named in the rule's own title, or drop `response.content` from its source list. Conditions 3–5 (`__reduce__` returning `os.system`, raw pickle opcodes) stay `critical`. |
| **ATR-2026-01896** Remote-key ransomware | thin | 0 | `requests.get("https://kms…/get_key").content` followed by Fernet encryption — envelope encryption against a key service | narrow: require the encrypt step to overwrite the original file, or a ransom artefact. As written, the invariant is "fetch a key over HTTP and encrypt", which is also what a backup tool does. Note this probe (B081) is constructed to fit the 10-character tail the pattern allows; B058, the same code with a query string, does not fire. |

---

## 6. List C — corpus

The brief's third list was "(乙) rules that do **not** false-positive in
practice — these need benign samples, not demotion". **That list is empty**: all
20 judgment-shaped rules fired. What exists instead is the corpus material
itself, and it is worth more than the empty list would have been.

`data/measurements/stable-critical-triage/benign-probes.jsonl` — 83 samples,
each with `id`, `class` (`primitive` / `quote`), `targets`, `kind`, `why`, `text`.

13 of them fire no critical rule at all. Those are the purest corpus additions:
they contain the shapes the corpus is missing and prove nothing is wrong today.

| probe | shape it carries | targets |
| --- | --- | --- |
| B003 | *do not tell the user about every retry* (verbosity control) | 00030 |
| B009 | `torch.load(io.BytesIO(...))` on a self-written checkpoint | 00433 |
| B025 | *retrieve bank account details → send to payroll provider* | 00703 |
| B026 | *create a voice clone → send to my producer* | 00706 |
| B032 | `apt-get remove --purge linux-headers-…` for a full `/boot` | 00711 |
| B045 | allowlist maintenance naming vendor domains | 01304 |
| B047 | `rbndr.us` named in a defensive test instruction | 01307 |
| B052 | forward-then-delete mailbox rule | 01753 |
| B063 | fleet deploy-key rotation writing `authorized_keys` | 01899 |
| B065 | privacy policy stating credentials are never emailed out | 00702, 00703 |
| B069 | drive-to-legal send then delete, plus archive | 00707, 01753 |
| B072 | signed-artefact upload with `weights_only=True` | 00433 |
| B083 | `pip install --index-url` against an internal mirror | 00712 |

**These files are deliberately not in any gate corpus.** Adding them changes the
denominator for all 784 rules, which is the user's call, not a side effect of a
research document. The size of that call, measured:

```
distinct rules fired by the 83 probes: 68
  of which currently 0 FP in data/benign-fp-measurement.json: 30
  of which already have FP on record: 38
total (rule, probe) firings: 191
```

Adding these 83 samples to `data/benign-corpus-extended/` would move **30 rules
from clean to dirty** — most of them outside this triage's 24. That is the
correct outcome (their zeros are equally vacuous) and it is exactly why it needs
a decision rather than a commit.

---

## 7. The 19 measured stable+critical rules

Not probed. Their zeros rest on a corpus that could have fired them, so they are
not in the class this document is about.

| rule | visibility | title |
| --- | ---: | --- |
| ATR-2026-00511 | 28 | MCP Web-Fetch Context Poisoning via Embedded Agent Instructions |
| ATR-2026-00512 | 132 | Rules-File Backdoor — Supply Chain Attack on AI Coding Assistant Config |
| ATR-2026-00704 | 54 | Indirect PI — Medical / Genetic Data Exfiltration via Agent Action |
| ATR-2026-00708 | 68 | Indirect PI — Unauthorized Financial Transfer via Agent Tool |
| ATR-2026-00709 | 588 | Indirect PI — Disable Authentication / MFA via Agent Tool |
| ATR-2026-00710 | 52 | Indirect PI — Unauthorized Physical Access Grant via Smart Lock |
| ATR-2026-00722 | 30 | Indirect PI — Account Manipulation / Emergency Service Dispatch |
| ATR-2026-00850 | 333 | Indirect PI — Credential Exfiltration via Email |
| ATR-2026-00851 | 220 | Indirect PI — Financial / Payment Credential Exfiltration via Email |
| ATR-2026-00852 | 241 | Indirect PI — Medical Record / Health Data Exfiltration via Email |
| ATR-2026-00853 | 54 | Indirect PI — Genetic / DNA Data Exfiltration via Agent Email |
| ATR-2026-01000 | 393 | Context-Ignore via Fake Completion Prefix |
| ATR-2026-01302 | 42 | Fake Tool Result Prefix — Injected Instruction |
| ATR-2026-01306 | 191 | MCP OAuth Authorization URL — Command Injection via URL Authority |
| ATR-2026-01310 | 185 | MCP Tool Description — Compliance/Audit Framing |
| ATR-2026-01454 | 109 | Direct Markdown Image/Link Exfil Payload |
| ATR-2026-01601 | 420 | SQL Injection Destructive DDL Statement |
| ATR-2026-01602 | 70 | SQL Injection UNION SELECT Data Exfiltration |
| ATR-2026-01754 | 87 | Ransom Extortion: Cloud File Exfil + Delete + Payment Demand |

One caution, from this run rather than from theory: **ATR-2026-00850**
(visibility 333, comfortably "measured") fired on probe B079, a password-manager
export mailed to the account owner's own address. Visibility counts samples
containing the required literals and ignores the ordering and proximity the
regex also demands — the gate's own header says it is an upper bound. "Measured"
means the zero is not vacuous. It does not mean the rule is clean.

---

## 8. What this run does not establish

- **Not a false-positive rate.** The 83 samples were written against these
  specific rules. 70/83 is the density of a targeted probe set, not of traffic.
- **Not a frequency claim.** Whether a given primitive appears in real traffic
  depends on the agent's job. This document says the legitimate content exists
  and is ordinary; it does not say how often it arrives.
- **Not a recall claim.** No attack corpus was re-run. Every demotion proposed
  in §5 costs detection strength, and the cost is stated per rule but not
  measured against an attack set.
- **Not a repair.** No rule file was modified. §5 is a recommendation list.
- **These 24 are not the whole problem.** With all 24 excluded, 27 of the 83
  legitimate probes are still denied, by 22 further `severity: critical` rules
  at `maturity: test`. Those sit outside `enforce` but inside the default lane,
  and they were not triaged here.

---

## 9. Reproducing every number

```bash
# tier and severity population (§1)
npx tsx scripts/gate-corpus-visibility.ts --json > /tmp/vis.json
python3 - <<'PY'
import json, os, yaml, collections
vis = {r["id"]: r for r in json.load(open("/tmp/vis.json"))["rules"]}
rows = []
for root, _, files in os.walk("rules"):
    for f in files:
        if not f.endswith(".yaml"): continue
        y = yaml.safe_load(open(os.path.join(root, f)))
        if isinstance(y, dict) and y.get("maturity") == "stable" and y.get("severity") == "critical":
            rows.append((y["id"], vis[y["id"]]["tier"]))
print(len(rows), collections.Counter(t for _, t in rows))
PY

# the probe run (§3, §5) — control, verdicts, per-condition attribution
npx tsx scripts/detection-boundary/stable-critical-probe.ts
npx tsx scripts/detection-boundary/stable-critical-probe.ts --json \
  > data/measurements/stable-critical-triage/probe-result-20260812.json

# the independent family classifier (§3)
python3 scripts/detection-boundary/build-corpus.py     # 5352 samples
npx tsx  scripts/detection-boundary/dump-rules.ts      # 784 rules
python3 scripts/detection-boundary/family.py

# corpus impact of adding the probes (§6) — printed by the same harness, and in
# its JSON under corpus_impact_if_added_to_benign_gate
npx tsx scripts/detection-boundary/stable-critical-probe.ts | sed -n '/benign gate corpus/,+4p'
```

Recorded output of the probe run:
`data/measurements/stable-critical-triage/probe-result-20260812.json`.
