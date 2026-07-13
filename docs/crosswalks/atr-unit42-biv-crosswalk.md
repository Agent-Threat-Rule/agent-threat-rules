# ATR -> Palo Alto Unit 42 Behavioral Integrity Verification (BIV) crosswalk

This document maps the capability taxonomy and compound-threat categories from
Palo Alto Networks Unit 42's **Behavioral Integrity Verification for AI Agent
Skills** research onto Agent Threat Rules (ATR) detection content, and -- just
as importantly -- states clearly which parts of the BIV model ATR **does not**
cover because they are a static manifest-diff verification step rather than a
runtime attack *pattern*.

- **Source (blog):** *AI Agent Supply Chain Risks*, Palo Alto Networks Unit 42,
  <https://unit42.paloaltonetworks.com/ai-agent-supply-chain-risks/>.
- **Source (paper):** *Behavioral Integrity Verification for AI Agent Skills*,
  arXiv:2605.11770. Dataset: 49,943 skills from a public skill registry; 80.0%
  of skills deviate from declared behavior (81.1% developer oversight / 18.9%
  adversarial intent); malicious-skill detection reported at F1 0.946 on a
  906-skill benchmark; ~5% of skills carry predicted multi-stage attack chains.
- **This mapping:** hand-authored, 2026-07-13. Class sizes are read from the
  ATR rule directories at authoring time (**748 rules** total). Verify counts
  against `data/stats.json` before any external citation.
- **Companion documents:**
  [`atr-cosai-mcp-taxonomy-mapping.md`](atr-cosai-mcp-taxonomy-mapping.md) maps
  the CoSAI MCP taxonomy; [`atr-attack-crosswalk.md`](atr-attack-crosswalk.md)
  and [`atr-ast-crosswalk.md`](atr-ast-crosswalk.md) map MITRE ATT&CK and OWASP
  AST respectively.

## What BIV is, and where ATR sits in it (read first)

BIV is a **verification** framework: it parses a skill's *declared* capabilities
from its manifest/description, statically infers the skill's *actual*
capabilities from its code, and flags the skill when the two typed sets diverge
over a shared 29-capability taxonomy. The novel signal is the **mismatch**, not
any single capability.

ATR is **runtime detection content** -- a corpus of machine-readable rules that
flag attack *patterns* in agent/tool inputs, outputs, descriptions, and call
sequences. ATR therefore maps onto the **observed-behavior half** of BIV's typed
comparison: for a given BIV capability, ATR answers "is there a rule that fires
when this capability is *exercised maliciously* at runtime?" ATR does **not**
parse a manifest and cannot supply the *declared* half of the comparison, so the
pure declared-vs-actual set-difference step (BIV's core mechanism) is out of
ATR's scope by construction. Where a BIV capability is a benign primitive that
is only interesting once it is *chained* (e.g. `base64`, `write`, `read-project`),
ATR's honest coverage is "flagged only in a compound signature," and this
document says so.

Coverage labels used below:
- **Detection** -- ATR carries rules that fire when this capability is exercised
  as an attack (directly, or as the load-bearing stage of a compound signature).
- **Partial** -- ATR detects some malicious manifestations, but the capability is
  frequently benign and/or the primary control is the BIV manifest-diff itself.
- **Out of scope** -- a benign primitive or a static-verification concern with no
  standalone runtime attack pattern for ATR to match.

## Table 1 -- 29-capability taxonomy (7 families)

| Family | Capability | ATR coverage | Representative ATR rules / classes |
| :--- | :--- | :--- | :--- |
| **Network** | outbound-http | Detection | Exfil sinks: `context-exfiltration` 00102 (disguised analytics), 00135 (exfil URL in instructions), 00261/00405 (markdown-image exfil); dropper fetches in `skill-compromise` 00220. |
| | outbound-socket | Partial | Reverse-shell / netcat sinks: 00223, 00201 (`nc` pipe); benign sockets not flagged. |
| | inbound | Out of scope | Binding a listener is architectural; only the reverse-shell *payload* form is flagged (00223). |
| | download-execute | Detection | Droppers: 00220 (base64->curl raw-IP->bash), 00223, 00126 (rug-pull startup fetch), 02141 (MCP config command exec). |
| **Filesystem** | read-project | Out of scope | Benign primitive; flagged only inside a data-lineage chain. |
| | read-sensitive | Detection | Credential/secret file reads: 00224 (`~/.aws`,`~/.gcloud`), 00423 (NL sensitive-file disclosure), 00161 (`id_rsa`/`.env`/`.netrc` condition). |
| | read-home | Partial | `~/.aws`, `~/.ssh`, `~/.netrc` reads flagged when part of a cred chain (00224, 00201). |
| | write | Out of scope | Benign primitive. |
| | write-sensitive | Partial | Agent memory/config tampering 00200; autostart/`settings` writes in skill rules. |
| | enumerate | Partial (thin) | Tool/capability enumeration 00504; filesystem enumeration itself is benign. |
| | delete | Partial | Destructive `rm -rf`/`unlink` flagged in behavior-mismatch (00061) and dropper cleanup. |
| **Process Execution** | process-exec | Detection | Shell/tool RCE: 00530 (unsanitized argv), tool-poisoning command-injection class (98). |
| | process-exec-shell | Detection | 00530, 00537 (Windows cmd), 02141; `curl|bash` droppers (00220/00223). |
| | code-eval | Detection | 00110 (`eval()`/`new Function`), 00432 (eval RCE). |
| | code-eval-dynamic | Detection | 00110 (`vm.runIn*`, `Reflect.construct(Function)`), 00002 (base64-decode-of-blob), 00126 (`eval(atob(...))` on startup). |
| **Environment** | env-access-specific | Out of scope | Benign primitive (`process.env.PORT`); flagged only when sensitive + chained. |
| | env-access-bulk | Partial | Bulk `printenv`/`env` dumps: 00115 (env-var harvesting). |
| | env-access-sensitive | Detection | 00201 (secret env -> pipe), 00115, 01892 (env exfiltration), 00146 (env-var existence probe). |
| **Encoding** | base64 | Partial | Flagged only inside obfuscation/exfil chains: 00002 (decode-of-blob), 00256 (base-N jailbreak), 00080 (encoding evasion). Benign base64 not flagged alone. |
| | crypto | Out of scope | Encryption is a benign primitive with no standalone attack pattern. |
| | compression | Out of scope | Benign primitive. |
| **Credential** | credential-read | Detection | 00113/00214/00217/00222 (credential theft/harvest), 00224, 00201. |
| | credential-create | Partial | 00274/00411 (API-key generation requests). |
| | credential-transmit | Detection | 00201 (pipe exfil), 00224 (base64->POST), 02017 (secret-key exfil), 00162 (skill cred-exfil combo), **NEW 02261 (language-agnostic chain)**. |
| **Instruction-Level Threats** | instruction-override | Detection (ATR core) | `prompt-injection` (246) + `agent-manipulation` (108); skill-scoped 00120, 00122. |
| | concealment | Detection | 00128 (HTML-comment hidden payload), 00129 (Unicode smuggling), 00337 (obfuscated system announcement). |
| | identity-hijack | Detection | 00060 (skill impersonation), 00134/00147/00151 (fork/publisher impersonation). |
| | silent-execution | Partial | On-startup/background execution (00126) and "do not tell the user" concealment (00161 condition); no dedicated standalone rule. |
| | exfiltration-instruction | Detection | 00135 (exfil URL in instructions), 00136 (tool-response piggyback), 00421-00423 (NL exfiltration instructions). |

## Table 2 -- Four compound-threat categories

BIV's four compound categories are exactly ATR's strongest lane: multi-primitive
*sequences* whose maliciousness lives in the composition, not in any one stage.

| BIV compound threat | Signature | ATR coverage | ATR rules |
| :--- | :--- | :--- | :--- |
| Exfiltration Chains | source primitive -> encoding transform -> network sink | Detection | 00224 (shell: `cat ~/.aws|base64|curl POST`), 00201 (env secret pipe), 00149 (skill exfil compound), 00162, 00157 (timebomb cred exfil), **NEW 02261 (language-agnostic os.environ/process.env -> base64 -> requests.post/fetch)**. |
| RCE Chains | download -> write -> execute (dropper motif) | Detection | 00220 (base64 -> raw-IP curl -> bash), 00223 (reverse-shell dropper), 00126 (rug-pull startup fetch+exec). |
| Code Obfuscation | encoding chain -> dynamic eval | Detection | 00002 (`base64_decode/atob/Buffer.from` of an opaque blob), 00110 (`eval`/`Function`/`vm`), 00126 (`eval(atob(...))`). |
| Data Lineage Violations | undeclared file->file or file->network pipeline | **Partial** | 00061 (skill description-behavior mismatch) detects the *observed-behavior* half; the declared-vs-observed typed-set diff itself is BIV's manifest-parse step, out of ATR's runtime-pattern scope. |

## Coverage summary

Across BIV's 29 capabilities, ATR provides:

- **Detection for 14** -- outbound-http, download-execute, read-sensitive,
  process-exec, process-exec-shell, code-eval, code-eval-dynamic,
  env-access-sensitive, credential-read, credential-transmit,
  instruction-override, concealment, identity-hijack, exfiltration-instruction.
- **Partial for 8** -- outbound-socket, read-home, write-sensitive, enumerate,
  delete, env-access-bulk, base64, credential-create, silent-execution.
  (silent-execution and credential-create are the thinnest and are candidate
  gaps for future rules.)
- **Out of scope for 7** -- inbound, read-project, write, env-access-specific,
  crypto, compression, plus the benign-primitive reading of enumerate. These are
  benign primitives BIV only cares about once *declared-vs-actual* disagrees --
  the manifest-diff step ATR does not perform.

Across the four compound categories, ATR provides **Detection for 3**
(Exfiltration Chains, RCE Chains, Code Obfuscation -- ATR's native
sequence-detection lane) and **Partial for 1** (Data Lineage Violations, whose
core is BIV's manifest-diff, not a runtime pattern).

## Honest conclusion

ATR and BIV are complementary, not competing. BIV is a *static* supply-chain
verification gate (does the skill's code do more than its manifest declares?);
ATR is *runtime* detection of the attack patterns those over-declared or
adversarial capabilities produce when exercised. The clean division of labor:

- **BIV owns** the declared-vs-actual typed-set comparison, the developer-oversight
  triage (81.1% of deviations), and the manifest-parse "declared" half.
- **ATR owns** the runtime attack signatures for the malicious 18.9% -- and its
  compound-signature lane lines up capability-for-capability with BIV's four
  compound-threat categories.

The one measured gap this crosswalk found and closed is a **code-surface
(non-shell) exfiltration chain**: ATR's exfil-chain rules (00201, 00224) keyed
on shell syntax (`cat ... | base64 | curl`), so the language-agnostic form BIV
highlights as its canonical example -- `os.environ`/`process.env` sensitive read
-> base64 encode -> `requests.post`/`fetch` -- was uncovered (verified: 0 rules
fired on that payload against the full 748-rule corpus). Rule **ATR-2026-02261**
closes it (see `rules/skill-compromise/`).

## ATD technique note

Where ATR rules cited above carry ATD (Agent Threat Detection knowledge-base)
technique tags in their metadata, a BIV capability resolves transitively to
those ATD techniques through the rule IDs in the tables. This crosswalk does not
mint new ATD IDs; it is the capability->rule bridge, and the rule metadata is the
rule->ATD/ATLAS/OWASP bridge.
