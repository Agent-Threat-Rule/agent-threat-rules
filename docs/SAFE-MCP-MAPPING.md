# ATR → SAF-MCP Technique Mapping

<!-- Generated from docs/saf-mcp-mapping.json by scripts/generate-saf-mcp-mapping.ts. Do not edit by hand. -->

Framework: SAF Framework Model v2 — [secure-agentic-framework/saf-mcp](https://github.com/secure-agentic-framework/saf-mcp), `research/framework-model.yml` at `4a74d69` (2026-09-02)
ATR release reviewed: v4.1.5 (reviewed 2026-10-16)

## How to read this

- Each pair was proposed from the rule's actual patterns and conditions, then kept only if two independent reviewers agreed on the technique fit and the relationship. Relationships follow the SAF registry semantics; nothing is marked direct.
- `partial`: the rule represents a bounded subset of the technique. `adjacent`: the rule provides supporting context but does not by itself represent the technique. These follow the SAF detection registry definitions.
- Modalities name the observation surfaces the rule actually inspects, using the SAF registry vocabulary.
- This is an inventory of candidate mappings, not a coverage or effectiveness claim, and none of the pairs has been validated by SAF. SAF decides whether an external mapping is validated in its own registry.
- Deprecated SAF techniques are not mapped.
- Per-rule `references.safe_mcp` tags inside rule files are author-declared and are not reconciled with this table; where they differ, this table is the reviewed result.

## Summary

- Active techniques in the framework model: 78
- Techniques with at least one reviewed ATR rule (partial or adjacent): 55
- Of those, techniques whose only reviewed rules are adjacent (supporting context, not detection of the technique itself): 20
- Techniques with none: 23 (listed at the end)
- Reviewed pairs: 131

## Mappings

### SAF-T1001 — Tool Poisoning Attack

Tactic: ATK-TA0001 Initial Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00161](../rules/tool-poisoning/ATR-2026-00161-important-tag-cross-tool-shadowing.yaml) | partial | content | Matches &lt;IMPORTANT>...&lt;/IMPORTANT> blocks with read/send/invoke/forward verbs, references to an 'also present'/'previously declared' companion tool, and 'before using this tool, read &lt;path>' directives. This is the Invariant-style cross-tool redirection variant of T1001. One condition (any bare sensitive-file name) is not specific to tool metadata, so the rule covers only a subset. |
| [ATR-2026-00579](../rules/prompt-injection/ATR-2026-00579-mcp-tool-description-line-jumping-injection.yaml) | partial | content | Regexes require a JSON "description"/"param_description" value (or 'tool description' text) carrying an agent-addressed imperative such as 'before using this tool', 'you must ... read/send/forward/route' or 'ignore previous'. That is the instruction-bearing tool-metadata subset of T1001; it does not observe definition drift or the redirected call that follows. |
| [ATR-2026-01300](../rules/tool-poisoning/ATR-2026-01300-mcp-notes-param-chat-history-exfil.yaml) | partial | content | Patterns match tool description or schema text telling the model to put the full chat history or transcript into a notes/history parameter. This is the argument-alteration subset of T1001, where metadata changes call arguments against the user's intent. It is limited to that one exfiltration idiom. |
| [ATR-2026-02025](../rules/tool-poisoning/ATR-2026-02025-mcp-full-schema-poisoning-nondescription-field.yaml) | partial | content | Detects directives hidden in inputSchema parts other than the description, such as imperative parameter names (content_from_reading_..._id_rsa), extra/sidenote/__doc__ fields that say to read and pass secrets, and 'in order to ... you must' text inside required/default fields. This matches T1001's parameter-schema poisoning vector, which changes arguments. |

### SAF-T1002 — Supply Chain Compromise

Tactic: ATK-TA0001 Initial Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00575](../rules/tool-poisoning/ATR-2026-00575-miasma-npm-worm-agent-config-backdoor.yaml) | adjacent | static | Flags the binding.gyp &lt;!(...) install-time fetch-and-run primitive and agent-config backdoor writes used by the Phantom Gyp/Miasma worm, which republished compromised legitimate packages. The rule has no condition on the T1002 discriminator: digest, signature or provenance mismatch on a trusted channel. It gives only artifact-level supporting context. |

### SAF-T1003 — Malicious MCP-Server Distribution

Tactic: ATK-TA0001 Initial Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02405](../rules/skill-compromise/ATR-2026-02405-malicious-skill-package-structure.yaml) | partial | static | Scans MCP-server and skill package contents for the AgentBaiting/FakeGit distribution structure: a .cmd/.bat launcher starting a renamed exe with a .txt argument, a LuaJIT runtime with a releases zip, mcp_servers configs pointing at .cmd/.bat, and campaign IOC repos and hashes. These packages were published intentionally through MCP registries, which is a bounded subset of malicious MCP-server distribution. |

### SAF-T1005 — Exposed Endpoint Exploit

Tactic: ATK-TA0001 Initial Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-01985](../rules/tool-poisoning/ATR-2026-01985-mcp-connect-bridge-unauth-process-spawn-rce.yaml) | partial | content | Matches /bridge request bodies whose serverPath names a shell or interpreter alongside an args field, or a bash/sh serverPath whose -c/-lc args chain a recon or egress command. This is MCP Connect's unauthenticated-by-default route that spawns backend processes, the 'support/test endpoint spawning a process' variant of T1005. The rule keys on the payload, not on the missing-auth decision. |
| [ATR-2026-01986](../rules/privilege-escalation/ATR-2026-01986-windows-mcp-unauth-http-powershell-cors.yaml) | partial | content, network | Matches an OPTIONS preflight on /mcp answered with wildcard Access-Control-Allow-Origin/Methods, and tools/call PowerShell in the same exchange as ACAO '*'. This is the T1005 subset where a browser origin reaches an MCP endpoint without Origin validation. |
| [ATR-2026-02021](../rules/tool-poisoning/ATR-2026-02021-mcp-inspector-unauthenticated-proxy-rce.yaml) | partial | content, network | Matches the request a browser or curl sends to MCP Inspector's unauthenticated proxy: /sse?transportType=stdio&command=... or 0.0.0.0/127.0.0.1/[::1]:6277 with command=. This is the browser-to-local-proxy realization (CVE-2025-49596) cited by T1005. It is product-specific and does not itself check the auth or Origin decision. |

### SAF-T1006 — User-Social-Engineering Install

Tactic: ATK-TA0001 Initial Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02405](../rules/skill-compromise/ATR-2026-02405-malicious-skill-package-structure.yaml) | partial | static | Several conditions match deceptive install content in fake MCP-server repos: download the release zip/exe and double-click it, click 'run anyway' past SmartScreen, disable Defender during setup, and mcp_servers configs whose command is a .cmd/.bat launcher. This is a bounded lure subset of user-approved attacker-controlled MCP installs. The rule does not observe the user's install action itself. |

### SAF-T1008 — Cross-Server Tool Shadowing

Tactic: ATK-TA0001 Initial Access, ATK-TA0004 Privilege Escalation

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00161](../rules/tool-poisoning/ATR-2026-00161-important-tag-cross-tool-shadowing.yaml) | partial | content | Condition 2 requires a descriptor referencing a co-installed tool via 'also present / previously declared / already installed &lt;tool>' wording, matching the Invariant Labs foreign-tool shadowing PoC; other OR-branches (&lt;IMPORTANT> directives, credential paths) also fire on ordinary own-tool poisoning, so it covers a bounded subset. |
| [ATR-2026-01775](../rules/tool-poisoning/ATR-2026-01775-semantic-mcp-tool-manifest-poisoning.yaml) | partial | content | Branches 'after using &lt;X> tool ... run this function ... modify/override result' and 'override the result of a check/verify tool' capture a descriptor directing how another tool's output is handled; its replacement/drop-in branches are name-squatting, which SAF scopes out of shadowing. |
| [ATR-2026-00579](../rules/prompt-injection/ATR-2026-00579-mcp-tool-description-line-jumping-injection.yaml) | adjacent | content | Flags tool/parameter description fields ordering the model to prepend/run/route actions before using any tool or every shell command, which can alter invocation of tools from other servers, but it does not require a foreign-tool reference or provenance mismatch. |

### SAF-T1101 — Command Injection

Tactic: ATK-TA0002 Execution

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00434](../rules/tool-poisoning/ATR-2026-00434-mcp-remote-authorization-endpoint-command-injection.yaml) | partial | content | Requires an OAuth/OIDC metadata URL field (authorization_endpoint, token_endpoint, etc.) carrying shell metacharacters ($( ), backticks, &&, \|cmd, ;cmd) - exactly the SAF 'authorization metadata' vector (CVE-2025-6514 mcp-remote), but only that one command-bearing input path. |
| [ATR-2026-02021](../rules/tool-poisoning/ATR-2026-02021-mcp-inspector-unauthenticated-proxy-rce.yaml) | partial | content | Matches /sse proxy requests with transportType=stdio plus an attacker-supplied command= parameter (or a request to localhost:6277 carrying command=), the CVE-2025-49596 full-executable-selection variant SAF cites; limited to the MCP Inspector proxy shape. |
| [ATR-2026-02141](../rules/tool-poisoning/ATR-2026-02141-mcp-server-config-command-execution.yaml) | partial | content | Detects MCP server config command/args pairs that launch nc -e, a shell/interpreter -c with network-fetch/reverse-shell payloads, docker build from a URL, or npx --yes, covering the SAF 'server configuration crosses into process launch' vector only for those dangerous command shapes. |
| [ATR-2026-00111](../rules/privilege-escalation/ATR-2026-00111-shell-escape.yaml) | adjacent | content | Matches shell-syntax injection in argument text (semicolon-chained dangerous commands, $( ) or backtick substitution running curl/bash/rm, &&/\|\| chains, pipes to sh/nc), i.e. the 'command modification through executable syntax' tool-input variant, without proving a reachable launch boundary. |

### SAF-T1102 — Prompt Injection (Multiple Vectors)

Tactic: ATK-TA0002 Execution

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00001](../rules/prompt-injection/ATR-2026-00001-direct-prompt-injection.yaml) | partial | content | Regexes over user_input for ignore/disregard/override-previous-instructions, new-task switches and hidden-instruction reveal demands cover the SAF direct user-prompt vector only. |
| [ATR-2026-00002](../rules/prompt-injection/ATR-2026-00002-indirect-prompt-injection.yaml) | partial | content | Matches instruction-override text in HTML comments, CSS-hidden elements, runs of zero-width/bidi characters, injected [INST]/&lt;\|im_start\|> wrappers and AI-addressed imperatives in external content, covering the indirect and visually hidden sub-vectors. |
| [ATR-2026-00579](../rules/prompt-injection/ATR-2026-00579-mcp-tool-description-line-jumping-injection.yaml) | partial | content | Requires a JSON tool/parameter 'description' field (or described docstring) carrying a model-addressed imperative (you must prepend/run/route, ignore the user, before using this tool), covering the SAF tool-description injection sub-vector. |

### SAF-T1105 — Path Traversal via File Tool

Tactic: ATK-TA0002 Execution

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00578](../rules/context-exfiltration/ATR-2026-00578-zen-mcp-path-traversal-blacklist-bypass.yaml) | partial | content | The rule matches non-canonical paths: a sensitive prefix followed by ./ or ../ hops, /etc/../etc/shadow bounces, and redundant slashes that resolve to protected files. This is T1105's 'alternate path forms defeat denylist checks' vector. It covers only sensitive-file targets and does no canonical containment check. |
| [ATR-2026-01616](../rules/privilege-escalation/ATR-2026-01616-path-traversal-agent-file-access.yaml) | partial | content | The rule matches two or more ../ segments in tool_args that point into system directories (etc, root, home, proc, var), and deep traversal in user_input. That is lexical traversal in a file-tool argument, a bounded subset of T1105. The rule cannot compare the canonical resolved path with allowed roots, and it misses traversal through links or alternate path forms. |
| [ATR-2026-02700](../rules/privilege-escalation/ATR-2026-02700-percent-encoded-path-traversal-tool-argument.yaml) | partial | content | The rule requires two or more percent-encoded ../ segments as the whole value of a named file-path parameter in tool_args, reaching a credential or system file. This covers the encoding-bypass vector T1105 describes. It is limited to credential-file targets, and its own documentation states it misses positional arguments. |

### SAF-T1106 — Autonomous Loop Exploit

Tactic: ATK-TA0002 Execution

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00209](../rules/tool-poisoning/ATR-2026-00209-mcpwn-runaway-invocation.yaml) | partial | content | The rule matches MCP response fields set to imperative continuation directives: retry_hint loop/until, continue_after_error with retry counts of 100 or more, next_action invoke chains, and 'retry this tool indefinitely'. This is T1106's primary vector, where a malicious server returns follow-up instructions that cause re-invocation. The rule cannot confirm that the loop actually ran without an effective bound. |

### SAF-T1111 — AI Agent CLI Weaponization

Tactic: ATK-TA0002 Execution

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-01989](../rules/excessive-autonomy/ATR-2026-01989-t1046-agent-internal-network-sweep.yaml) | adjacent | content | The rule matches agent tool calls that run nmap CIDR sweeps across a port range, or subnet netcat loops. These are target-facing offensive actions that an agent CLI performs during T1111 operations. The rule cannot separate a weaponized CLI from a hijacked agent or an authorized test. |
| [ATR-2026-02400](../rules/excessive-autonomy/ATR-2026-02400-agent-approval-gate-disabled-runtime.yaml) | adjacent | content | The rule matches agent CLI names (claude, codex, gemini, hermes, aider and others) together with documented approval-bypass flags, environment variables and settings (--dangerously-skip-permissions, --yolo, bypassPermissions). That is the unsafe-mode marker in T1111's analytic. The rule does not require the correlated shell child process, and it also fires when a benign user's agent is hijacked, so it is supporting context rather than a bounded subset. |

### SAF-T1201 — Post-Approval Tool Mutation

Tactic: ATK-TA0003 Persistence

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00126](../rules/skill-compromise/ATR-2026-00126-skill-rug-pull-setup.yaml) | adjacent | static | The rule matches skill code patterns that make later mutation possible: eval(fetch(...)), base64-decode-then-exec, post-install remote fetch, and remote config loading. The rule itself says real rug-pull detection needs hash comparison over time. It flags the precondition, not the mutation after approval. |
| [ATR-2026-00581](../rules/tool-poisoning/ATR-2026-00581-mcp-tool-rug-pull-post-approval-redefinition.yaml) | adjacent | content | The rule matches tool-definition text where a post-approval or version-bump trigger ('after the user approves', 'on subsequent runs', 'now that this tool is trusted') appears with an exfiltration or execution indicator. It also matches text that rewrites its own description to add required initialization steps. It sees only the content of the mutated definition, not T1201's decisive comparison of the approved hash against the observed hash. |

### SAF-T1204 — Context Memory Implant

Tactic: ATK-TA0003 Persistence, ATK-TA0008 Lateral Movement

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00551](../rules/privilege-escalation/ATR-2026-00551-cross-conversation-memory-write.yaml) | partial | memory, runtime | This trace forbid rule fires when a memory.write/vector_store.upsert/longterm.append/rag.ingest TOOL span sets target_conversation_id to a value other than the active conversation.id. It observes a durable memory write that lands in another session's scope. Correlating that write with the later retrieval is left outside the rule. |
| [ATR-2026-00075](../rules/context-exfiltration/ATR-2026-00075-agent-memory-manipulation.yaml) | adjacent | content | The regexes require explicit persistence verbs ('commit to memory', 'add ... to your permanent/long-term memory') or cross-session framing ('in all future sessions ... always'), joined to behavior-changing directives. That covers the memory-instruction-marked write stage of an implant, but not the later cross-session retrieval that T1204 also requires. |

### SAF-T1302 — Agentic Confused Deputy

Tactic: ATK-TA0004 Privilege Escalation

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00074](../rules/agent-manipulation/ATR-2026-00074-cross-agent-privilege-escalation.yaml) | adjacent | content | Conditions match inter-agent requests such as 'execute this with your admin/elevated permissions', 'use my elevated access', or claims to act on behalf of an admin/orchestrator agent. These capture a lower-privilege principal asking a deputy agent to use authority the requester lacks. The rule does not observe the resulting privileged tool effect or the missing authorization check. |
| [ATR-2026-00549](../rules/privilege-escalation/ATR-2026-00549-destructive-tool-without-human-approval.yaml) | adjacent | runtime | This trace require rule fires when a TOOL span with tool.privilege=destructive has no earlier HUMAN span or approval attribute in the trace. That is the missing-approval indicator before an elevated action. It does not establish the low-trust requestor or untrusted content side of the authority mismatch. |
| [ATR-2026-02667](../rules/excessive-autonomy/ATR-2026-02667-preapproved-tool-list-in-job-payload.yaml) | adjacent | content | The rule matches a submitted job or workflow payload whose approve/approved_tools/auto_approve_tools list already names execute_command, shell, delete_file and similar tools. In that case a requestor-supplied list neutralizes the runtime approval gate (the PraisonAI unauthenticated Jobs API case). That is one bounded variant of an action-bound approval that is ineffective against a low-trust requestor. |

### SAF-T1303 — Sandbox Escape via Server Exec

Tactic: ATK-TA0004 Privilege Escalation

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00567](../rules/tool-poisoning/ATR-2026-00567-mcp-stdio-config-command-injection.yaml) | adjacent | content | Regexes fire when an MCP stdio config's "command" is a raw shell or contains shell metacharacters, or when "args" passes -c/-e with a code payload. This is the attacker-supplied launch material in CVE-2026-42271 (LiteLLM stdio spawn, SAF claim C003). The rule sees only the request side and cannot confirm that the spawned process ran in a different, more privileged context. |
| [ATR-2026-02141](../rules/tool-poisoning/ATR-2026-02141-mcp-server-config-command-execution.yaml) | adjacent | content | Matches dynamic MCP server config whose command/args launch an attacker-chosen process: nc -e, a shell or interpreter -c with a dangerous payload, docker build from a remote URL, an npx --yes allowlist bypass, or a node //path bypass. This is attacker-controlled launch material reaching a process launcher. The resulting privilege context is not observed. |

### SAF-T1305 — Host OS Priv-Esc (RCE)

Tactic: ATK-TA0004 Privilege Escalation

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00434](../rules/tool-poisoning/ATR-2026-00434-mcp-remote-authorization-endpoint-command-injection.yaml) | partial | content | Detects shell metacharacters, command substitution, or URL-encoded metacharacters inside authorization_endpoint and other OAuth metadata URLs in an MCP server response. This is exactly the CVE-2025-6514 mcp-remote vector that SAF cites as demonstrated host RCE. It is limited to that one metadata-to-exec flaw. |
| [ATR-2026-01985](../rules/tool-poisoning/ATR-2026-01985-mcp-connect-bridge-unauth-process-spawn-rce.yaml) | partial | content | Fires on a /bridge request whose serverPath names a shell or interpreter with an args field, or bash -c chained recon/egress commands. The flaw is an unauthenticated MCP bridge spawning an arbitrary host process as its own account. This is the same unauthenticated proxy-to-exec class as the Inspector case. |
| [ATR-2026-02021](../rules/tool-poisoning/ATR-2026-02021-mcp-inspector-unauthenticated-proxy-rce.yaml) | partial | content | Matches the MCP Inspector proxy request /sse?transportType=stdio&command=..., or a :6277 loopback URL carrying command=. This is the CVE-2025-49596 browser-to-Inspector unauthenticated command launch that SAF lists as demonstrated evidence. It covers one product path. |

### SAF-T1307 — Confused Deputy Attack

Tactic: ATK-TA0004 Privilege Escalation

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00434](../rules/tool-poisoning/ATR-2026-00434-mcp-remote-authorization-endpoint-command-injection.yaml) | partial | content | SAF-T1307 cites CVE-2025-6514 as a direct deputy case: untrusted server metadata reaches a privileged URL-opening path. It also names 'untrusted authorization endpoint preceding a process launch' as a product IoC, and this rule matches that malicious authorization_endpoint metadata. Initiator/deputy binding validity is not observed. |
| [ATR-2026-02021](../rules/tool-poisoning/ATR-2026-02021-mcp-inspector-unauthenticated-proxy-rce.yaml) | partial | content | SAF-T1307 lists CVE-2025-49596 as a direct vulnerability: an unauthenticated initiator exercises the Inspector proxy's stdio launch authority. This rule matches that unauthenticated proxy request shape (/sse transportType=stdio command=). It covers only this product-specific deputy path. |

### SAF-T1402 — Instruction Steganography

Tactic: ATK-TA0005 Defense Evasion

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00129](../rules/skill-compromise/ATR-2026-00129-unicode-smuggling.yaml) | adjacent | content | On content (skill or tool metadata), the rule matches 3 or more Unicode Tag surrogate pairs, or 5 or more zero-width characters on one line. Both are invisible instruction carriers, but the same code points occur in legitimate text (a subdivision-flag emoji such as the England flag is a run of Tag characters and fires the first condition), and SAF states that character anomalies alone are insufficient. This is carrier-only supporting context with no recovery or action correlation. |
| [ATR-2026-00258](../rules/prompt-injection/ATR-2026-00258-unicode-tag-injection.yaml) | adjacent | content | Regexes on tool_response fire on invisible Unicode Tag-block characters (U+E0000-E007F, including Tag-ASCII and escaped forms). That is one of the invisible Unicode carriers T1402 lists, but a single Tag-ASCII character also fires on legitimate subdivision-flag emoji, and SAF states that character anomalies alone are insufficient, so this is carrier-only supporting context. The rule does not see the decode or sensitive-action correlation that SAF requires, and it does not cover the image, share or opaque-state carriers. |
| [ATR-2026-00312](../rules/prompt-injection/ATR-2026-00312-unicode-variant-selector-ascii-smuggling.yaml) | partial | content | Fires on runs of 3 or more Variation Selectors Supplement codepoints in tool_response, and on 'decode variant selector' framing. This is an ASCII-smuggling encoding whose meaning is invisible to a reviewer but recoverable by the model, so it is one bounded encoded-carrier subset of T1402. |
| [ATR-2026-00276](../rules/prompt-injection/ATR-2026-00276-invisible-unicode-bidi-injection.yaml) | adjacent | content | Matches repeated zero-width characters and BiDi override/isolate controls in tool_response, plus their escaped forms in content. These map to the 'invisible Unicode and control characters' carrier in T1402. SAF notes that character anomalies alone are insufficient, so this is carrier-only supporting context. |

### SAF-T1405 — Tool Obfuscation/Renaming

Tactic: ATK-TA0005 Defense Evasion

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00060](../rules/skill-compromise/ATR-2026-00060-skill-impersonation.yaml) | partial | content | Regexes on tool_name match typosquatted names (filesystem/github/slack/openai/anthropic variants), trust-implying prefixes (official-/verified-), fake version or enhanced suffixes, and description claims of being a replacement for a legitimate tool. These cover the deceptive-name and collision subset of T1405, but not definition-hash drift against an approved binding. |
| [ATR-2026-01775](../rules/tool-poisoning/ATR-2026-01775-semantic-mcp-tool-manifest-poisoning.yaml) | partial | content | The first two conditions match tool descriptions claiming to replace, shadow, act as, or be a drop-in replacement for an official or standard named tool. That is descriptor wording meant to cause misidentification with an expected capability. The other conditions target covert-action directives that are not T1405. |
| [ATR-2026-01301](../rules/tool-poisoning/ATR-2026-01301-tool-description-exclusive-tool-override.yaml) | adjacent | content | Matches tool-description directives such as 'use this tool rather than', 'do NOT use other tools' and 'always use this tool regardless'. These bias preferential selection, but through instruction-bearing semantics, which SAF assigns to T1001 rather than to identity presentation. |

### SAF-T1408 — OAuth Protocol Downgrade

Tactic: ATK-TA0005 Defense Evasion

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02409](../rules/excessive-autonomy/ATR-2026-02409-mcp-async-task-abuse.yaml) | partial | content | One condition requires MCP context markers (mcpServers, oauth-protected-resource, /mcp) within 600 chars of code_challenge_method=plain. That matches the T1408 indicator of an MCP authorization request using plain PKCE. The rule does not cover a missing code_challenge, verifier-without-challenge exchanges, or the S256-to-weaker transition, and the same condition also matches implicit and password grants. |

### SAF-T1407 — Server Proxy Masquerade

Tactic: ATK-TA0005 Defense Evasion

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02107](../rules/context-exfiltration/ATR-2026-02107-ssrf-internal-hostname-domain-allowlist-bypass.yaml) | adjacent | content | Mined from the Apify MCP advisories (GHSA-jwp7-wg77-3w9v and GHSA-6gr2-qh89-hxwm), it matches URLs where a trusted domain sits in the userinfo or as a prefix label, while the real authority is attacker-controlled. This is the URL-authority-confusion element of T1407, without the MCP endpoint identity or relay/credential-reuse signal that SAF requires. |

### SAF-T1503 — Env-Var Scraping

Tactic: ATK-TA0006 Credential Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00115](../rules/context-exfiltration/ATR-2026-00115-env-var-harvesting.yaml) | partial | content, static | One condition matches access to the whole environment object (process.env / os.environ / System.getenv with no subscript or member access), which is server code enumerating its own environment. Other conditions match printenv or bare env piped to a network sink. It is text-only, so a runtime read that never appears as matched code text is out of reach, and its .env file-read condition belongs to T1502. |
| [ATR-2026-02261](../rules/skill-compromise/ATR-2026-02261-code-credential-exfil-chain.yaml) | partial | content, static | Matches one ordered code chain: a secret-named environment variable (os.environ, process.env or getenv) is read into a variable, that same variable is base64- or hex-encoded, and it is then sent out over the network. This covers in-process collection of secret-bearing env values, but only the subset that is encoded and sent; bulk enumeration is not required. |

### SAF-T1501 — Full-Schema Poisoning (FSP)

Tactic: ATK-TA0006 Credential Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02025](../rules/tool-poisoning/ATR-2026-02025-mcp-full-schema-poisoning-nondescription-field.yaml) | adjacent | content, static | Matches read or exfiltration imperatives placed in schema-resident, non-description fields: inputSchema parameter names, extra/note/instructions/_meta fields, and required/default/type fields. That covers the schema-resident path FSP needs, but the rule fires on a single path and does not check for coordinated semantics across two or more definition paths. |

### SAF-T1502 — File-Based Credential Harvest

Tactic: ATK-TA0006 Credential Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00583](../rules/context-exfiltration/ATR-2026-00583-mcp-env-secret-file-read-without-consent.yaml) | partial | content | Matches a read or fs tool call, in function-call form or as a JSON tool_input path key, whose path argument targets .env, secrets, credentials, .npmrc or .netrc. That is a file-tool read of a credential-bearing ordinary file entering the agent workflow, limited to that fixed set of file names. |
| [ATR-2026-01988](../rules/context-exfiltration/ATR-2026-01988-t1005-agent-local-data-staging-exfil.yaml) | partial | content | Matches cat/head/base64-style reads of SSH keys, AWS credentials, .env, docker or kube config in content or tool_args, but only when piped or redirected to curl, wget, nc or DNS tools. The credential-file read is caught only together with follow-on exfiltration. |
| [ATR-2026-02684](../rules/context-exfiltration/ATR-2026-02684-modern-credential-store-file-argument.yaml) | partial | content | Matches a serialized file-tool call (read_file, attach_file, upload_file and similar) whose quoted path argument is a modern credential store: gh hosts.yml, gcloud credentials, rclone.conf, .pypirc, cargo or terraform tokens, Azure token caches, or the Kubernetes service-account token. That is a bounded set of credential files read through an agent filesystem tool. |

### SAF-T1504 — Token Theft via API Response

Tactic: ATK-TA0006 Credential Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-01961](../rules/context-exfiltration/ATR-2026-01961-meta-ads-mcp-unauth-token-leak.yaml) | partial | content | Conditions match a JSON-RPC response request_url to graph.facebook.com that carries an embedded access_token, plus the unauthenticated tools/call get_ad_accounts request. That is the Meta Ads advisory SAF cites, where a reusable token reaches an unauthorized caller, but it is specific to one vendor. |
| [ATR-2026-00150](../rules/context-exfiltration/ATR-2026-00150-credential-in-tool-response.yaml) | adjacent | content | Matches PEM private keys and token formats (sk-proj/ant/live, ghp_, gho_, glpat-, xox*) in tool-response content. That covers the reusable-token-in-result part for those token classes, but it cannot evaluate whether the recipient is authorized. |
| [ATR-2026-01948](../rules/context-exfiltration/ATR-2026-01948-netlicensing-mcp-product-number-path-traversal-token-leak.yaml) | adjacent | content | Matches product_number=../token or %2e%2e/token traversal payloads that send the netlicensing-mcp request to the /token endpoint, skipping the server's token redaction so the raw API key lands in the tool result. The rule detects the request that causes the leak, not the response itself, and only for one server. |

### SAF-T1505 — In-Memory Secret Extraction

Tactic: ATK-TA0006 Credential Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00524](../rules/context-exfiltration/ATR-2026-00524-claude-code-anthropic-base-url-credential-exfil.yaml) | partial | content, static | Matches repository settings or env assignments that point ANTHROPIC_BASE_URL at a host outside the allowlist, a public IP, or plain http. That untrusted config makes the agent runtime send its in-memory API key to an external recipient, but only for this one configuration vector. |
| [ATR-2026-02262](../rules/context-exfiltration/ATR-2026-02262-env-resolution-credential-exfil.yaml) | partial | content | Requires a credential field whose value is the literal env:VARNAME string, next to a base_url pointing to a non-first-party, non-internal host. That is SAF's in-scope case of an attacker-controlled reference resolved against the host process environment and sent to an external destination, limited to the env: syntax. |
| [ATR-2026-02373](../rules/context-exfiltration/ATR-2026-02373-langsmith-prompt-manifest-baseurl-exfil.yaml) | partial | content | Matches a deserialized prompt manifest that sets secrets_from_env=true together with a base_url, openai_api_base or azure_endpoint override to a non-major-cloud, non-internal host. That is live environment secrets resolved and sent to an untrusted destination, limited to the LangSmith manifest shape. |

### SAF-T1507 — Authorization Code Interception

Tactic: ATK-TA0006 Credential Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02409](../rules/excessive-autonomy/ATR-2026-02409-mcp-async-task-abuse.yaml) | adjacent | content | Two conditions match MCP OAuth exchanges that use code_challenge_method=plain, implicit or password grants, and registrations or metadata with wildcard or userinfo-confusion redirect URIs or plaintext/raw-IP authorization servers. These line up with SAF's non-S256 PKCE and redirect-validation indicators. The rule does not check verifier failure or code reuse, and its other conditions cover unrelated task abuse. |

### SAF-T1506 — Infrastructure Token Theft

Tactic: ATK-TA0006 Credential Access

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00013](../rules/tool-poisoning/ATR-2026-00013-tool-ssrf.yaml) | partial | content | Its tool_args conditions match requests to AWS IMDS credential paths (/latest/meta-data, iam/security-credentials, X-aws-ec2-metadata-token), the GCP /computeMetadata/v1 path with the Metadata-Flavor header, and Azure metadata. That is the metadata-service request path of infrastructure token theft. The rule's other SSRF branches (shorteners, loopback encodings) fall outside this technique, and the rule never confirms that a credential was acquired or transferred. |
| [ATR-2026-01605](../rules/context-exfiltration/ATR-2026-01605-ssrf-aws-metadata-endpoint.yaml) | partial | content | It requires 169.254.169.254 as an HTTP fetch target with a path, or the canonical /latest/(meta-data\|dynamic\|user-data\|api/token) path, in tool_args or user_input. That covers only the AWS IMDS request branch of the technique, not Kubernetes service-account tokens, environment-variable credentials, or the outbound transfer. |
| [ATR-2026-01946](../rules/context-exfiltration/ATR-2026-01946-cloud-metadata-ssrf-ip-encoding-bypass.yaml) | partial | content | It matches IPv6-transition, integer, hex and octal encodings of the 169.254.169.254 metadata IP inside a URL-fetch context. That is a bounded evasion variant of the metadata-service request vector, with no observation of token acquisition. |
| [ATR-2026-02684](../rules/context-exfiltration/ATR-2026-02684-modern-credential-store-file-argument.yaml) | partial | content | Its conditions match a file-tool argument whose value is the in-pod /var/run/secrets/kubernetes.io/serviceaccount/token, along with gcloud and Azure token caches. That matches the projected service-account volume read in SAF-T1506. Its other stores (gh hosts.yml, pypirc, cargo) are developer secrets outside this technique, and the rule does not observe exfiltration. |

### SAF-T1602 — Tool Enumeration

Tactic: ATK-TA0007 Discovery

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00504](../rules/context-exfiltration/ATR-2026-00504-tool-and-function-capability-enumeration.yaml) | adjacent | content | Its user_input regexes match agent-directed requests for a complete list of tools or functions and for a named tool's parameters. That shows intent to inventory tool definitions through the model rather than through an observed tools/list call. |
| [ATR-2026-01303](../rules/tool-poisoning/ATR-2026-01303-tool-schema-enumeration-social-engineering.yaml) | adjacent | content | Its patterns match demands for the agent's full tool list, internal or admin functions, and every operation's input schema, including a fake SYSTEM VERBOSE directive asking for INPUT_SCHEMA. The goal is the same tool-definition catalog, but the rule sees a conversational extraction request, not the tools/list JSON-RPC request that defines the technique. |

### SAF-T1603 — System Prompt Disclosure

Tactic: ATK-TA0007 Discovery

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00020](../rules/context-exfiltration/ATR-2026-00020-system-prompt-leak.yaml) | partial | content | Its agent_output conditions match responses that emit system-prompt content: a 'system prompt:' label, raw &lt;&lt;SYS>>/&lt;\|im_start\|>system delimiters, 'you are a helpful assistant' preambles, and 'my instructions are'. This sits on the response side of the disclosure boundary. It relies on generic leak markers rather than overlap with the protected prompt or a canary, and it has no authorization context. |
| [ATR-2026-00424](../rules/context-exfiltration/ATR-2026-00424-nl-system-prompt-leak.yaml) | adjacent | content | It matches leak, reveal or verbatim verbs aimed at the system, developer or operator prompt or hidden instructions, plus 'repeat everything above', anywhere in content such as skill or tool text. That is the request that delivers the technique. SAF makes unauthorized recovery of the instruction content the defining observable, and the rule does not observe the disclosed content. |
| [ATR-2026-00505](../rules/context-exfiltration/ATR-2026-00505-system-prompt-extraction-instruction-dump-request.yaml) | adjacent | content | It matches dump, relay or reveal verbs aimed at 'your instructions/system prompt/initial context', verbatim-without-omission demands, and requests to embed the system instructions in an email reply or document. That is the extraction request that delivers the technique; it does not see the disclosed instructions, which SAF makes the defining observable. |
| [ATR-2026-00514](../rules/context-exfiltration/ATR-2026-00514-system-prompt-extraction.yaml) | adjacent | content | Its user_input regexes match targeted verbatim or word-for-word requests for the system prompt or initial instructions, 'repeat everything above including the system' requests, debug-mode framing, and 'begin your response with my system prompt' forcing. That covers the request-elicitation delivery step of the primary vector, not confirmed recovery of instruction content. |

### SAF-T1605 — Capability Mapping

Tactic: ATK-TA0007 Discovery

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00491](../rules/excessive-autonomy/ATR-2026-00491-garak-agent-breaker-markdown-just-raw-json.yaml) | adjacent | content | It matches requests for a JSON or structured list of the agent's tools and capabilities, and requests to analyze each available tool for exploits or bypasses. That parallels mapping capabilities for follow-on selection, but it is model-mediated and does not observe server/discover or the list-method sequence. |
| [ATR-2026-01303](../rules/tool-poisoning/ATR-2026-01303-tool-schema-enumeration-social-engineering.yaml) | adjacent | content | It matches demands for a JSON array of every operation with its inputs mapped to types and schemas. That supports building a capability map, but it is a conversational extraction attempt rather than the advertised-metadata discovery the technique defines. |
| [ATR-2026-01772](../rules/context-exfiltration/ATR-2026-01772-semantic-internal-state-recon.yaml) | adjacent | content | Its conditions match requests to list internal, hidden or admin tools and endpoints with their parameters, and per-tool parameter discovery. That is reconnaissance context for capability mapping, but it does not observe protocol-level enumeration under an MCP request identity. |

### SAF-T1606 — Directory Listing via File Tool

Tactic: ATK-TA0007 Discovery

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02023](../rules/tool-poisoning/ATR-2026-02023-escaperoute-filesystem-mcp-prefix-bypass.yaml) | adjacent | content | Regexes require a Filesystem-MCP operation (list_directory/directory_tree/read_file etc.) on an allow_dir sibling path (CVE-2025-53110 prefix bypass). SAF-T1606 names that CVE only as an enabling boundary-bypass neighbor; the rule does not detect directory enumeration itself. |

### SAF-T1701 — Cross-Tool Contamination

Tactic: ATK-TA0008 Lateral Movement

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00550](../rules/prompt-injection/ATR-2026-00550-untrusted-retrieval-to-privileged-tool.yaml) | partial | runtime | The trace forbid primitive fires when a TOOL span with privilege write/destructive/exfil is preceded in the same trace by a RETRIEVER span with source.trust=untrusted. This matches the untrusted-source-result to distinct high-impact call sequence, but it is temporal rather than causal, limited to RETRIEVER sources, and ignores user intent and approval. |
| [ATR-2026-00584](../rules/prompt-injection/ATR-2026-00584-indirect-injection-via-tool-response.yaml) | adjacent | content | Matches a tool/API result blob followed by an injected 'as an additional step / IMPORTANT!!! you must' imperative to send/transfer/delete toward a destination. This captures the instruction-bearing source result only, not the causally linked cross-tool call. |
| [ATR-2026-02403](../rules/tool-poisoning/ATR-2026-02403-mcp-external-content-missing-spotlighting.yaml) | adjacent | content | Matches tool_response forge content (PR/issue description, comment, wiki) carrying hidden HTML-comment imperatives such as 'you must call/fetch/post'. That is the adversary-influenced source-tool result from T1701's collaborative-content vector, but no later distinct-tool call is observed. |

### SAF-T1703 — Tool-Chaining Pivot

Tactic: ATK-TA0008 Lateral Movement

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00550](../rules/prompt-injection/ATR-2026-00550-untrusted-retrieval-to-privileged-tool.yaml) | partial | runtime | Trace rule: an untrusted RETRIEVER span followed in the same trace by a write/destructive/exfil TOOL span covers the upstream-result to second-boundary privileged call shape. It does not check user-intent support, approval state, distinct server identity or causal linkage. |
| [ATR-2026-00161](../rules/tool-poisoning/ATR-2026-00161-important-tag-cross-tool-shadowing.yaml) | adjacent | content | Matches tool-description directives aimed at a co-installed tool ('side effect on the also present send_email tool') and &lt;IMPORTANT> hidden directives, which is T1703's malicious tool-description vector. It sees only the delivery metadata, not the induced call to the other tool. |
| [ATR-2026-00584](../rules/prompt-injection/ATR-2026-00584-indirect-injection-via-tool-response.yaml) | adjacent | content | Matches injected 'as an additional step you must send/transfer to &lt;destination>' after a tool result. This is the upstream instruction that would drive a pivot, not the pivot call itself. |
| [ATR-2026-02403](../rules/tool-poisoning/ATR-2026-02403-mcp-external-content-missing-spotlighting.yaml) | adjacent | content | Detects attacker-authored repository or issue content returned by a read tool with hidden imperatives to call/fetch/post via another capability. That is the upstream retrieved-object influence, without the later out-of-intent call. |

### SAF-T1704 — Compromised-Server Pivot

Tactic: ATK-TA0008 Lateral Movement

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00434](../rules/tool-poisoning/ATR-2026-00434-mcp-remote-authorization-endpoint-command-injection.yaml) | partial | content | Matches shell metacharacters ($(), backticks, &&, \|) inside the authorization_endpoint and other OAuth metadata URLs returned by an MCP server. This is the CVE-2025-6514 client-implementation pivot that T1704 lists as an attack vector, so it covers that bounded subset but not metadata-driven cross-server pivots. |
| [ATR-2026-00161](../rules/tool-poisoning/ATR-2026-00161-important-tag-cross-tool-shadowing.yaml) | adjacent | content | The cross-tool shadowing condition flags server-supplied tool descriptions that redirect a co-installed tool ('also present send_email tool'), matching T1704's cross-server metadata influence vector. It does not observe the resulting different-server action or a catalog change. |
| [ATR-2026-01306](../rules/tool-poisoning/ATR-2026-01306-mcp-oauth-command-injection.yaml) | adjacent | content | Matches $()/backtick/pipe command substitution in the userinfo part of an MCP OAuth authorize/token URL that a malicious server hands to a vulnerable client. It covers the same server-to-client-host execution pivot class, limited to that URL shape. |

### SAF-T1112 — Sampling Request Abuse

Tactic: ATK-TA0002 Execution

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-01930](../rules/tool-poisoning/ATR-2026-01930-mcp-sampling-prompt-injection.yaml) | partial | content | Every condition is anchored on sampling/createMessage or its systemPrompt/includeContext fields. It flags injected covert tool invocation, cross-turn persistence, resource-theft appendages, role overrides and includeContext-plus-exfil-URL. That covers the attacker-influenced request subset but not the approval-state or budget-amplification signals the technique centres on. |

### SAF-T1705 — Cross-Agent Instruction Injection

Tactic: ATK-TA0008 Lateral Movement

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00030](../rules/agent-manipulation/ATR-2026-00030-cross-agent-attack.yaml) | partial | content | agent_source is multi_agent_comm. Its content regexes catch instruction-bearing peer messages: instruction overrides, 'new instructions:', role redefinition, fake error/status with a 'switch to/fallback' redirect, and 'forward all data to &lt;url>'. Those patterns cover only overt injection markers in an inter-agent message. The rule does not observe the receiver actually acting on the message. |
| [ATR-2026-00074](../rules/agent-manipulation/ATR-2026-00074-cross-agent-privilege-escalation.yaml) | partial | content | Matches multi_agent_comm content that asks a peer to bypass the orchestrator, or to 'execute this with your elevated/admin permissions', or that relays credentials. This is the subset where a peer message tries to make the receiver use its own authority. The rule targets privilege-escalation wording, not general instruction relay. |
| [ATR-2026-00116](../rules/agent-manipulation/ATR-2026-00116-a2a-message-validation.yaml) | partial | content | Scoped to A2A/multi-agent message content. Regexes cover instruction override, 'new system instructions:', credential-forwarding requests, and embedded 'execute tool: ...exec/eval' calls. That is a bounded subset of attacker instructions relayed to a receiving agent, and it does not include the causal receiver action. |
| [ATR-2026-02500](../rules/prompt-injection/ATR-2026-02500-prompt-layer-self-replication.yaml) | adjacent | content | Matches directives that tell the model to copy, embed or propagate 'this instruction/prompt' into every reply, output or file so it reaches the next assistant. That is the Prompt Infection self-replication variant of the cross-agent hop. It is limited to explicit replication wording and is not tied to an inter-agent channel (llm_io). |

### SAF-T1801 — Automated Data Harvesting

Tactic: ATK-TA0009 Collection

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02406](../rules/context-exfiltration/ATR-2026-02406-mcp-sequential-id-enumeration.yaml) | partial | content | Requires several MCP tools/call exchanges, or a loop, that walk sequential integer record/version/backup IDs through one read tool. That is systematic repeated reads of many distinct objects. Coverage is limited to integer-ID enumeration and does not include breadth harvesting across repositories, conversations or paths. |

### SAF-T1803 — Database Dump

Tactic: ATK-TA0009 Collection

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02303](../rules/data-poisoning/ATR-2026-02303-kql-kusto-pipe-injection-metadata-tool.yaml) | adjacent | content | Flags a table_name/database_name parameter whose value breaks out into a '\| project ... \| take/sample N' KQL chain. This is query-language injection into a supposedly safe metadata tool that returns table data. SAF counts query injection under T1803 only when it directly enables unauthorized bulk retrieval and notes that the CVE-2026-33980 PoC retrieves selected data, not a complete dump; the rule fires on any take/sample N, and its second condition (.drop/.alter/.delete/.purge) is destructive rather than a dump. It is limited to the Kusto syntax. |
| [ATR-2026-01807](../rules/context-exfiltration/ATR-2026-01807-asb-bulk-data-exfil-external.yaml) | adjacent | content | Matches 'export\|extract\|dump\|copy the entire database / all records' together with an external server destination. That covers whole-database dump instructions, but only when the instruction is paired with an outbound target, which overlaps follow-on exfiltration. |
| [ATR-2026-02233](../rules/tool-poisoning/ATR-2026-02233-unscoped-destructive-db-request-nl.yaml) | adjacent | content | The condition '(show\|list\|dump\|export\|display) all records for all users' flags an unscoped mass-disclosure database request aimed at an agent with DB tools. That is the delivery of a dump-equivalent operation. It does not observe the export call, result size or approval state. |

### SAF-T1804 — API Data Harvest

Tactic: ATK-TA0009 Collection

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02406](../rules/context-exfiltration/ATR-2026-02406-mcp-sequential-id-enumeration.yaml) | partial | content | Detects repeated MCP tools/call reads that iterate integer record/backup/version IDs, including loop constructs and 4+ sequential calls. This is enumeration-driven retrieval through a read-path authorization weakness (CVE-2026-54052 cross-tenant IDOR). Pagination, record-count and byte thresholds are not covered. |
| [ATR-2026-02531](../rules/privilege-escalation/ATR-2026-02531-kusto-query-injection-outbound-reach.yaml) | partial | content | Matches an MCP table_name/database_name argument carrying a pipe followed by a union, search, externaldata, evaluate or .export operator. That is the ADX query-construction injection (CVE-2026-33980) that SAF cites for this technique, where the tool reads beyond the single declared table. The volume and breadth shape is not observed. |
| [ATR-2026-01602](../rules/privilege-escalation/ATR-2026-01602-sql-injection-union-select-exfil.yaml) | adjacent | content | Detects UNION SELECT injection in data-query tool arguments that retrieves records from tables outside the intended query. This covers the query-construction-weakness vector of API/DB harvest, without the discovery-to-read sequence or volume thresholds. |

### SAF-T1910 — Covert Channel Exfiltration

Tactic: ATK-TA0010 Exfiltration

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02190](../rules/context-exfiltration/ATR-2026-02190-dns-exfiltration-ping-dig-encoded-subdomain.yaml) | partial | content | Matches ping/dig/nslookup commands whose leftmost hostname label carries an encoded blob or a credential prefix (AKIA, sk-, ghp_, xox). That covers the DNS-lookup covert carrier, where secret data leaves via an innocuous-looking diagnostic action. Other carriers are not covered. |
| [ATR-2026-02304](../rules/context-exfiltration/ATR-2026-02304-preapproved-domain-encoded-path-exfil.yaml) | partial | content | Matches a fetch/WebFetch URL to an allowlisted domain (huggingface.co/hf.co) whose path carries a base64 segment. This is the carrier itself: data hidden in an apparently legitimate, pre-approved request whose disclosure purpose is concealed. It is bounded to that domain pair. |

### SAF-T1911 — Parameter Exfiltration

Tactic: ATK-TA0010 Exfiltration

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02304](../rules/context-exfiltration/ATR-2026-02304-preapproved-domain-encoded-path-exfil.yaml) | partial | content | Matches a WebFetch/fetch url argument to huggingface.co/hf.co whose path holds a 16+ char base64 run ending in '=' padding. That is accessible data encoded into a tool-call argument that goes to an attacker-observable destination. It is bounded to one allowlisted-domain channel and to base64 encoding. |
| [ATR-2026-02570](../rules/context-exfiltration/ATR-2026-02570-wallet-secret-material-in-agent-tool-payload.yaml) | partial | content | The regexes require a seed-phrase label set to 12-24 BIP-39-shaped words, or a wallet/keypair private key set to a quoted 32+ char high-entropy value, inside an MCP tool payload or argument (TP: seed_phrase in a tool argument). This catches sensitive values in the argument object, but only for wallet secrets, and it does not check destination trust. |

### SAF-T2101 — Data Destruction

Tactic: ATK-TA0040 Impact

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00549](../rules/privilege-escalation/ATR-2026-00549-destructive-tool-without-human-approval.yaml) | partial | runtime | Trace require-primitive that fires when a TOOL span with tool.privilege=destructive (drop_table, file.delete, force_push) has no prior human-approval span. This mirrors SAF's 'destructive operation with approval absent' branch, but it depends on privilege labeling and does not establish adversarial intent or target criticality. |
| [ATR-2026-01601](../rules/privilege-escalation/ATR-2026-01601-sql-injection-destructive-ddl.yaml) | partial | content | Matches tool_args where a string terminator plus ';' or '--' is followed by DROP TABLE/DATABASE, TRUNCATE or DELETE FROM. That is an injected destructive operation against stored data through a database tool argument, limited to the SQL-injection form. |
| [ATR-2026-00716](../rules/tool-poisoning/ATR-2026-00716-ipi-data-destruction-carrier.yaml) | adjacent | content | Matches injected content telling the agent to delete, purge or erase files, documents or records (medical records, cloud drive or EHR files, 'Delete the file with ID'). This captures the adversarial destruction objective that SAF couples to the delete operation, but it sees the instruction, not the executed tool call. |

### SAF-T1903 — Malicious Server Control Channel

Tactic: ATK-TA0011 Command and Control

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02600](../rules/skill-compromise/ATR-2026-02600-in-source-reverse-shell-assembly.yaml) | partial | static | Requires all three in package source: an outbound socket connect to a raw host/port, std fd rebinding (dup2/pipe to stdin), and an interactive shell spawn. That is the bidirectional operator-channel code shipped in malicious MCP-server packages (cites mcp-runcommand-server). It is a static precursor only. It does not see the runtime server-role egress, and it misses WebSocket or custom-transport command channels. |

### SAF-T2104 — Fraudulent Transactions

Tactic: ATK-TA0040 Impact

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00098](../rules/excessive-autonomy/ATR-2026-00098-unauthorized-financial-action.yaml) | adjacent | content, runtime | Fires on value-bearing tool calls by tool_name (send_money, wire_transfer, stripe_charge, etc.) and on tool_args carrying amount/currency/recipient or action=pay/transfer, plus agent text confirming a payment. It catches the value-bearing action itself but does not compare it against a bound approval, and it fires on every legitimate payment call, so it is supporting context rather than a bounded subset. |
| [ATR-2026-00708](../rules/excessive-autonomy/ATR-2026-00708-ipi-financial-transfer-unauthorized.yaml) | adjacent | content | Regexes over untrusted content for instructions to initiate a payment or transfer from an account to a payee/wallet, IBAN-format destinations, 'send as much money as possible / full balance' to an account ID, or redirecting a recurring-payment recipient. These show the injected instruction, not the transaction it may cause. |
| [ATR-2026-00860](../rules/context-exfiltration/ATR-2026-00860-indirect-pi-financial-transfer-hijack.yaml) | adjacent | content | Requires an 'ignore all previous instructions' override followed by a payment or wire-transfer initiation with an amount and an account number or payee ID. It shows a narrow, carrier-specific injected instruction, not the transaction it may cause. |

### SAF-T2105 — Disinformation Output

Tactic: ATK-TA0040 Impact

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00380](../rules/agent-manipulation/ATR-2026-00380-fake-citation-biased-information-mandate.yaml) | adjacent | content | Matches mandates to fabricate citations ('make them up if you have to') combined with non-objective or one-sided framing. This is a prompt-side signal of fabricated provenance, not evidence that deceptive output reached a downstream consumer. |
| [ATR-2026-01841](../rules/model-abuse/ATR-2026-01841-deepfake-disinformation.yaml) | adjacent | content | Matches requests to create or spread a deepfake and post it 'claiming it's a real/authentic video'. That is the direct deceptive-content-production and false-provenance vector, matched on the request text only. |
| [ATR-2026-01906](../rules/prompt-injection/ATR-2026-01906-content-manipulation.yaml) | adjacent | content | BIPIA invariants match injected text telling the model to add or integrate fabricated, false, misleading or baseless claims or statistics into its response. That is the attacker-directed false-answer vector; the deceptive output itself is not checked. |

### SAF-T2103 — Code Sabotage

Tactic: ATK-TA0040 Impact

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00512](../rules/prompt-injection/ATR-2026-00512-rules-file-backdoor-injection.yaml) | adjacent | content | Matches instructions to modify AI-coding rules files (.cursorrules, copilot-instructions.md, CLAUDE.md) with exfiltration or script injection. It also matches 'whenever generating code always include &lt;script>/eval/remote import' and directives to include malicious dependencies. This is the rules-file vector by which a coding agent plants behavior-changing code, but the resulting repository diff is not observed. |

### SAF-T2106 — Context Memory Poisoning via Vector Store Contamination

Tactic: ATK-TA0040 Impact

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00551](../rules/privilege-escalation/ATR-2026-00551-cross-conversation-memory-write.yaml) | partial | memory, runtime | A trace forbid primitive fires when a memory.write/vector_store.upsert/rag.ingest tool span targets a conversation ID different from the current one. That is the write-boundary crossing into persistent memory; later retrieval of the record is not correlated. The rule's maturity is draft. |
| [ATR-2026-01774](../rules/data-poisoning/ATR-2026-01774-semantic-rag-memory-poisoning.yaml) | adjacent | content | Inspects retrieved or remembered content (tool_response) for AgentPoison trigger-activation phrases, embedded destructive 'Solution: DeleteDB' entries, chained [user_memory=] injections, and forged prior-conversation records. It covers the retrieval-side appearance of poisoned records, not the unauthorized write. |

### SAF-T3001 — RAG Backdoor Attack

Tactic: ATK-TA0040 Impact

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-01774](../rules/data-poisoning/ATR-2026-01774-semantic-rag-memory-poisoning.yaml) | adjacent | content | Conditions match AgentPoison-style trigger-gated passages in retrieved content ('Because there is &lt;trigger> in the question, this means we...', &lt;adversarial_trigger_tokens>) carrying an attacker-selected action. That is a bounded signature of trigger-conditioned planted passages; corpus insertion and integrity are not observed. |

### SAF-T2107 — AI Model Poisoning via MCP Tool Training Data Contamination

Tactic: ATK-TA0042 Resource Development

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00073](../rules/model-security/ATR-2026-00073-malicious-finetuning-data.yaml) | adjacent | content | Matches poisoned fine-tuning records (system-role safety-bypass examples, trigger-response backdoor patterns, completions teaching code execution or credential disclosure). It does not establish lineage from an MCP tool result into the training corpus, so it is auxiliary context only. |

### SAF-T1805 — Context Snapshot Capture

Tactic: ATK-TA0009 Collection

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00449](../rules/context-exfiltration/ATR-2026-00449-spring-ai-chatmemory-cross-user-leak.yaml) | adjacent | content, memory, static | Several conditions match retrieved-memory or audit lines that print a retrieved conversation_id or memory-owner id next to the active session or user id (the regexes do not compare the two values), two user tags in one advisor-injected window, or a shared or wildcard-tenant ChatMemory config. That is cross-owner retrieval of conversation state, limited to the Spring AI ChatMemory family. |
| [ATR-2026-00548](../rules/context-exfiltration/ATR-2026-00548-cross-agent-session-context-leak.yaml) | adjacent | identity, runtime | A trace invariant fires when session.id or user.id drifts across spans of one delegation chain, meaning a downstream agent processed another session's or user's data. This is cross-owner context-scope evidence, but it does not observe a snapshot, history or checkpoint read or export. |

### SAF-T1802 — File Collection

Tactic: ATK-TA0009 Collection

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-02023](../rules/tool-poisoning/ATR-2026-02023-escaperoute-filesystem-mcp-prefix-bypass.yaml) | partial | content | Requires a filesystem-MCP operation (read_file, list_directory, etc.) on a path that extends the allowed-directory token into a sibling directory, the CVE-2025-53110 colliding-prefix root escape. That is one bounded boundary-bypass variant of file collection that SAF cites. |
| [ATR-2026-02250](../rules/context-exfiltration/ATR-2026-02250-attachment-upload-tool-arbitrary-file-read.yaml) | partial | content | Matches attachment, upload or file_path tool arguments that target /proc/self/environ, /etc/passwd or shadow, or SSH keys, or that start with two or more ../ traversals. That is the request side of retrieving or attaching files outside the approved boundary through a file-capable tool. A successful byte return is not verified. |
| [ATR-2026-02700](../rules/privilege-escalation/ATR-2026-02700-percent-encoded-path-traversal-tool-argument.yaml) | partial | content | Matches a named file or path tool argument whose whole value is two or more percent-encoded ../ segments resolving to a credential or system file (.ssh, .aws, .env, passwd). This covers the encoded-traversal subset of retrieval beyond the approved root. |

### SAF-T1902 — Response-Borne Covert Channel

Tactic: ATK-TA0011 Command and Control, ATK-TA0010 Exfiltration

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00261](../rules/context-exfiltration/ATR-2026-00261-markdown-image-exfiltration.yaml) | partial | content | Matches tool or LLM response text with a markdown image whose query string carries a base64 payload of 60+ characters or a data placeholder, plus templates telling the model to swap markers for encoded conversation data. That is a renderer-active, data-bearing carrier in a response, but the receiver fetch is not correlated. |
| [ATR-2026-00258](../rules/prompt-injection/ATR-2026-00258-unicode-tag-injection.yaml) | adjacent | content | Flags Unicode Tag-block characters (raw or escaped) in tool responses, one of the invisible carriers SAF names. Detection is carrier-only and aimed at hidden instructions (prompt injection), with no receiver path, so it is supporting context only. |
| [ATR-2026-01453](../rules/context-exfiltration/ATR-2026-01453-markdown-image-base64-exfil-carrier.yaml) | adjacent | content | Matches markdown image URLs with [QUERY] or other exfil placeholder query parameters, 'where QUERY is the base64 encoded', and instructions to embed a markdown image in the reply. That is the injected template that makes the model emit a concealed, data-bearing image locator in its response. |

### SAF-T1913 — HTTP POST Exfil

Tactic: ATK-TA0010 Exfiltration

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-01300](../rules/tool-poisoning/ATR-2026-01300-mcp-notes-param-chat-history-exfil.yaml) | adjacent | content | Matches tool-description text telling the model to fill a 'notes' parameter with the full chat history, including context-offload framing. That is the poisoned-description prerequisite that causes sensitive data to be placed in a remote server's tool arguments, not the POST transfer itself. |
| [ATR-2026-02376](../rules/tool-poisoning/ATR-2026-02376-tool-description-conversational-trigger-history-exfil.yaml) | adjacent | content | Matches a tool description that defines a common user phrase as a trigger to forward or include the full conversation history in a call. That is a delivery precondition for history landing in tool arguments sent to the server, with no observation of the request. |

### SAF-T1914 — Tool-to-Tool Exfil

Tactic: ATK-TA0010 Exfiltration

| ATR rule | Relationship | Modalities | Evidence |
|---|---|---|---|
| [ATR-2026-00857](../rules/context-exfiltration/ATR-2026-00857-indirect-pi-cloud-file-exfil.yaml) | adjacent | content | Matches injected instructions to retrieve files from Google Drive, OneDrive or Dropbox and send them as attachments or to an external email address, including bulk send-then-delete. That is a cloud-storage source to email sink transition expressed in instruction text, without lineage telemetry. SAF makes source-to-sink data lineage the defining observable and treats injection as delivery. |
| [ATR-2026-01964](../rules/context-exfiltration/ATR-2026-01964-langchain-gmailtoolkit-indirect-prompt-injection-email-exfil.yaml) | adjacent | content | Matches GmailToolkit text that names the payments-noreply email and then a send or draft without confirmation or to an external address, the CVE-2025-46059 framing, or send_gmail_message/create_gmail_draft to an external address with a suppress-confirmation directive. Only the first condition names a source; none observes the data lineage SAF makes the defining observable, so this is supporting context for the CVE-2025-46059 flow. |
| [ATR-2026-00161](../rules/tool-poisoning/ATR-2026-00161-important-tag-cross-tool-shadowing.yaml) | adjacent | content | Matches tool descriptions with &lt;IMPORTANT> hidden read/send directives, cross-tool shadowing wording, credential-file references and pre-invocation 'read file' directives. That is the poisoned-description delivery vector for tool-to-tool exfil, not the data-bearing sink call itself. |
| [ATR-2026-00550](../rules/prompt-injection/ATR-2026-00550-untrusted-retrieval-to-privileged-tool.yaml) | adjacent | runtime | A trace forbid fires when a TOOL span with privilege write, destructive or exfil is preceded in the same trace by a RETRIEVER span marked untrusted. That captures the injected-source to outbound-sink sequence, but only by time order, not by data lineage of a sensitive result. |

## Techniques with no reviewed ATR rule

- SAF-T1004 — Server Impersonation / Name-Collision
- SAF-T1007 — OAuth Authorization Phishing
- SAF-T1207 — Hijack Update Mechanism
- SAF-T1009 — Authorization Server Mix-up
- SAF-T1103 — Fake Tool Invocation (Function Spoofing)
- SAF-T1110 — Multimodal Prompt Injection via Images/Audio
- SAF-T1202 — OAuth Token Persistence
- SAF-T1203 — Backdoored Server Binary
- SAF-T1206 — Credential Implant in Config
- SAF-T1304 — Credential Relay Chain
- SAF-T1308 — Token Scope Substitution
- SAF-T1406 — Metadata Manipulation
- SAF-T1401 — Line Jumping
- SAF-T1403 — Consent-Fatigue Exploit
- SAF-T1404 — Response Tampering
- SAF-T1601 — MCP Server Enumeration
- SAF-T1604 — Server Version Enumeration
- SAF-T1706 — OAuth Token Pivot Replay
- SAF-T1707 — CSRF Token Relay
- SAF-T1904 — Chat-Based Backchannel
- SAF-T1915 — Cross-Chain Laundering via Bridges/DEXs
- SAF-T2102 — Service Disruption
- SAF-T1901 — Outbound Webhook C2
