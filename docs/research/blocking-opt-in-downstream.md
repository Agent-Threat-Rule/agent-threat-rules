# Downstream compatibility: what breaks if blocking becomes opt-in

Investigation report. **No production code changed** — measurement and source reading only.

- Baseline commit: `994b01b2b` (`origin/main`, 2026-08-14)
- Branch: `docs/blocking-opt-in-downstream`
- Rules on disk: 784 (`find rules -name "*.yaml" | wc -l`) == `data/stats.json`.rules.total 784 — no drift
- Published npm version at baseline: `agent-threat-rules@3.5.12`
- Prior reports this one builds on: `docs/research/verdict-maturity-audit.md`
  (branch `docs/verdict-maturity-audit`) and `docs/research/dual-channel-audit.md`
  (branch `docs/dual-channel-audit`)
- Probe scripts: `.scratch-downstream/verify-adapters.ts`, `.scratch-downstream/verify-surfaces.ts`
  (uncommitted; listed under "Reproduction")

---

## 0. Conclusion in one paragraph

Of the **33 adopters listed in `ADOPTERS.md`**, **zero** read the verdict channel
(`permissionDecision`) and **zero** read `response.actions`. Every integration that makes a
block/allow decision re-implements its own severity floor over `engine.evaluate()` /
`pyatr.scan()` — the third channel. Making blocking opt-in in the reference engine therefore
changes the behaviour of exactly **three shipped surfaces**, all of them inside this repository:
`atr guard` (the Claude Code PreToolUse hook), the `atr_scan` MCP tool's `verdict.outcome`
field, and the `HookHandler` public API. The risk is not "downstream stops blocking" —
downstream blocking never came from this channel. The risk is **ecosystem inconsistency**: a
sibling repository (`Agent-Threat-Rule/claude-agent-sdk-atr`) ships its own hard-coded
`critical`/`high` → `deny` matrix, so after the change the reference engine and the ATR-authored
SDK hook would disagree about what ATR blocks by default.

The premise being tested — "ATR's own runtime does not actually block" — is **confirmed by
measurement**, and it is stronger than stated: both shipped adapters are inert for all seven
blocking-class actions.

---

## 1. What "blocking becomes opt-in" is taken to mean

The change is not yet specified, so this report evaluates two variants separately. They have
different blast radii and must not be conflated.

| Variant | Change | Surfaces touched |
|---|---|---|
| **V1 — verdict channel** | The hook stops asserting a permission decision unless the operator opts in: omit `hookSpecificOutput.permissionDecision` instead of emitting `deny`/`ask`, and never emit `allow` (an `allow` overrides the host's own prompt, so silence — not `allow` — is the neutral value). Detection output is still emitted. | `src/hook-handler.ts`, `src/verdict.ts`, `src/mcp-tools/scan.ts` |
| **V2 — action channel** | `ActionExecutor` additionally refuses to dispatch INTERRUPT-tier-and-above actions (`block_*`, `quarantine_session`, `reset_context`, `reduce_permissions`, `kill_agent`) without an explicit operator directive. OBSERVE-tier actions (`alert`, `snapshot`, `escalate`, `shadow`) still run. | `src/engine.ts:1668`, `src/action-executor.ts`, `PlatformAdapter` contract |

Where a finding depends on which variant is chosen, both are stated.

---

## 2. Method and controls

Every dynamic claim in §3 and §6 comes from a script that aborts (exit 3) unless a non-trivial
control holds first. This matters because `new ATREngine(...)` does not compile patterns without
`await engine.loadRules()`, and because `HookHandler` **fails open to `allow`** when its engine is
not wired — and `allow` is truthy, so "did I get a value back" is a fake pass.

| Control | Assertion | Measured |
|---|---|---|
| C1 | `engine.loadRules() >= 700` | 784 ✓ |
| C2 | documented-matching payload yields `permissionDecision === 'deny'` | `deny` ✓ |
| C3 | the same evaluation dispatches ≥ 1 action | `["block_tool","alert","escalate","snapshot"]` ✓ |
| C4 | ≥ 1 matched rule actually declares `block_tool` | `ATR-2026-00099` ✓ |
| S-C2 | the `atr_scan` MCP tool reports `verdict.outcome === 'deny'` for that payload | `deny` ✓ |
| S-C3 | that same tool reports ≥ 1 match | `threats_found: 2` ✓ |

Control payload: `google-chrome --no-sandbox &` — the public reproduction case from
`docs/RESPONSE-ACTION-ELIGIBILITY.md` §1a. Static source claims are cited by file and line and
are reproducible with `grep`; nothing in this report rests on recall.

For downstream repositories: source was fetched from the target repository on 2026-08-14, from
`main` for merged PRs and from the PR head SHA for open PRs. Where source could not be read, the
row says so explicitly.

---

## 3. Does ATR's own runtime block anything? (self-verified)

**Claim under test:** `DefaultAdapter` is a no-op, `StdioAdapter`'s blocking methods write to a
private `responseBuffer`, and `flushResponses()` has no callers — therefore "when ATR runs itself,
`block_tool` does nothing".

**Verdict: confirmed, and it is true of all seven blocking-class actions, not just `block_tool`.**

### 3a. Only two adapters exist

```
$ grep -rn "implements PlatformAdapter" src tests examples scripts integrations
src/adapters/stdio-adapter.ts:29:export class StdioAdapter implements PlatformAdapter {
src/adapters/default-adapter.ts:29:export class DefaultAdapter implements PlatformAdapter {
```

### 3b. `flushResponses()` has no callers anywhere in the repository

```
$ grep -rn "flushResponses" . --exclude-dir=node_modules --exclude-dir=.git
docs/RESPONSE-ACTION-ELIGIBILITY.md:78:...
docs/RESPONSE-ACTION-ELIGIBILITY.md:352:...
src/adapters/stdio-adapter.ts:37:  flushResponses(): readonly unknown[] {
```

Two documentation mentions and the definition itself. No caller in `src/`, `tests/`, `bin/`,
`scripts/`, or `integrations/`.

### 3c. Measured: seven blocking methods, zero observable effect

`.scratch-downstream/verify-adapters.ts` calls each blocking method on each adapter with
`process.stdout.write` / `process.stderr.write` intercepted and byte-counted:

| Adapter | stdout bytes | stderr bytes | Return value | Side effect |
|---|---:|---:|---|---|
| `DefaultAdapter` × 7 blocking methods | **0** | **0** | `success: true`, `"[<action>] logged (no-op) for verdict: deny"` | none |
| `StdioAdapter` × 7 blocking methods | **0** | **0** | `success: true`, e.g. `"Tool blocked via stdio protocol"` | 7 entries pushed onto `responseBuffer`, which has no reader |
| `StdioAdapter` × 4 observe methods (`alert`/`snapshot`/`escalate`/`shadow`) | 0 | **315** | `success: true` | stderr lines — the only thing that leaves the process |

The seven blocking-class methods are `blockInput`, `blockOutput`, `blockTool`,
`quarantineSession`, `resetContext`, `reducePermissions`, `killAgent`.

### 3d. End-to-end through the shipped CLI, not a hand-assembled handler

```
$ printf '%s\n' \
  '{"hook":"PreToolUse","tool_name":"Bash","tool_input":{"command":"google-chrome --no-sandbox &"}}' \
  '{"hook":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | npx tsx src/cli.ts guard
```

stdout (what Claude Code reads):

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"DENY: Hidden Capability in MCP Skill [critical/93% confidence] (3 rules matched)"},"atr_decision":"deny","matched_rules":["ATR-2026-00062","ATR-2026-00040","ATR-2026-00099"]}
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"ALLOW: High-Risk Tool Invocation Without Human Confirmation [low/71% confidence] (1 rule matched)"},"atr_decision":"allow","matched_rules":["ATR-2026-00099"]}
```

stderr: one `[atr-guard] Loaded 784 rules` line plus `alert` / `escalate` / `snapshot` JSON.

`grep -c "block_tool"` over both captured streams: **0 and 0**. The `block_tool` dispatched on
line 1 (control C3 proves it ran) leaves no trace on either stream. Process exit code 0.

### 3e. Consequence for risk sizing

Under **V2**, the set of consumers whose behaviour changes is the set of consumers that supply a
custom `PlatformAdapter` with a real enforcement implementation. **No such consumer was found**
— not in this repository, not in any repository listed in `ADOPTERS.md`, and not in any
ATR-organisation repository (§6). So V2's measured blast radius on known consumers is **zero**;
its cost is a contract change for future adapters, not a regression for current ones.

Conversely: the same measurement means the current `response.actions` machinery provides **no
enforcement today**, so making it opt-in removes no protection that anyone is receiving.

---

## 4. Complete adopter inventory (fresh read of `ADOPTERS.md`)

`ADOPTERS.md` at `994b01b2b` — 33 active entries plus 6 removed:

| Tier | Entries |
|---|---:|
| Tier S — standards bodies & frameworks | 5 |
| Tier 1 — production deployments | 3 |
| Tier 2 — open-source tooling & SDK integrations | 13 |
| Tier 3 — documentation references & awesome-lists | 12 |
| Tier 4 — commercial implementations | 0 |
| **Total active** | **33** |
| Removed entries (archived / closed PR / unverifiable) | 6 |

### 4a. Evidence-link drift found while verifying (report, do not silently fix)

Every evidence PR was re-checked with `gh pr view` on 2026-08-14. Three entries do not match
their listed status:

| Entry | `ADOPTERS.md` says | GitHub says (2026-08-14) |
|---|---|---|
| **NVIDIA garak** | Status `in-review`, evidence `NVIDIA/garak#1676` | PR **CLOSED**, not merged. `gh search prs --repo NVIDIA/garak --author eeee2345` returns that PR only — no successor. |
| **NVIDIA NeMo Guardrails** | Status `in-review`, evidence `NVIDIA-NeMo/Guardrails#1992` | PR **CLOSED**. A successor, **#2251, is OPEN** with the same title. The listed evidence link is dead; the adoption claim is still directionally live via #2251. |
| **Microsoft Agent Framework** | `Since: 2026-06-16`, Status `shipped` | PR #6528 merged **2026-07-08**. Shipped is correct; the date is three weeks early. |

Also worth recording, because it changes how "notify the adopters" should be read: **all 33
evidence PRs were opened by the same GitHub account (`eeee2345`)**. `ADOPTERS.md` is a
self-declared register, and it is entirely self-contributed. The one entry with a documented
external owner is AG2, whose entry states the capability is "since maintained by an AG2
maintainer".

---

## 5. Which channel does each integration actually read?

Channel names follow `docs/research/dual-channel-audit.md` §0, with two additions needed to
describe what was actually found:

- **A** — `hookSpecificOutput.permissionDecision` (the verdict channel)
- **B** — `response.actions` dispatched through `ActionExecutor`
- **C** — `match.rule.severity` compared against the consumer's own floor
- **D** — any match at all; severity read only for reporting, never gating
- **E** — the rule YAML schema only (format converters / rule packs; no engine at runtime)
- **F** — none (taxonomy, catalogue, awesome-list, prose)

### 5a. Adapter-tier and code-bearing adopters — source read line by line

| Adopter | Source read (fetched 2026-08-14) | Channel | Decision rule | Affected by V1? | Affected by V2? |
|---|---|---|---|---|---|
| **AG2 (AutoGen)** | `ag2ai/ag2classic@main` `autogen/agentchat/contrib/capabilities/atr_guardrail.py` (304 L) | **C** | `min_severity="low"` default, `action ∈ {allow,warn,block}`; drops flagged LLM inputs, redacts tool outputs | No | No |
| **BerriAI LiteLLM** (#28050, OPEN) | PR head `aa52a34` `litellm/proxy/guardrails/guardrail_hooks/atr/atr.py` (474 L) | **C** | `pyatr` `engine.evaluate()`; `_DEFAULT_SEVERITY_THRESHOLD = "high"`; raises `HTTPException(400)` | No | No |
| **Microsoft Agent Framework** (#6528, MERGED) | `microsoft/agent-framework@main` `python/samples/02-agents/middleware/atr_validation_middleware.py` (180 L) | **D** | `matches[0].rule_id if matches else None` — **blocks on any match, no severity gate**; raises `MiddlewareTermination` before `call_next()` | No | No |
| **OpenAI Guardrails** (#77, OPEN) | PR head `d83d41b` `src/guardrails/checks/text/atr.py` (146 L) | **C** | `pyatr.scan`; `min_severity` default `"medium"`; sets `tripwire_triggered` — the host framework decides the consequence | No | No |
| **rulezet (CIRCL)** (#50, MERGED) | `rulezet/rulezet-core@main` `app/features/rule/rule_format/available_format/atr_format.py` (405 L) | **E** | Parses and validates ATR YAML (`severity` enum, detection block). No engine, no runtime decision | No | No |
| **NVIDIA NeMo Guardrails** (#2251, OPEN; #1992 CLOSED) | PR head `d47e9f5` `nemoguardrails/library/atr/actions.py` (92 L) | **C** | `pyatr.scan`; `rails.config.atr.block_severities`, default `["critical","high"]`; returns `RailOutcome.block()` | No | No |
| **Microsoft PyRIT — dataset** (#1715, MERGED) | `microsoft/PyRIT@main` `pyrit/datasets/seed_datasets/remote/agent_threat_rules_dataset.py` (320 L) | **E** | Loads ATR rules as adversarial seed prompts. No decision at all | No | No |
| **Microsoft PyRIT — scorer** (#1893, OPEN) | PR head `pyrit/score/true_false/agent_threat_rules_scorer.py` (160 L) | **C** | `min_severity="medium"`; true/false score, no enforcement | No | No |
| **Microsoft Agent Governance Toolkit** (#1277, MERGED) | `examples/atr-community-rules/sync_atr_rules.py` (274 L) | **E** | Converts each ATR detection pattern into an AGT policy rule with `"action": "deny"` **hard-coded** and priority from `severity`. **Skips `status == "draft"` and `maturity == "test"`** before converting | No | No |
| **NVIDIA garak** (#1676, CLOSED) | PR head `garak/detectors/atr.py` (233 L) | **E/D** | Consumes a pre-baked `garak/data/atr/rules.json`; the detector loop destructures severity into `_severity` and never uses it | No | No |
| **Cisco AI Defense skill-scanner** (#99, MERGED) | PR file list; ATR rules translated into `skill_scanner/data/packs/atr/signatures/*.yaml` | **E** | ATR rules become Cisco signature-pack entries; Cisco's own scanner decides | No | No |
| **Cisco a2a-scanner** (#14, OPEN) | PR head `a2ascanner/data/packs/atr/pack.yaml` + 6 signature files | **E** | Same shape as skill-scanner | No | No |
| **Cisco mcp-scanner** (#194, OPEN) | PR file list — one YARA rule + tests | **E** | ATR-derived YARA rule; no ATR code | No | No |
| **Gen Digital Sage** (#33, MERGED) | PR head `threats/agent-layer.yaml` (447 L) | **E** | ATR patterns transcribed into Sage's own threat-rule format | No | No |
| **Splunk security_content** (#4128, OPEN) | PR file list — 3 SPL detections + 2 macros | **E** | ATR-derived SPL; no ATR code | No | No |
| **Promptfoo** (#8529, OPEN) | PR head `examples/redteam-atr-mcp-defense/atr-assertion.mjs` (107 L) | **C** | `import { ATREngine } from 'agent-threat-rules'`; `engine.evaluate()`; `FAIL_SEVERITIES = ['critical','high']`; assertion pass/fail | No | No |
| **AMD GAIA** (#1809, MERGED) | `docs/integrations/guard-proxy.mdx` (72 L) | **F (doc)** → points at `Agent-Threat-Rule/atr-lemonade-guard` | Documentation of a pattern; GAIA core takes no dependency. The proxy it links to is analysed in §6 | No | No |
| **SigmaHQ** (#6015, MERGED) | PR is a single README line in the Sigma tools directory | **F** | Cross-listing only | No | No |
| **MISP taxonomies / galaxy** (#323, #1207, MERGED) | `agent-threat-rules/machinetag.json`, `clusters/agent-threat-rules.json` | **F** | Rule-ID taxonomy and threat-intel clusters | No | No |
| **OWASP Agent Security Regression Harness** (#74, MERGED) | 4 scenario YAML files | **F** | ATR-derived regression scenarios | No | No |
| **FINOS Common Cloud Controls** (#986, MERGED) | `catalogs/ai-ml/gen-ai/controls.yaml` | **F** | Guideline mappings | No | No |
| **NIST AI RMF OSCAL** (#338, OPEN) | 2 OSCAL profile XML files | **F** | Catalogue submission | No | No |
| **OpenTelemetry semconv-genai** (#165, OPEN) | `model/agent/registry.yaml` + events | **F** | Proposed attribute names | No | No |
| **Tier 3 awesome-lists** (10 entries) | README list entries | **F** | Link only | No | No |
| **killertcell428/aigis** (#154, MERGED) | `docs/compliance/ATR_CROSSWALK.md` | **F** | ATLAS-axis crosswalk document | No | No |

### 5b. In-repository integrations and adapters — grep matrix

Recount of the previous report's table at this commit, by counting channel markers per file:

```
integrations/goose/scripts/atr_scan.py                verdict=0 actions=0 severity=3
integrations/langchain/langchain_atr_guardrail.py     verdict=0 actions=0 severity=9
integrations/pydantic-ai/pydantic_ai_atr.py           verdict=0 actions=0 severity=12
integrations/rampart/src/atr_rules_evaluator.py       verdict=0 actions=0 severity=12
src/adapters/mastra.ts                                verdict=0 actions=0 severity=5
src/adapters/nemoclaw-preflight.ts                    verdict=0 actions=0 severity=8
src/adapters/openshell-filter.ts                      verdict=0 actions=0 severity=8
```

(`verdict` counts `permissionDecision|evaluateWithVerdict|computeVerdict`; `actions` counts
`.actions|response.actions`.) All seven are channel **C**; none is affected by V1 or V2.

### 5c. The three surfaces that *are* affected

`permissionDecision` appears in exactly six files repository-wide (excluding `node_modules`,
`data/`, `proposals/`, and this report's probe scripts):

```
src/hook-handler.ts
src/quality/action-eligibility.ts
scripts/gate-action-eligibility.ts
tests/claude-code-contract.test.ts
docs/RESPONSE-ACTION-ELIGIBILITY.md
```

| Surface | What changes under V1 | Notes |
|---|---|---|
| **`atr guard`** (`src/cli.ts` `cmdGuard` → `HookHandler`) | The only consumer of channel A. Installed by `atr init` (`src/cli.ts:975` writes `{"type":"command","command":"npx agent-threat-rules guard"}` into `hooks.PreToolUse` of `.claude/settings.local.json`, or `~/.claude/settings.json` with `--global`, `src/cli.ts:980-981`) and documented in `docs/deployment-guide.md:126` ("Option 4: Claude Code Hook"). Under V1 it stops asserting `deny`/`ask` unless opted in — and it must also stop asserting `allow`, which it currently emits on both the clean path and the fail-open error path. | The doc text says "checked against ATR rules in real time", not "blocked", so the prose survives the change; the lane table in `README.md:214` ("Advisory / eval (default)") becomes *true* rather than contradicted. |
| **`atr_scan` MCP tool** (`src/mcp-tools/scan.ts:88-101`) | Emits `verdict.outcome` and `verdict.reason` in its JSON result. Measured: `deny` for the control payload, `allow` for benign text. Under V1 this field's semantics change for every MCP client. | The previous report recorded the MCP server as "no decision, matches only". That is **incomplete** — `handleScan` calls `evaluateWithVerdict()` and surfaces the outcome. Corrected here. The same result also surfaces `recommended_actions: m.rule.response.actions` as advisory data (measured: `["alert","snapshot"]` and `["escalate","alert","snapshot"]` for the control payload). |
| **`HookHandler` public API** | `src/index.ts` re-exports it; any external TypeScript consumer constructing a `HookHandler` sees the contract change. No such external consumer was found (§7). | `tests/claude-code-contract.test.ts:18-24` pins the 1:1 verdict → `permissionDecision` mapping, and `tests/verdict.test.ts:82-89` pins `critical → deny`. Both will need updating; this is expected, not a surprise. |

`atr scan` (CLI) and the GitHub Action are **not** affected: `action.yml` gates on the
`severity` input (default `medium`) and `fail-on-finding` (default `true`), and
`src/cli/scan-handler.ts:132-134` sets `process.exitCode = 1` from `failHits`, a severity count.
Channel C, both.

---

## 6. Consumers that exist but are not in `ADOPTERS.md`

`ADOPTERS.md` is the authoritative register of *declared* adoption, but it is not a complete
register of *code that consumes ATR*. Six additional consumers were found, four of them
ATR-authored. They matter because two of them re-implement the block decision themselves.

| Consumer | Where | Channel | Decision rule | Affected by V1 / V2? |
|---|---|---|---|---|
| **`Agent-Threat-Rule/claude-agent-sdk-atr`** | `src/claude_agent_sdk_atr/__init__.py` (104 L) | **C, emitting an A-shaped payload** | `pyatr.scan`; `DEFAULT_BLOCK_SEVERITIES = ("critical","high")`; **constructs its own** `{"hookSpecificOutput": {"permissionDecision": "deny", ...}}`. On no match it returns `{}` — it never emits `allow`. | **No** — but this is the ecosystem-consistency problem. See §6a. Not published to PyPI (404); GitHub-install only. |
| **`Agent-Threat-Rule/atr-lemonade-guard`** | `src/atr-scan.mjs` (108 L); npm dep `agent-threat-rules ^3.5.0` | **D** | `summarizeMatches()` sets `blocked: true` whenever `matches.length > 0`; severity used only to pick the rule to report. This is the proxy AMD GAIA's merged doc links to. | No. Not published to npm; `git clone` only. |
| **`Agent-Threat-Rule/openshell-middleware-atr`** | `src/guard.ts` (118 L), `src/config.ts` (93 L) | **C + maturity** | `engine.evaluate()` then `.filter(matchesMaturity(...))`; defaults `denyAtSeverity: "high"`, **`maturity: "stable"`**. The only consumer found that filters on maturity — it re-implements the enforce lane in userland because the engine exposes no entry point for it. | No. Not published to npm. |
| **`Agent-Threat-Rule/openguardrails-detector-atr`** | `src/index.ts` (403 L) | **C** | `blockSeverities` default `["critical","high"]` → OGR `block`; approval severities → `require_approval`. | No. Published to npm; 31 downloads last month. |
| **`Agent-Threat-Rule/NeMo-Agent-Toolkit-atr`** | `src/nat/plugins/atr/detector.py` (105 L) | **C** | `DEFAULT_DENY_SEVERITIES`; `action = "deny" if any(m.severity in self._deny) else "log"`. | No. Not published to PyPI under its own name (404). |
| **`cisco-ai-defense/aibom`** | `aibom/src/aibom/security_enrichment.py` (316 L) | **C (reporting only)** | `pyatr` `engine.evaluate()`; tags components with matched rule ids, ATLAS/ATT&CK refs. No block decision at all. | No. **Not listed in `ADOPTERS.md`** — a real Cisco integration the register is missing. |
| **`eeee2345/adk-atr-guardrail`** | `src/adk_atr_guardrail/plugin.py` (157 L) | **C** | `pyatr.scan`; `min_severity="high"` default; replaces the model turn with a block message. | No. On PyPI. (The upstream `google/adk-python#6130` PR was closed and the entry was removed from `ADOPTERS.md` on 2026-07-05; the standalone package survives.) |

### 6a. The one real consistency problem the change creates

`claude-agent-sdk-atr` is the only other ATR-authored component that speaks the Claude Code hook
contract, and it already does the thing V1 proposes:

```python
matches = [match for match in scan(content) if match.severity.lower() in block]
if not matches:
    return {}                       # <- no permissionDecision: host applies its own default
...
return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                               "permissionDecision": "deny", ...}}
```

Two consequences worth stating plainly:

1. **It is a working precedent for the "never emit `allow`" rule.** It returns `{}` on the clean
   path, so the host's own permission prompt is preserved. The reference engine emits `allow` on
   both the clean path *and* the fail-open error path, which is the behaviour V1 removes.
2. **After V1, the two ATR-authored hooks disagree by default.** The reference engine would emit
   no decision; the SDK hook would still hard-deny every `critical`/`high` match, from a
   `pyatr`-bundled ruleset with no maturity filter. Either the SDK hook gets the same opt-in
   treatment in the same release, or ATR ships two contradictory answers to "does ATR block by
   default?".

`nemoclaw-preflight.ts`, `openshell-filter.ts`, `mastra.ts`, `openshell-middleware-atr`,
`openguardrails-detector-atr`, `NeMo-Agent-Toolkit-atr` and `adk-atr-guardrail` are the same
situation one level down: **eight independent re-implementations of "critical/high ⇒ block"**,
none of which V1 touches. The de facto cross-implementation interface is the `severity` label on
the rule file, exactly as `docs/research/verdict-maturity-audit.md` §5 concluded.

---

## 7. The package-consumer side: what could and could not be determined

### 7a. Package identity

The npm package is **`agent-threat-rules`** (not `@atr/*`; no `@atr` scope exists on npm). The
Python engine is **`pyatr`** on PyPI. `package.json` at baseline: `agent-threat-rules@3.5.12`,
bins `atr` and `agent-threat-rules`, subpath exports `.`, `./quality`, `./mcp`, `./converters/*`.

### 7b. Download volume (measured 2026-08-14)

| Package | Window | Downloads | Source |
|---|---|---:|---|
| `agent-threat-rules` (npm) | last month (2026-07-11 → 2026-08-09) | **10,260** | `api.npmjs.org/downloads/point/last-month` |
| `agent-threat-rules` (npm) | last week (2026-08-03 → 2026-08-09) | **5,139** | same |
| `pyatr` (PyPI) | last month | **12,003** | `pypistats.org/api/packages/pyatr/recent` |
| `pyatr` (PyPI) | last week | **2,362** | same |
| `openguardrails-detector-atr` (npm) | last month | **31** | `api.npmjs.org` |

**Download counts are not adoption.** They include CI installs, mirrors, and this project's own
workflows (`agent-threat-rules` publishes on every rules merge, and the GitHub Action runs
`npm install -g agent-threat-rules@latest` on every invocation). They cannot be decomposed here.

A discrepancy worth recording: `packages.ecosyste.ms` reports `downloads = 3147` for the same
last-month window and `dependent_packages_count = 0`, `dependent_repos_count = 0`. Where the two
disagree, npm's own API is authoritative; the ecosyste.ms figure appears to be a stale snapshot,
and its dependent counts are demonstrably wrong (§7c finds real dependents).

### 7c. Who depends on the package — and why this list is incomplete

GitHub code search on 2026-08-14:

| Query | Repositories returned |
|---|---|
| `"agent-threat-rules" filename:package.json` | this repository (root + `editors/vscode`); one unrelated monorepo outside the ATR ecosystem and not listed in `ADOPTERS.md` (7 of its packages), out of scope for this audit |
| `from 'agent-threat-rules'` | this repository (docs + `src/tc-reporter.ts`); `precize/Agentic-AI-Top10-Vulnerability` (a doc snippet); the same out-of-scope monorepo |
| `from pyatr import` | `microsoft/agent-governance-toolkit` (`examples/acs-atr-annotator/atr_adapter.py` — a **second** MS AGT integration beyond the one in `ADOPTERS.md`); `cisco-ai-defense/aibom`; `eeee2345/adk-atr-guardrail`; this repository's `integrations/`; plus two forks of the MS AGT repo |
| `"agent-threat-rules guard"` | **0 results** |
| `atr_hook_matcher` / `claude_agent_sdk_atr` | **0 results** |

**This search demonstrably under-reports.** `Agent-Threat-Rule/atr-lemonade-guard` is a public
repository whose `src/atr-scan.mjs:8` reads `import { ATREngine } from 'agent-threat-rules';`
and whose `package.json` declares the dependency — and it appears in **neither** of the first two
queries. Code search indexes a subset of public repositories and no private ones. So:

- **"0 results for `agent-threat-rules guard`" is not evidence that nobody runs `atr guard`.**
  The hook is written into `.claude/settings.local.json` or `~/.claude/settings.json`, which are
  routinely gitignored or outside any repository. The population of channel-A consumers is
  **unmeasurable with the tools available here**.
- The npm dependent-package graph is likewise unmeasurable: npm exposes no dependents API, and
  the third-party index that does (`ecosyste.ms`) returns 0 for a package with at least four
  known dependents.

**Honest bound:** the channel-A consumer population is at least 1 (`atr guard` itself, installed
by an unknown number of users) and at most "everyone who ran `atr init`" — a number this
investigation cannot produce.

---

## 8. Migration risk table

Ordered by risk. "Notify" means what the change actually requires, not a generic courtesy.

| # | Consumer | Channel read | Behaviour change under V1 | Behaviour change under V2 | Why | Notification |
|---|---|---|---|---|---|---|
| 1 | **`atr guard`** — this repo's Claude Code hook | **A** | **Yes.** Stops emitting `deny`/`ask`; must also stop emitting `allow` (currently emitted on the clean path *and* the fail-open path) | No | Sole consumer of channel A | Release note + `docs/deployment-guide.md` §Option 4 + `README.md:214` lane table (which currently describes the default as advisory — the change makes that description true) |
| 2 | **`Agent-Threat-Rule/claude-agent-sdk-atr`** | C, emits its own A payload | **No** — but it will now contradict the reference engine by hard-denying `critical`/`high` | No | Independent copy of the deny matrix | **Must ship the same opt-in decision in the same release**, or the two ATR hooks disagree. Owner is the ATR project itself |
| 3 | **`atr_scan` MCP tool** | **A** (`verdict.outcome`) | **Yes.** `verdict.outcome` semantics change for every MCP client and for the model reading the tool result | No | `handleScan` calls `evaluateWithVerdict()` and surfaces the outcome (`src/mcp-tools/scan.ts:99-102`) | Release note; consider keeping the field and adding an explicit "advisory" marker rather than removing it, since the value is model-facing text |
| 4 | **`HookHandler` public API** | **A** | **Yes** (contract) | No | Re-exported from `src/index.ts` | Semver minor/major decision + CHANGELOG. No external consumer found, but §7c cannot prove none exists |
| 5 | **Test suite** | **A** | **Yes.** `tests/claude-code-contract.test.ts:18-24` and `tests/verdict.test.ts:82-89` pin the current mapping | Possibly `tests/hook-handler.test.ts` | Behaviour is deliberately pinned | Internal; expected work, not breakage |
| 6 | **Tier-1 blacklist path** | A, indirectly | **Yes, and this is the one safety-relevant regression.** `src/engine.ts:372-374` relies on "blacklist match ⇒ `critical` ⇒ guaranteed DENY" to stop known-malicious skills | No | Documented in `verdict-maturity-audit.md` §6.2 | V1 must carve this path out explicitly, or Tier-1 blacklist enforcement silently disappears from the hook |
| 7 | **Any custom `PlatformAdapter`** | **B** | No | **Yes** (INTERRUPT+ actions no longer dispatched without a directive) | — | **None found anywhere** (§3e). Zero known consumers; document the contract change in `SPEC.md` §5.5 / `INTEGRATION.md` |
| 8 | **33 `ADOPTERS.md` entries** | C / D / E / F | **No** | **No** | None reads A or B; all blocking is severity-driven over `evaluate()` / `scan()`, or the adopter only consumes rule files | **No breakage notice needed.** A courtesy note is optional; `INTEGRATION.md` should be amended to state which channel downstream *should* read, since its examples are the reason everyone invented their own floor |
| 9 | **7 non-listed consumers** (§6) | C / D | **No** | **No** | Same reason | Four are ATR-owned and should be swept for consistency with #2; `cisco-ai-defense/aibom` should be added to `ADOPTERS.md` |
| 10 | **npm / PyPI consumers at large** | unknown | **Unknown** | **Unknown** | Population unmeasurable (§7c) | Treat the release note as the only reachable channel. Do not claim the change is non-breaking on the basis of the searches in §7c — they under-report by construction |

---

## 9. What this report does not establish

- **The size of the `atr guard` user population.** GitHub code search returns 0 hits for the
  hook command, but hook settings files are gitignored or non-repository files. Unmeasurable
  here (§7c).
- **npm dependent packages beyond code search.** npm has no dependents API; the one third-party
  index queried returns 0 dependents for a package with at least four known ones. The list in
  §7c is a lower bound, not an inventory.
- **Private / enterprise integrations.** Three Tier-1 adopters (Cisco AI Defense, Microsoft
  Agent Governance Toolkit, Gen Digital Sage) consume ATR *rules*, and their evidence PRs are
  readable — but what their products do downstream of the imported signatures is not visible in
  those PRs. The channel classification (**E**) is based on what the merged PR contains, which
  is rule data, not engine calls. If any of them later embeds the TypeScript engine, that is
  invisible from here.
- **Whether the AG2 maintainer has changed `atr_guardrail.py` since adoption.** Source was read
  from `main` on 2026-08-14; no diff was taken against the state at merge.
- **The behaviour of the LiteLLM, OpenAI Guardrails, PyRIT-scorer, NeMo-Guardrails, Splunk,
  Cisco mcp-scanner, Cisco a2a-scanner and Promptfoo integrations after review changes.** All
  are open PRs; the source read is the current head SHA and may be revised before merge.
- **Any recall or false-positive consequence of V1 or V2.** This report is about compatibility,
  not detection quality. Neither variant changes which rules fire.

---

## 10. Reproduction

```bash
git -C <atr-repo> worktree add -f /tmp/dsopt/wt -b docs/blocking-opt-in-downstream origin/main
ln -sfn <atr-repo>/node_modules /tmp/dsopt/wt/node_modules
cd /tmp/dsopt/wt

# §3 — adapter no-op verification (aborts exit 3 unless C1..C4 hold)
npx tsx .scratch-downstream/verify-adapters.ts

# §5c — which shipped surfaces expose the verdict channel (aborts exit 3 unless S-C1..S-C3 hold)
npx tsx .scratch-downstream/verify-surfaces.ts

# §3d — end-to-end through the shipped CLI, both streams captured
printf '%s\n' \
  '{"hook":"PreToolUse","tool_name":"Bash","tool_input":{"command":"google-chrome --no-sandbox &"}}' \
  '{"hook":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | npx tsx src/cli.ts guard > /tmp/guard.out 2> /tmp/guard.err
grep -c "block_tool" /tmp/guard.out /tmp/guard.err     # both 0

# §3a / §3b — adapter inventory and dead flush
grep -rn "implements PlatformAdapter" src tests examples scripts integrations
grep -rn "flushResponses" . --exclude-dir=node_modules --exclude-dir=.git

# §5b / §5c — channel matrix and the six files that touch the verdict channel
grep -rn "permissionDecision" . --exclude-dir=node_modules --exclude-dir=.git \
  --exclude-dir=data --exclude-dir=proposals

# §4a — adopter evidence-link re-verification
gh pr view 1676 --repo NVIDIA/garak --json state,mergedAt
gh pr view 1992 --repo NVIDIA-NeMo/Guardrails --json state,mergedAt
gh search prs --repo NVIDIA-NeMo/Guardrails --author eeee2345 --json number,title,state

# §7b — package figures
curl -s https://api.npmjs.org/downloads/point/last-month/agent-threat-rules
curl -s https://pypistats.org/api/packages/pyatr/recent
```

Exit codes are judged directly; no output string is grepped for pass/fail. Probe scripts live
in `.scratch-downstream/` and are not committed.
