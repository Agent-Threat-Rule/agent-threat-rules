# MCP tools/list scan on benign tool definitions

False-positive measurement of `atr scan` on MCP `tools/list` documents, over the benign corpus in
[`data/test-corpora/mcp-tools-list-benign/`](../../test-corpora/mcp-tools-list-benign/README.md): 45 official
reference and vendor MCP servers, 710 tool definitions (698 distinct), read from pinned commits.

The files here are not `scripts/measurement/schema.ts` measurements: that schema is built around recall,
and a corpus with no attack samples has none. As with `data/measurements/clawhub-benign/`, the report is
its own JSON (`kind: "benign-fp"`), named so `verify.ts` does not read it as a schema file, and append-only
like every other measurement here. It does not feed `data/stats.json`.

## Reports

- `benign-fp_2026-10-22_pinned-2026-10-22_atr-4-1-5.json`: the first measurement, before PR #737 scoped
  tool definitions. Code `30c07b02` (rules tree `1660b3a6`, the same as PR #737's base).
- `benign-fp_2026-10-22_pinned-2026-10-22_atr-4-1-5_with-tool-definition-scope.json`: superseded by the
  next file, kept (append-only). The same corpus and
  shapes re-measured at `5796c0c4` (same rules tree), plus `tool_definition_context`: `atr scan` built from
  PR #737 at `2f76611e` (rules tree `1660b3a6`), with the engine option `toolDefinitions` the CLI sets for a
  tools/list document.
- `benign-fp_2026-10-22_pinned-2026-10-22_atr-4-1-5_tool-definition-scope-cf2793d9.json`: the current
  report. Code `23ff42c8` (rules tree `1660b3a6`; the corpus now also carries the awslabs root NOTICE and the
  fetch / git LICENSE files, tool documents unchanged), `tool_definition_context` from PR #737 at `cf2793d9`,
  which keeps events that carry a tools array on the event path and reports the scope in its JSON. Same
  numbers as the report before it.

## What was measured (ATR 4.1.5, rules tree `1660b3a6`)

Event shapes per tool definition, same content (the definition as JSON) and fields (`tool_name`,
`tool_description`):

- `mcp_exchange`: what `atr scan` built for a tools/list document in PR #737 before the scope (`51be1a1c`).
  The type has no source type, so every rule runs.
- tool-definition context: the same event on an engine constructed with `toolDefinitions: true` (PR #737
  `2f76611e`): a rule with agent_source `tool_call` runs only if a condition reads `tool_description` or it
  is in `TOOL_IDENTITY_RULES` (ATR-2026-00060); every other rule runs as before.
- `tool_response`: the same event typed `tool_response`, the type `atr test` builds for an mcp_exchange
  rule (comparison only).

Regex tier only (no embedding, no semantic judge), as `atr scan` runs by default. `cli_crosscheck`
confirms the `51be1a1c` CLI flags exactly the (tool, rule) pairs the script computes for `mcp_exchange`.

| Lane | mcp_exchange, before the scope | tool-definition context (PR #737) | tool_response |
|---|---|---|---|
| hunt | 58 / 710 = 8.2% (95% CI 6.4 to 10.4%) | 6 / 710 = 0.85% (0.39 to 1.83%) | 32 / 710 = 4.5% |
| alert | 57 / 710 = 8.0% | 5 / 710 = 0.70% | 31 / 710 = 4.4% |
| enforce | 0 / 710 | 0 / 710 | 1 / 710 (ATR-2026-00443, stable) |

Enforce going from 0 to 0 carries no information about the scope: the enforce lane loads only
`maturity: stable` rules, and none of the rules involved is stable. ATR-2026-00099, -00113 and -00063
(the call rules that made the false positives) and the nine rules that read `tool_description`
(ATR-2026-00100..00107, -00441) are all `test`, so enforce runs none of them, with or without the scope. The
enforce lane therefore also runs no tool-description rule on a tools/list document today.

What drove the 58 (`fp-classification.json` has the reason for every flag):

- 54 involved tool_call rules, written for a tool being invoked, running on a tool being defined:
  ATR-2026-00099 (48 tools: names containing delete, remove, reset, exec, eval, publish, subscribe, ...),
  ATR-2026-00113 (5), ATR-2026-00063 (1). The scope removes them.
- The 6 that remain, all at high or critical severity: five over-broad conditions and one form match.
  ATR-2026-01987 (Supabase execute_sql / apply_migration name `COPY ... FROM PROGRAM` as a primitive),
  ATR-2026-00225 (Cloudflare's 1.1.1.1 resolver; `[^\n]*` spans the single-line JSON to a later
  "control"), ATR-2026-00217 (`sync` inside `async`, then `[^\n]*` to "key"), ATR-2026-00161 and
  ATR-2026-00569 (a DynamoDB description documenting that `../../../../etc/passwd` is blocked), and
  ATR-2026-00579 (experimental, hunt only: "Before calling this tool, you MUST first ...", the line-jumping
  form, benign by intent). Follow-ups for those rules, not changed here.
- On tool_response, prompt-injection (llm_io) rules read the JSON text as a prompt: ATR-2026-00454 counts
  JSON escapes (`\n\n\n`) as backslash-per-character encoding on 21 tools.

Switching to tool_response is not a fix: `tool_description_rule_coverage` shows the rules that read
`tool_description` (ATR-2026-00100..00107, -00441, all agent_source tool_call) fire on 39 of their 41 own
true positives as mcp_exchange and on 0 as tool_response. Of the 41, 35 are description texts and 4 are
ATR-2026-00441 code snippets that fire through its content conditions; the 2 that do not fire are
ATR-2026-00441 tool calls written as JSON with arguments, not definitions. This check was run in the hunt
lane only (those rules are `test`, so alert would match it and enforce loads none of them).

## Reproduce

```
git checkout <atr_commit in the report>
npm ci
bash scripts/mcp-tools-list/reproduce.sh            # re-extract the corpus, compare, measure (nothing written)
bash scripts/mcp-tools-list/reproduce.sh --write    # also write a new report here
```

`CLI_RESULTS=<dir>` adds the cross-check against `atr scan` output from a PR #737 build, and
`SCOPED_CLI_RESULTS=<dir> SCOPED_CLI_REPO=<checkout>` the tool-definition context from a build of that
checkout; once the measured checkout has `src/tool-definition-scope.ts`, the context is measured in-process
(see the script).
