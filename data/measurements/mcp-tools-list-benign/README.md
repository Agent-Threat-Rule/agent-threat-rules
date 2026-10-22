# MCP tools/list scan on benign tool definitions

False-positive measurement of `atr scan` on MCP `tools/list` documents, over the benign corpus in
[`data/test-corpora/mcp-tools-list-benign/`](../../test-corpora/mcp-tools-list-benign/README.md): 45 official
reference and vendor MCP servers, 710 tool definitions (698 distinct), read from pinned commits.

The files here are not `scripts/measurement/schema.ts` measurements: that schema is built around recall,
and a corpus with no attack samples has none. As with `data/measurements/clawhub-benign/`, the report is
its own JSON (`kind: "benign-fp"`), named so `verify.ts` does not read it as a schema file, and append-only
like every other measurement here. It does not feed `data/stats.json`.

## What was measured (ATR 4.1.5, rules tree `1660b3a6`, 2026-10-22)

Two event shapes per tool definition, same content (the definition as JSON) and fields (`tool_name`,
`tool_description`):

- `mcp_exchange`: what `atr scan` builds for a tools/list document in PR #737 (`51be1a1c`). The type has no
  source type, so every rule runs.
- `tool_response`: the same event typed `tool_response`, the type `atr test` builds for an mcp_exchange rule.

Regex tier only (no embedding, no semantic judge), as `atr scan` runs by default. The report's
`cli_crosscheck` confirms the PR #737 CLI flags exactly the same (tool, rule) pairs in every lane.

| Lane | mcp_exchange (PR #737) | tool_response |
|---|---|---|
| hunt | 58 / 710 = 8.2% (95% CI 6.4 to 10.4%); 11 at high or critical | 32 / 710 = 4.5%; 9 at high or critical |
| alert | 57 / 710 = 8.0% | 31 / 710 = 4.4% |
| enforce | 0 / 710 | 1 / 710 (ATR-2026-00443, stable) |

What drives it (`fp-classification.json` has the reason for every flag):

- 54 of the 58 hunt-lane mcp_exchange flags involve tool_call rules, written for a tool being invoked,
  running on a tool being defined: ATR-2026-00099 (48 tools: names containing delete, remove, reset, exec,
  eval, publish, subscribe, ...), ATR-2026-00113 (5), ATR-2026-00063 (1). They never run on tool_response.
  Without tool_call rules the same events flag 6 tools in hunt (0.85%), 5 in alert, 0 in enforce.
- JSON.stringify puts a definition on one line, so `[^\n]*` and `.*` in line-oriented patterns span the
  whole definition (ATR-2026-00225, -00217, -00113, -00020, -00502).
- On tool_response, prompt-injection (llm_io) rules read the JSON text as a prompt: ATR-2026-00454 counts
  JSON escapes (`\n\n\n`) as backslash-per-character encoding on 21 tools.
- One flag is arguably a true positive in form: ATR-2026-00579 (experimental, hunt only) on a DynamoDB
  tool whose description tells the model what it must do before calling the tool.

Switching the PR to tool_response is not a fix: `tool_description_rule_coverage` shows the rules that read
`tool_description` (ATR-2026-00100..00107, -00441, all agent_source tool_call) fire on 39 of their 41 own
true positives as mcp_exchange and on 0 as tool_response.

## Reproduce

```
git checkout <atr_commit in the report>
npm ci
bash scripts/mcp-tools-list/reproduce.sh            # re-extract the corpus, compare, measure (nothing written)
bash scripts/mcp-tools-list/reproduce.sh --write    # also write a new report here
```

`CLI_RESULTS=<dir>` adds the cross-check against `atr scan` output from a PR #737 build (see the script).
