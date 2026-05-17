# Promptfoo PR #8529 fix draft

Draft of the two source files needed to unblock
[promptfoo/promptfoo#8529](https://github.com/promptfoo/promptfoo/pull/8529).

Copy these into `examples/redteam-atr-mcp-defense/` in the promptfoo PR
branch (`eeee2345/promptfoo @ examples/redteam-atr-mcp-defense`).

## What changed vs. the PR's current files

### `atr-assertion.mjs`

1. **Top-level static `import` instead of dynamic `import()`.**
   The PR's `await import('agent-threat-rules')` inside a try/catch was the
   thing the codex bot flagged as fragile under CJS interop. Because
   `agent-threat-rules` is published as a pure ESM package (`"type": "module"`)
   and this file is `.mjs`, a normal top-level `import` is both simpler and
   correct. If the dependency is missing, Node throws a clear
   `ERR_MODULE_NOT_FOUND` at load time, which is friendlier than failing
   inside every assertion call.

2. **Explicit `(output, context)` signature.**
   Promptfoo's `type: javascript` `file://` assertions are invoked with
   positional `(output, context)`. The PR used `(output)` only, which works
   but reads as if the author wasn't sure of the contract. Accepting both
   makes the signature self-documenting. `context` is intentionally unused.

3. **Full JSDoc on every documentable symbol** (file `@module` block,
   `FAIL_SEVERITIES`, `enginePromise`, `getEngine`, `atrAssertion`) including
   `@param`, `@returns`, `@example`, and a `@type` on the cache variable.
   This is to satisfy the docstring-coverage CI check that is currently
   reporting 0%. Each top-level declaration now has a directly-attached
   JSDoc block.

4. **Severity threshold extracted to a `FAIL_SEVERITIES` constant** so users
   can tune it without hunting through logic. No behaviour change at the
   defaults (`critical` + `high`).

5. **`String(output ?? '')` retained** — handles `undefined` / non-string
   provider outputs without throwing.

### `promptfooconfig.yaml`

1. **Removed `defaultTest.options.transformVars`.**
   The PR had:
   ```yaml
   options:
     transformVars: '{ ...vars, sessionId: context.uuid }'
   ```
   `context.uuid` is not a documented Promptfoo context field, so this
   `transformVars` expression either silently produces `sessionId: undefined`
   or throws at evaluation time. The example doesn't need a `sessionId` at
   all, so the cleanest fix is to drop the block.

Everything else in the yaml is unchanged. If reviewers still flag
`jailbreak:meta` / `crescendo` strategy names as deprecated, that's a
separate rename and can be handled in a follow-up commit.

## How to apply

```bash
# In the promptfoo PR working copy:
cp atr-assertion.mjs        examples/redteam-atr-mcp-defense/atr-assertion.mjs
cp promptfooconfig.yaml     examples/redteam-atr-mcp-defense/promptfooconfig.yaml
git add examples/redteam-atr-mcp-defense/
git commit -m "fix(redteam-atr-mcp-defense): address review feedback on PR #8529"
git push
```
