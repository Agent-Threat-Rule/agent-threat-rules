# ATR to Sigma converter

`scripts/generate-sigma.py` converts Agent Threat Rules (ATR) YAML rules into
[Sigma](https://sigmahq.io) detection rules, so the Sigma ecosystem (SIEM
backends through pySigma / sigma-cli) can consume ATR's agent/LLM detections.

This was built in response to
[agentshield-ai/sigma-ai#9](https://github.com/agentshield-ai/sigma-ai/issues/9),
where — after the ATR to MITRE ATT&CK crosswalk
(`docs/crosswalks/atr-attack-crosswalk.md`) landed — the agreed next step was
"the YAML to Sigma converter".

The example rules under `docs/sigma-export/rules/` in this directory were
produced by this script from the real ATR rules named in each file; they are
not hand-authored.

## Why this is not a lossless 1:1 conversion

ATR and Sigma detect different things at different layers, and the honest
answer is that the mapping is exact on one axis and approximate on others. This
is stated up front rather than buried.

Sigma was built to match fields in **host / network / cloud log events**
(a `process_creation` event, an `sshd` auth log). ATR patterns fire on **AI
agent runtime surfaces** — the model's `content`, the `user_input`, a
`tool_response`, `tool_args`, `tool_name`, `agent_output`. There is no ratified
Sigma `logsource` for agent traffic today. So the converter emits a **custom,
clearly-labelled** logsource (`logsource.product: ai_agent`) and preserves the
ATR field name verbatim as the Sigma detection field. Anyone deploying these
into a SIEM must map those field names onto their own agent-telemetry pipeline.
That wiring step is the approximate part, and it is the operator's to complete.

The one axis that **is** exact is the MITRE ATT&CK technique id — the same join
key the crosswalk established.

## Field mapping table

| ATR field | Sigma field | Mapping | Exact? |
|---|---|---|---|
| `title` | `title` | verbatim, truncated to 256 chars (Sigma limit) | yes |
| `id` (e.g. `ATR-2026-00030`) | `id` | deterministic UUIDv5 of the ATR id (Sigma requires a UUID; ATR ids are not UUIDs). Same ATR id always yields the same UUID. The original ATR id is also preserved as an `atr.rule.*` tag. | derived, stable |
| `severity` (critical/high/medium/low) | `level` | direct: critical→critical, high→high, medium→medium, low→low | yes |
| `status` / `maturity` | `status` | stable→stable, experimental→experimental, test→test, draft→experimental | yes for shared values |
| `description` | `description` | verbatim + a provenance/limitations note appended | yes (additive) |
| `author` | `author` | verbatim | yes |
| `date` (`YYYY/MM/DD`) | `date` | normalised to ISO `YYYY-MM-DD` | yes |
| `references.mitre_attack: Txxxx` | `tags: attack.txxxx` | lower-cased, prefixed `attack.` — **the canonical Sigma join key** | **exact** |
| `references.mitre_atlas: AML.Txxxx` | `tags: atlas.aml-txxxx` | custom namespace (Sigma has no ATLAS taxonomy) | additive, non-standard |
| `references.owasp_agentic: ASInn` | `tags: owasp-agentic.asinn` | custom namespace | additive, non-standard |
| `references.owasp_llm: LLMnn` | `tags: owasp-llm.llmnn` | custom namespace | additive, non-standard |
| `tags.category` | `tags: atr.category.<cat>` | custom namespace | additive, non-standard |
| detection `field` (content, tool_response, ...) | Sigma detection field name | verbatim; drives `logsource.category` (see below) | field name exact; logsource custom |
| detection `operator: regex` + `value` | `field\|re` or `field\|re\|i` | leading inline `(?i)` is stripped and re-expressed as the Sigma `re\|i` case-insensitive sub-flag; the rest of the pattern is passed through verbatim | see caveat below |
| detection `condition: any` | `condition: 1 of sel_*` | | yes |
| detection `condition: all` | `condition: all of sel_*` | | yes |
| detection `false_positives` | `falsepositives` | verbatim | yes |
| detection numeric operators (`gt`/`lt`/...) | plain field match + warning | Sigma base spec has no portable numeric comparison | **approximate** |

### logsource.category derivation

The Sigma `logsource.category` is derived from the rule's dominant detection
field (custom values, all under `product: ai_agent`):

| ATR detection field | logsource.category |
|---|---|
| `content` | `ai_agent_content` |
| `user_input` | `ai_agent_prompt` |
| `tool_response` | `ai_agent_tool_response` |
| `tool_args` / `tool_input` / `tool_name` / `tool_description` | `ai_agent_tool_call` |
| `agent_output` | `ai_agent_output` |
| anything else (e.g. `trace.*`, `behavioral.metric_value`) | `ai_agent_other` (with a warning) |

## Known limitations (honest)

1. **No standard agent logsource.** `logsource.product: ai_agent` and the
   `ai_agent_*` categories are ATR-defined, not ratified by SigmaHQ. Backends
   will not know these field names until you map them to your agent telemetry.
   This is the single biggest caveat.

2. **Case-insensitivity relies on `re|i` backend support.** ATR regexes almost
   universally open with inline `(?i)`. The converter strips that and emits the
   Sigma `re|i` sub-flag, which is the portable way. A handful of patterns with
   other combined inline flags (`(?is)` etc.) keep the remaining flag inline;
   inline-flag support varies by backend. Patterns with no leading `(?i)` are
   emitted as case-sensitive `re` exactly as ATR wrote them.

3. **Regex flavor.** ATR patterns are Python `re`. Sigma `re` is documented as
   PCRE-ish but the effective flavor is the *target backend's* regex engine
   after pySigma translation. Exotic constructs (lookbehind, named groups,
   backreferences) may not survive every backend. The converter does not
   rewrite regex internals — it passes them through, so a pattern that a backend
   cannot compile is a backend limitation surfaced at deploy time, not silently
   altered here.

4. **Behavioral / aggregation rules degrade.** ATR behavioral-method rules
   (e.g. `ATR-2026-00553`, "more than 100 tool calls per minute per session")
   carry a `detection.behavioral` aggregation block (count over a time window).
   The Sigma **base** spec has no aggregation grammar (Sigma Correlation rules
   are a separate, evolving construct). The converter maps only the rule's
   `detection.conditions` — for behavioral rules that is a match on the
   pre-computed threshold-breach signal, **not** the underlying count-over-time
   logic. Treat these as approximate.

5. **`test_cases` / `evasion_tests` are not carried over.** ATR ships rich
   true-positive / true-negative / evasion test corpora per rule. Sigma has no
   place for them in the rule schema, so they stay in ATR. (They remain the
   authoritative validation of the underlying pattern.)

6. **ATLAS / OWASP tags are non-standard namespaces.** Only `attack.*` is
   understood by mainstream Sigma tooling. `atlas.*`, `owasp-agentic.*`,
   `owasp-llm.*`, and `atr.*` are additive agent-layer context this converter
   emits so no ATR metadata is lost — but off-the-shelf Sigma backends will
   ignore them unless you teach them the namespace.

## Usage

Requires Python 3.10+ and PyYAML (`pip install pyyaml`), no other dependencies —
same zero-heavy-dependency discipline as `scripts/generate-attack-crosswalk.py`.

Convert a single rule to stdout:

    python3 scripts/generate-sigma.py --rule rules/agent-manipulation/ATR-2026-00030-cross-agent-attack.yaml

Convert several rules into a directory (one `.sigma.yml` each):

    python3 scripts/generate-sigma.py \
      --rule rules/agent-manipulation/ATR-2026-00030-cross-agent-attack.yaml \
      --rule rules/agent-manipulation/ATR-2026-00118-approval-fatigue.yaml \
      --out docs/sigma-export/rules

Convert the entire rule corpus:

    python3 scripts/generate-sigma.py --all --out docs/sigma-export/rules

Conversion warnings (approximate mappings, unmapped fields) are printed to
stderr; add `--quiet` to suppress them. Every warning names the ATR rule id so
nothing is hidden.

## Validating the output with real Sigma tooling

The emitted files are standard Sigma YAML. To check them against pySigma:

    pip install sigma-cli
    sigma check docs/sigma-export/rules/

`sigma check` validates schema and structure. Note it may warn on the custom
`ai_agent` logsource / non-standard tag namespaces — that is expected and is
exactly limitation (1) and (6) above, not a converter bug.

The five exported example rules in `docs/sigma-export/rules/` have been parsed
by pySigma's `SigmaRule.from_yaml()` with zero errors (title, level, and tags
all recognised). The test suite re-checks this automatically when pySigma is
installed (and skips it cleanly when it is not).

## Tests

`scripts/test_generate_sigma.py` verifies the load-bearing guarantees: the
output is valid YAML with all required Sigma fields, `level`/`status` are in
Sigma's allowed sets, the ATT&CK join key round-trips (every enterprise ATT&CK
id in the source ATR rule appears as `attack.txxxx`, and no bogus `attack.*`
tag is minted from an ATLAS id), the `(?i)` → `re|i` transform is applied, and
every rule in the whole corpus converts to reparseable Sigma without crashing.

    python3 scripts/test_generate_sigma.py     # standalone
    pytest scripts/test_generate_sigma.py      # under CI

## License

ATR is MIT-licensed. This converter and its output may be reused under the same
terms.
