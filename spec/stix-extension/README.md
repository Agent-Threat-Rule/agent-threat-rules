# Agent Threat Rules (ATR) — STIX 2.1 Extension

This directory defines a STIX 2.1 extension that introduces the
`x-atr-rule` custom Domain Object so ATR rules can be represented
natively in STIX/TAXII threat-intelligence pipelines.

## Why a STIX extension

ATR rules are an open detection vocabulary for AI agent threats —
prompt injection, tool poisoning, MCP server attacks, skill compromise.
They were adopted as a MISP taxonomy in [MISP/misp-taxonomies#323][misp-tax]
on 2026-05-10 and a MISP galaxy in [MISP/misp-galaxy#1207][misp-gal].

Several CTI consumers use STIX/TAXII rather than MISP. Mapping ATR to a
generic STIX `indicator` or `attack-pattern` object is lossy: the
nine-category attack class, regex detection patterns, severity, and the
compliance-framework references (EU AI Act, NIST AI RMF, ISO 42001) all
get flattened. This extension preserves them as first-class fields on a
new `x-atr-rule` SDO.

## Files

- [`extension-definition.json`](./extension-definition.json) — the
  STIX 2.1 Extension Definition object. Stable id
  `extension-definition--93370194-c964-570f-9802-9d1154e5525d`. Consumers
  reference this id in the `extensions` map of every `x-atr-rule`
  instance.
- [`x-atr-rule-schema.json`](./x-atr-rule-schema.json) — JSON Schema
  (Draft 7) for the new SDO. Defines required fields, enum values for
  `atr_category` / `severity` / `agent_source_type` / `response_actions`,
  and structural constraints on `detection_patterns` and
  `compliance_refs`.
- [`examples/atr-rule-prompt-injection-example.json`](./examples/atr-rule-prompt-injection-example.json)
  — concrete instance for `ATR-2026-00001` showing the full payload
  shape including the extension reference.

## Identifier convention

`x-atr-rule.id` is recommended to be a deterministic UUIDv5 derived
from the canonical ATR rule id (e.g. `ATR-2026-00431`) under the
namespace UUID `6f7a8b9c-1d2e-4f5a-9b8c-7e6d5f4a3b2c`. The same rule id
therefore always produces the same STIX id across consumers, which lets
multiple feeds align without conflict resolution.

## Extension type

`extension_types: ["new-sdo"]` per STIX 2.1 §7.3, which is the correct
designation for introducing a brand-new top-level Domain Object type.
The schema field on the Extension Definition points at the JSON Schema
in this directory via raw GitHub URL so the schema is dereferenceable
for validating consumers.

## Validation

```bash
python3 -m pip install jsonschema
python3 -c "import json, jsonschema; \
  schema = json.load(open('spec/stix-extension/x-atr-rule-schema.json')); \
  example = json.load(open('spec/stix-extension/examples/atr-rule-prompt-injection-example.json')); \
  jsonschema.validate(example, schema); \
  print('OK')"
```

## Status

Draft v1.0.0. Not yet submitted to the OASIS CTI Technical Committee.
The extension is usable today by any consumer that processes STIX
extensions per the spec; OASIS submission becomes relevant if a
subset of fields ends up wanting promotion into core STIX.

## Related

- Canonical ATR repo: <https://github.com/Agent-Threat-Rule/agent-threat-rules>
- ATR YAML schema: [`../atr-schema.yaml`](../atr-schema.yaml)
- npm: <https://www.npmjs.com/package/agent-threat-rules>
- DOI: 10.5281/zenodo.19178002

[misp-tax]: https://github.com/MISP/misp-taxonomies/pull/323
[misp-gal]: https://github.com/MISP/misp-galaxy/pull/1207
