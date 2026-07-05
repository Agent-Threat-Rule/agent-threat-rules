#!/usr/bin/env python3
"""Convert Agent Threat Rules (ATR) YAML into Sigma detection rules.

This produces Sigma-format YAML from ATR rules so the Sigma ecosystem (SIEM
backends via pySigma / sigma-cli) can consume ATR's agent/LLM detections. It
was written in response to agentshield-ai/sigma-ai#9, where the next step after
the ATR<->ATT&CK crosswalk was "the YAML to Sigma converter".

Design honesty (read docs/sigma-export/README.md for the full mapping table and
its known limitations):

  * The join key with mainstream Sigma is the enterprise ATT&CK technique id.
    ATR carries it as `references.mitre_attack: Txxxx`; this emitter writes it
    as Sigma `tags: attack.txxxx` (lower-cased, prefixed). That axis is exact.

  * ATR and Sigma have a genuine impedance mismatch. ATR patterns fire on agent
    runtime surfaces (content / tool_call / tool_response / user_input / ...),
    which are NOT standard Sigma log fields. There is no ratified Sigma
    logsource for agent traffic, so this emitter uses a custom, clearly-labelled
    taxonomy: `logsource.product: ai_agent`. Anyone wiring this into a SIEM must
    map those fields to their own agent-telemetry pipeline. This is approximate
    by nature and is called out, not hidden.

  * ATR regexes are Python `re` with a near-universal leading inline `(?i)`.
    Sigma's `re` modifier is case-sensitive by default but supports `re|i`.
    Where an ATR pattern starts with `(?i)`, we strip it and emit `field|re|i`;
    otherwise `field|re`. Remaining inline flags (rare) are preserved verbatim
    inside the pattern -- backend support for inline flags varies, which is a
    documented limitation, not a silent one.

  * ATR's non-regex operators are rare. `operator: gt` (numeric behavioral
    threshold) has no clean Sigma string-match equivalent, so those single
    conditions are emitted with a `gt`-style numeric comparison note and the
    rule is flagged in its description as partially approximated.

Nothing about the ATT&CK/ATLAS/OWASP tags or the regexes is invented: every
value is read verbatim from the source ATR rule.

Run:
  python3 scripts/generate-sigma.py --rule rules/agent-manipulation/ATR-2026-00030-cross-agent-attack.yaml
  python3 scripts/generate-sigma.py --all --out docs/sigma-export/rules
  python3 scripts/generate-sigma.py --all --stdout        # one doc stream
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys
import uuid

try:
    import yaml
except ImportError:  # pragma: no cover - environment guard
    sys.exit("PyYAML required: pip install pyyaml")

RULES_GLOB = "rules/**/*.yaml"

# Stable UUIDv5 namespace so a given ATR id always yields the same Sigma id
# across runs (Sigma wants a UUID; ATR ids are not UUIDs). Deterministic ==
# regenerable without churn, same discipline as the crosswalk generator.
ATR_SIGMA_NAMESPACE = uuid.UUID("6f0d9d4e-6d5a-5c2b-9b7a-11c0ffee5161")

# ATR severity -> Sigma level. Both scales share the top four names; ATR has no
# "informational", Sigma has no bare "info", so this is a direct 1:1 for the
# values ATR actually uses (critical/high/medium/low).
SEVERITY_TO_LEVEL = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
}

# ATR status / maturity -> Sigma status. Sigma's vocabulary is
# stable/test/experimental/deprecated/unsupported. ATR uses
# stable/experimental/draft plus a maturity of stable/test/experimental.
STATUS_TO_SIGMA = {
    "stable": "stable",
    "experimental": "experimental",
    "test": "test",
    "draft": "experimental",
    "deprecated": "deprecated",
    "unsupported": "unsupported",
}

# ATR detection field -> Sigma logsource.category. There is no official Sigma
# category for agent traffic; these are ATR-defined and documented as custom.
# The field name itself is preserved verbatim as the Sigma detection field so
# no information is lost -- only the coarse logsource.category is derived here.
FIELD_TO_CATEGORY = {
    "content": "ai_agent_content",
    "user_input": "ai_agent_prompt",
    "tool_response": "ai_agent_tool_response",
    "tool_args": "ai_agent_tool_call",
    "tool_input": "ai_agent_tool_call",
    "tool_name": "ai_agent_tool_call",
    "tool_description": "ai_agent_tool_call",
    "agent_output": "ai_agent_output",
}


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def first_token(value: str) -> str:
    s = str(value).strip()
    return s.split()[0] if s else ""


# Enterprise ATT&CK ids (T1xxx, optional .NNN subtechnique). ATLAS short-form
# (T00xx) and AML.Txxxx are handled separately so we never mint a bogus
# attack.txxxx tag from an ATLAS id sitting in the wrong field.
ATTACK_RE = re.compile(r"^(T1\d{3})(\.\d{3})?$")
ATLAS_FULL_RE = re.compile(r"^AML\.T\d{4}")
ATLAS_SHORT_RE = re.compile(r"^T0\d{2,3}$")


def sigma_id_for(atr_id: str) -> str:
    return str(uuid.uuid5(ATR_SIGMA_NAMESPACE, str(atr_id) or "atr-unknown"))


def build_tags(refs: dict) -> list[str]:
    """Derive Sigma tags from ATR references, verbatim ids only.

    * enterprise ATT&CK  -> attack.txxxx        (the canonical Sigma join key)
    * MITRE ATLAS        -> atlas.aml-txxxx      (custom namespace; not standard)
    * OWASP Agentic      -> owasp-agentic.asiNN  (custom namespace; not standard)
    * OWASP LLM          -> owasp-llm.llmNN      (custom namespace; not standard)
    Only the first (attack.*) is understood by mainstream Sigma tooling; the
    rest are additive agent-layer context and are labelled as custom.
    """
    tags: list[str] = []
    seen: set[str] = set()

    def add(tag: str) -> None:
        if tag not in seen:
            seen.add(tag)
            tags.append(tag)

    for entry in as_list(refs.get("mitre_attack")):
        tok = first_token(entry)
        if ATTACK_RE.match(tok):
            add(f"attack.{tok.lower()}")
        elif ATLAS_FULL_RE.match(tok) or ATLAS_SHORT_RE.match(tok):
            # ATLAS id misfiled in mitre_attack -> route to the atlas namespace,
            # never to attack.*, so the ATT&CK join key stays clean.
            add(f"atlas.{tok.lower().replace('.', '-')}")

    for entry in as_list(refs.get("mitre_atlas")):
        tok = first_token(entry)
        if tok:
            add(f"atlas.{tok.lower().replace('.', '-')}")

    for entry in as_list(refs.get("owasp_agentic")):
        tok = first_token(entry).rstrip(":")
        m = re.match(r"^(ASI\d+):?", tok)
        if m:
            add(f"owasp-agentic.{m.group(1).lower()}")

    for entry in as_list(refs.get("owasp_llm")):
        tok = first_token(entry).rstrip(":")
        m = re.match(r"^(LLM\d+):?", tok)
        if m:
            add(f"owasp-llm.{m.group(1).lower()}")

    return tags


def strip_leading_i_flag(pattern: str) -> tuple[str, bool]:
    """If the ATR regex opens with a case-insensitive inline flag, strip it and
    signal that the Sigma `i` sub-flag should be used instead.

    Handles `(?i)` and combined leading groups like `(?is)` / `(?im)` by
    removing only the `i` and keeping the rest as an inline group. Anything the
    emitter does not confidently understand is left verbatim (fail safe: the
    pattern still matches, we just do not get the clean `re|i`).
    """
    m = re.match(r"^\(\?([a-zA-Z]+)\)", pattern)
    if not m:
        return pattern, False
    flags = m.group(1)
    if "i" not in flags:
        return pattern, False
    rest_flags = flags.replace("i", "")
    body = pattern[m.end():]
    if rest_flags:
        return f"(?{rest_flags}){body}", True
    return body, True


def convert_conditions(atr_detection: dict) -> tuple[dict, str, list[str]]:
    """Turn ATR detection.conditions into Sigma selections + a condition string.

    Returns (selections_map, condition_expr, warnings).

    Each ATR condition becomes its own named Sigma selection `sel_N` so the
    original 1:1 structure (and each condition's description) survives. The ATR
    `condition: any|all` becomes Sigma `1 of sel_*` / `all of sel_*`.
    """
    warnings: list[str] = []
    selections: dict[str, dict] = {}
    conditions = as_list(atr_detection.get("conditions"))
    combine = str(atr_detection.get("condition", "any")).strip().lower()

    for idx, cond in enumerate(conditions, start=1):
        if not isinstance(cond, dict):
            warnings.append(f"condition #{idx} is not a mapping; skipped")
            continue
        field = cond.get("field") or cond.get("detection_field") or "content"
        operator = str(cond.get("operator", "regex")).strip().lower()
        value = cond.get("value")
        sel_name = f"sel_{idx}"

        if operator == "regex":
            if value is None:
                warnings.append(f"condition #{idx} has no value; skipped")
                continue
            pattern, use_i = strip_leading_i_flag(str(value))
            modifier = "re|i" if use_i else "re"
            selections[sel_name] = {f"{field}|{modifier}": pattern}
        elif operator in ("gt", "lt", "gte", "lte", "eq"):
            # Numeric behavioral threshold. Sigma has no portable numeric
            # comparison in the base spec (backends vary); emit an equality-style
            # placeholder plus an explicit warning so this is never silently
            # mis-stated as an exact translation.
            selections[sel_name] = {field: value}
            warnings.append(
                f"condition #{idx} uses numeric operator '{operator}' "
                f"(value={value!r}); Sigma base spec has no portable numeric "
                f"comparison -- emitted as a plain field match, APPROXIMATE."
            )
        else:
            selections[sel_name] = {f"{field}|contains": value}
            warnings.append(
                f"condition #{idx} uses unmapped operator '{operator}'; "
                f"emitted as |contains, APPROXIMATE."
            )

    if not selections:
        # A rule with no convertible conditions still needs a valid detection.
        selections["sel_placeholder"] = {"content|contains": ""}
        warnings.append("no convertible conditions; emitted placeholder selection")

    sel_names = list(selections.keys())
    if len(sel_names) == 1:
        condition_expr = sel_names[0]
    elif combine == "all":
        condition_expr = "all of sel_*"
    else:
        condition_expr = "1 of sel_*"

    return selections, condition_expr, warnings


def convert_rule(doc: dict, source_path: str) -> tuple[dict, list[str]]:
    """Convert one parsed ATR rule dict into a Sigma rule dict (+ warnings)."""
    warnings: list[str] = []
    atr_id = doc.get("id", "")
    refs = doc.get("references") or {}
    if not isinstance(refs, dict):
        refs = {}
    tags = doc.get("tags") or {}
    if not isinstance(tags, dict):
        tags = {}
    atr_detection = doc.get("detection") or {}
    if not isinstance(atr_detection, dict):
        atr_detection = {}

    selections, condition_expr, cond_warnings = convert_conditions(atr_detection)
    warnings.extend(cond_warnings)

    severity = str(doc.get("severity", "medium")).strip().lower()
    level = SEVERITY_TO_LEVEL.get(severity)
    if level is None:
        level = "medium"
        warnings.append(f"unknown severity '{severity}'; defaulted level=medium")

    status_src = str(doc.get("status") or doc.get("maturity") or "experimental").strip().lower()
    status = STATUS_TO_SIGMA.get(status_src, "experimental")

    # logsource category from the dominant detection field.
    fields_used = [
        (c.get("field") or c.get("detection_field"))
        for c in as_list(atr_detection.get("conditions"))
        if isinstance(c, dict)
    ]
    fields_used = [f for f in fields_used if f]
    category = None
    if fields_used:
        primary = max(set(fields_used), key=fields_used.count)
        category = FIELD_TO_CATEGORY.get(primary)
        if category is None:
            category = "ai_agent_other"
            warnings.append(
                f"detection field '{primary}' has no category mapping; "
                f"used logsource.category=ai_agent_other (custom)."
            )

    sigma_tags = build_tags(refs)
    # ATR category as an additive namespaced tag (not a standard Sigma tag).
    atr_category = tags.get("category")
    if atr_category:
        sigma_tags.append(f"atr.category.{str(atr_category).replace('_', '-')}")
    if atr_id:
        sigma_tags.append(f"atr.rule.{str(atr_id).lower()}")

    # Assemble description, honestly noting any approximation.
    desc = str(doc.get("description", "")).strip()
    provenance = (
        f"Converted from Agent Threat Rules {atr_id} "
        f"({os.path.basename(source_path)}) by scripts/generate-sigma.py. "
        f"ATR is MIT-licensed. logsource.product=ai_agent is a custom "
        f"(non-standard) taxonomy for agent runtime telemetry."
    )
    if any("APPROXIMATE" in w for w in warnings):
        provenance += (
            " NOTE: this rule contains at least one condition that could not be "
            "translated 1:1 to Sigma (see conversion warnings); treat as "
            "approximate."
        )
    full_desc = f"{desc}\n\n{provenance}" if desc else provenance

    references_urls = [
        "https://github.com/Agent-Threat-Rule/agent-threat-rules",
    ]

    falsepositives = as_list(atr_detection.get("false_positives")) or ["Unknown"]

    sigma: dict = {
        "title": str(doc.get("title", atr_id or "ATR rule"))[:256],
        "id": sigma_id_for(atr_id),
        "status": status,
        "description": full_desc,
        "references": references_urls,
        "author": str(doc.get("author", "ATR Community")),
        "date": _normalize_date(doc.get("date")),
        "tags": sigma_tags,
        "logsource": _build_logsource(category),
        "detection": {**selections, "condition": condition_expr},
        "falsepositives": [str(fp) for fp in falsepositives],
        "level": level,
    }
    return sigma, warnings


def _build_logsource(category: str | None) -> dict:
    ls: dict = {"product": "ai_agent"}
    if category:
        ls["category"] = category
    ls["definition"] = (
        "Custom ATR taxonomy for AI agent runtime telemetry. Detection field "
        "names (content, user_input, tool_response, tool_args, tool_name, "
        "tool_description, agent_output, ...) are ATR surfaces, not standard "
        "Sigma fields; map them to your agent-telemetry pipeline."
    )
    return ls


def _normalize_date(value) -> str:
    """ATR dates are YYYY/MM/DD or already ISO. Sigma wants ISO YYYY-MM-DD."""
    if value is None:
        return ""
    s = str(value).strip()
    m = re.match(r"^(\d{4})[/-](\d{1,2})[/-](\d{1,2})$", s)
    if m:
        return f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    return s


class _SigmaDumper(yaml.SafeDumper):
    """Dumper that keeps insertion order and avoids YAML anchors/aliases."""


def _ignore_aliases(self, data):  # noqa: ANN001
    return True


_SigmaDumper.ignore_aliases = _ignore_aliases


def dump_sigma(sigma: dict) -> str:
    return yaml.dump(
        sigma,
        Dumper=_SigmaDumper,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=100000,  # never wrap regex values
    )


def load_yaml(path: str) -> dict | None:
    try:
        doc = yaml.safe_load(open(path))
    except Exception as exc:  # noqa: BLE001
        print(f"WARN: could not parse {path}: {exc}", file=sys.stderr)
        return None
    return doc if isinstance(doc, dict) else None


def iter_rule_paths(explicit: list[str] | None, do_all: bool) -> list[str]:
    if explicit:
        return explicit
    if do_all:
        return sorted(glob.glob(RULES_GLOB, recursive=True))
    return []


def out_filename(atr_id: str, source_path: str) -> str:
    base = os.path.splitext(os.path.basename(source_path))[0]
    return f"{base}.sigma.yml"


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert ATR YAML rules to Sigma format.")
    parser.add_argument("--rule", action="append", default=[], help="path to a single ATR rule YAML (repeatable)")
    parser.add_argument("--all", action="store_true", help="convert every rule under rules/**/*.yaml")
    parser.add_argument("--out", help="output directory for one .sigma.yml per rule")
    parser.add_argument("--stdout", action="store_true", help="print all Sigma docs to stdout, --- separated")
    parser.add_argument("--quiet", action="store_true", help="suppress per-rule conversion warnings")
    args = parser.parse_args()

    paths = iter_rule_paths(args.rule or None, args.all)
    if not paths:
        parser.error("nothing to do: pass --rule <path> (repeatable) and/or --all")

    if args.out:
        os.makedirs(args.out, exist_ok=True)

    converted = 0
    total_warnings = 0
    stdout_chunks: list[str] = []

    for path in paths:
        doc = load_yaml(path)
        if doc is None:
            continue
        sigma, warnings = convert_rule(doc, path)
        text = dump_sigma(sigma)
        converted += 1
        total_warnings += len(warnings)

        if not args.quiet and warnings:
            for w in warnings:
                print(f"WARN [{doc.get('id','?')}]: {w}", file=sys.stderr)

        if args.out:
            fname = out_filename(str(doc.get("id", "")), path)
            with open(os.path.join(args.out, fname), "w") as fh:
                fh.write(text)
        if args.stdout or not args.out:
            stdout_chunks.append(text.rstrip() + "\n")

    if stdout_chunks and (args.stdout or not args.out):
        print("\n---\n".join(stdout_chunks))

    print(
        f"Converted {converted} ATR rule(s) to Sigma"
        + (f" -> {args.out}" if args.out else "")
        + f" ({total_warnings} conversion warning(s)).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
