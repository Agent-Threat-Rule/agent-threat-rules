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
import json
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


# ---------------------------------------------------------------------------
# RE2 portability
# ---------------------------------------------------------------------------
#
# Sigma is a source format; each backend compiles the `re` modifier to its own
# engine. Two engine families matter here and they disagree:
#
#   PCRE / Python re  -- understands \\uXXXX, lookaround, backreferences.
#   RE2 (Go, Rust)    -- spells the escape \\x{XXXX} and, being a finite
#                        automaton, cannot run lookaround or backreferences
#                        at all.
#
# So there is no single spelling that satisfies both, and silently picking one
# breaks the other. This emitter therefore keeps the source dialect by default
# and offers --regex-dialect re2 for RE2 backends, while ALWAYS recording what
# a RE2 backend cannot run. Reported via the existing conversion-warning
# mechanism plus an `atr.portability.*` tag, so a consumer learns a rule is
# unrunnable from the rule itself instead of from a compile error.

RE2_MAX_REPEAT = 1000

# The one blocker that --regex-dialect re2 removes by itself. Named rather than
# inlined because the end-of-run summary decides what "would unlock" means by
# comparing against it: if the two spellings drift apart, the summary silently
# starts counting zero, and a downstream RE2 consumer goes on believing the
# corpus is less portable than it is.
SPELLING_BLOCKER = (
    "JS-style \\uXXXX / (?<name> spelling; RE2 needs \\x{XXXX} / (?P<name> "
    "(re-run with --regex-dialect re2)"
)
_HEX4_RE = re.compile(r"[0-9a-fA-F]{4}")
_BRACED_HEX_RE = re.compile(r"\{([0-9a-fA-F]{1,6})\}")
_GROUP_NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)>")
_REPEAT_RE = re.compile(r"\{(\d+)(?:,(\d*))?\}")


def _scan_escape(rx: str, i: int, in_class: bool) -> tuple[tuple | None, str | None, int]:
    """Classify the escape starting at `rx[i]`. Returns (rewrite, blocker, next)."""
    nxt = rx[i + 1] if i + 1 < len(rx) else ""
    if nxt == "u":
        m = _BRACED_HEX_RE.match(rx, i + 2) or _HEX4_RE.match(rx, i + 2)
        if m:
            hexits = m.group(1) if m.re is _BRACED_HEX_RE else m.group(0)
            cp = int(hexits, 16)
            blocker = (
                f"\\u{hexits} is a UTF-16 surrogate; RE2 folds it to U+FFFD, so the "
                f"rewritten pattern compiles but can never match"
                if 0xD800 <= cp <= 0xDFFF
                else None
            )
            return (i, m.end(), "\\x{%s}" % hexits), blocker, m.end()
    if in_class and nxt in ("b", "B"):
        return None, f"\\{nxt} inside a character class is a backspace escape; RE2 rejects it", i + 2
    if nxt == "k" and rx[i + 2 : i + 3] == "<":
        return None, "named backreference \\k<name> requires backtracking; RE2 rejects it", i + 2
    if not in_class and nxt.isdigit() and nxt != "0":
        return None, f"backreference \\{nxt} requires backtracking; RE2 rejects it", i + 2
    return None, None, i + 2


def _scan_group(rx: str, i: int) -> tuple[tuple | None, str | None, int]:
    """Classify the group opener at `rx[i]`. Returns (rewrite, blocker, next)."""
    if rx[i : i + 4] in ("(?<=", "(?<!"):
        return None, "lookbehind requires backtracking; RE2 rejects it", i + 4
    if rx[i : i + 3] in ("(?=", "(?!"):
        return None, "lookahead requires backtracking; RE2 rejects it", i + 3
    if rx[i : i + 3] == "(?>":
        return None, "atomic group is not expressible in RE2", i + 3
    if rx[i : i + 3] == "(?<":
        m = _GROUP_NAME_RE.match(rx, i + 3)
        if m:
            return (i, m.end(), "(?P<%s>" % m.group(1)), None, m.end()
    return None, None, i + 1


def _scan_repeat(rx: str, i: int) -> tuple[str | None, int]:
    """Flag a `{n,m}` bound above RE2's hard cap. Returns (blocker, next)."""
    m = _REPEAT_RE.match(rx, i)
    if not m:
        return None, i + 1
    bounds = [int(m.group(1))] + ([int(m.group(2))] if m.group(2) else [])
    if any(b > RE2_MAX_REPEAT for b in bounds):
        return f"repeat bound {m.group(0)} exceeds RE2's limit of {RE2_MAX_REPEAT}", m.end()
    if rx[m.end() : m.end() + 1] == "+":
        return "possessive quantifier is not expressible in RE2", m.end() + 1
    return None, m.end()


def walk_regex(rx: str) -> tuple[list[tuple], list[str]]:
    """One escape/character-class-aware pass over `rx`.

    Returns the mechanically rewritable spans and the constructs RE2 cannot
    run. The walk (rather than a bare re.sub) is what keeps an ESCAPED
    backslash -- `\\\\u0041`, a rule hunting the literal text `\\u0041` -- from
    being mistaken for a unicode escape and silently corrupted.
    """
    rewrites: list[tuple] = []
    blockers: list[str] = []
    i, in_class = 0, False
    while i < len(rx):
        ch = rx[i]
        if ch == "\\":
            rw, bl, i = _scan_escape(rx, i, in_class)
            if rw:
                rewrites.append(rw)
            if bl:
                blockers.append(bl)
            continue
        if in_class:
            in_class = ch != "]"
            i += 1
            continue
        if ch == "[":
            in_class, i = True, i + 1
            continue
        if ch == "(":
            rw, bl, i = _scan_group(rx, i)
            if rw:
                rewrites.append(rw)
            if bl:
                blockers.append(bl)
            continue
        if ch == "{":
            bl, i = _scan_repeat(rx, i)
            if bl:
                blockers.append(bl)
            continue
        i += 1
    return rewrites, blockers


def rewrite_re2_escapes(pattern: str) -> str:
    """Apply the RE2 spelling of the two exactly-equivalent escape forms.

    Verified by scripts/verify-re2-equivalence.ts, which compares the original
    under JavaScript against the rewrite under Go's regexp over a per-pattern
    input battery. Never mutates the input.
    """
    rewrites, _ = walk_regex(pattern)
    out = pattern
    for start, end, replacement in reversed(rewrites):
        out = out[:start] + replacement + out[end:]
    return out


def re2_blockers(pattern: str) -> list[str]:
    """Constructs in `pattern` that no RE2 backend can run."""
    return walk_regex(pattern)[1]


# The static walk above catches what RE2 REFUSES TO COMPILE. It cannot catch
# the second, quieter failure mode: a pattern that compiles fine under RE2 but
# does not mean the same thing, because JavaScript and RE2 disagree about \s
# (Unicode vs ASCII), about UTF-16 surrogates, and about whether a bounded
# repeat counts code units or runes. Those only surface by running both engines
# over the same inputs, which is what scripts/verify-re2-equivalence.ts does.
# Its measured verdict is checked in here and consulted below, so a rule that
# would silently mis-detect downstream is tagged rather than shipped as clean.

EQUIVALENCE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "re2-equivalence.json",
)


def load_equivalence_divergences(path: str = EQUIVALENCE_PATH) -> dict:
    """Map rule id -> list of measured RE2 divergences. Absent file = empty."""
    try:
        with open(path, encoding="utf-8") as fh:
            return dict(json.load(fh).get("divergentRules", {}))
    except (OSError, ValueError):
        return {}


def measured_divergence_warnings(atr_id: str, divergences: dict) -> list[str]:
    """Warnings for conditions the differential run caught diverging under RE2."""
    return [
        "condition {loc} RE2-INCOMPATIBLE: {cause} (measured: {n}/{total} inputs "
        "disagree between JavaScript and RE2)".format(
            loc=entry.get("location", "?"),
            cause=cause,
            n=entry.get("mismatches", "?"),
            total=entry.get("inputs", "?"),
        )
        for entry in divergences.get(str(atr_id), [])
        for cause in entry.get("causes", [])
    ]


def emit_for_dialect(pattern: str, regex_dialect: str) -> tuple[str, list[str]]:
    """Return the pattern to emit plus what RE2 still cannot run afterwards.

    The portability verdict has to describe the pattern as EMITTED, not the
    source. Under --regex-dialect pcre a `\\uXXXX` escape is left alone, which
    is correct for PCRE/Python-re backends and still unreadable to RE2 -- so it
    counts as a blocker there and not under --regex-dialect re2. Tagging a rule
    re2-ok because its blocker happened to be fixable, without having fixed it,
    would be exactly the silent-failure this metadata exists to prevent.
    """
    rewrites, blockers = walk_regex(pattern)
    if regex_dialect == "re2":
        out = pattern
        for start, end, replacement in reversed(rewrites):
            out = out[:start] + replacement + out[end:]
        return out, blockers
    if rewrites:
        blockers = blockers + [SPELLING_BLOCKER]
    return pattern, blockers


def convert_conditions(atr_detection: dict, regex_dialect: str = "pcre") -> tuple[dict, str, list[str]]:
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
            pattern, blockers = emit_for_dialect(pattern, regex_dialect)
            for blocker in blockers:
                warnings.append(f"condition #{idx} RE2-INCOMPATIBLE: {blocker}")
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


def convert_rule(
    doc: dict,
    source_path: str,
    regex_dialect: str = "pcre",
    divergences: dict | None = None,
) -> tuple[dict, list[str]]:
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

    selections, condition_expr, cond_warnings = convert_conditions(atr_detection, regex_dialect)
    # The measured verdict describes the REWRITTEN spelling running on RE2, so
    # it applies to the re2 emission. Under pcre the same conditions are already
    # blocked for the earlier reason that RE2 cannot even parse \uXXXX.
    if regex_dialect == "re2":
        cond_warnings = cond_warnings + measured_divergence_warnings(
            atr_id, divergences if divergences is not None else load_equivalence_divergences()
        )
    warnings.extend(cond_warnings)
    re2_blocked = [w for w in cond_warnings if "RE2-INCOMPATIBLE" in w]

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
        # dict.fromkeys, not set(): `max` walks the container, so on a tie the
        # winner is whichever element the iteration reaches first. A set of
        # strings iterates in an order that depends on per-process hash
        # randomisation, so a rule whose top two surfaces tie -- 13 rules in the
        # corpus today, e.g. tool_args vs user_input -- would emit a different
        # logsource.category on different runs of the same code against the same
        # rule. That is phantom churn for any consumer diffing the export.
        # Insertion-ordered dedupe breaks the tie by first appearance in the
        # rule, which is both stable and the rule author's own ordering.
        primary = max(dict.fromkeys(fields_used), key=fields_used.count)
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
    # Portability is metadata, not a silent failure: a backend that compiles to
    # RE2 (Go/Rust, i.e. most SIEM backends) can read this tag and skip the rule
    # instead of erroring out mid-pipeline on a pattern it can never run.
    sigma_tags.append(
        "atr.portability.re2-blocked" if re2_blocked else "atr.portability.re2-ok"
    )

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
    if re2_blocked:
        # Two distinct failure modes, and conflating them would mislead: a
        # construct RE2 REFUSES TO COMPILE fails loudly, whereas a measured
        # dialect divergence compiles happily and quietly matches the wrong
        # set of inputs. The second is the dangerous one, so name it as such.
        reasons = sorted({w.split("RE2-INCOMPATIBLE: ", 1)[-1] for w in re2_blocked})
        measured = [r for r in reasons if "measured:" in r]
        uncompilable = [r for r in reasons if "measured:" not in r]
        provenance += " PORTABILITY: this rule is not safe to run on RE2-family backends (Go, Rust, and the Sigma backends built on them)."
        if uncompilable:
            provenance += " Cannot compile under RE2: " + "; ".join(uncompilable) + "."
        if measured:
            provenance += (
                " Compiles under RE2 but does NOT reproduce the original match "
                "behaviour, as measured by differential execution against the "
                "reference engine: " + "; ".join(measured) + "."
            )
        provenance += (
            " Such backends should skip this rule rather than emit a partial or "
            "silently incorrect detection; PCRE/Python-re backends are unaffected."
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


def rules_unlocked_by_re2_dialect(
    blocked_rules: list[dict], regex_dialect: str, divergences: dict
) -> list[str]:
    """Rule ids that --regex-dialect re2 would move from blocked to runnable.

    A rule qualifies only when escape spelling is its ONLY blocker: a rule that
    also uses lookaround or a backreference stays blocked in either dialect,
    and reporting it here would promise a downstream RE2 backend rules it still
    cannot run.

    Rules with a MEASURED divergence are excluded even though their only static
    blocker is the spelling. Those are the ones whose rewrite compiles under RE2
    and then matches a different language; the divergence warning is attached
    under --regex-dialect re2 only (under pcre they are already blocked for the
    earlier reason), so counting reasons alone would quietly over-promise by
    exactly that set. Excluding them is what keeps this number equal to what
    a real re2-dialect run produces.

    Returns [] under --regex-dialect re2: there is nothing left to advertise.
    """
    if regex_dialect != "pcre":
        return []
    return [
        r["id"]
        for r in blocked_rules
        if r["reasons"]
        and all(reason == SPELLING_BLOCKER for reason in r["reasons"])
        and not divergences.get(str(r["id"]))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert ATR YAML rules to Sigma format.")
    parser.add_argument("--rule", action="append", default=[], help="path to a single ATR rule YAML (repeatable)")
    parser.add_argument("--all", action="store_true", help="convert every rule under rules/**/*.yaml")
    parser.add_argument("--out", help="output directory for one .sigma.yml per rule")
    parser.add_argument("--stdout", action="store_true", help="print all Sigma docs to stdout, --- separated")
    parser.add_argument("--quiet", action="store_true", help="suppress per-rule conversion warnings")
    parser.add_argument(
        "--regex-dialect",
        choices=("pcre", "re2"),
        default="pcre",
        help=(
            "regex spelling to emit. pcre (default) keeps ATR's source dialect, which "
            "PCRE/Python-re backends understand. re2 rewrites \\uXXXX to \\x{XXXX} and "
            "(?<n> to (?P<n> for Go/Rust backends. Neither dialect can express "
            "lookaround or backreferences in RE2 -- those rules are tagged, not faked."
        ),
    )
    parser.add_argument(
        "--portability-report",
        help="write a JSON summary of RE2 portability across the converted rules",
    )
    args = parser.parse_args()

    paths = iter_rule_paths(args.rule or None, args.all)
    if not paths:
        parser.error("nothing to do: pass --rule <path> (repeatable) and/or --all")

    if args.out:
        os.makedirs(args.out, exist_ok=True)

    converted = 0
    total_warnings = 0
    stdout_chunks: list[str] = []
    blocked_rules: list[dict] = []
    divergences = load_equivalence_divergences()

    for path in paths:
        doc = load_yaml(path)
        if doc is None:
            continue
        sigma, warnings = convert_rule(doc, path, args.regex_dialect, divergences)
        text = dump_sigma(sigma)
        converted += 1
        total_warnings += len(warnings)
        reasons = sorted({w.split("RE2-INCOMPATIBLE: ", 1)[-1] for w in warnings if "RE2-INCOMPATIBLE" in w})
        if reasons:
            blocked_rules.append({"id": str(doc.get("id", "")), "path": path, "reasons": reasons})

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

    portable = converted - len(blocked_rules)
    coverage = (portable / converted * 100.0) if converted else 0.0
    would_unlock = rules_unlocked_by_re2_dialect(blocked_rules, args.regex_dialect, divergences)
    if args.portability_report:
        with open(args.portability_report, "w") as fh:
            json.dump(
                {
                    "regex_dialect": args.regex_dialect,
                    "rules_converted": converted,
                    "re2_portable": portable,
                    "re2_blocked": len(blocked_rules),
                    "re2_coverage_pct": round(coverage, 2),
                    "would_unlock_with_re2_dialect": would_unlock,
                    "blocked": blocked_rules,
                },
                fh,
                indent=2,
            )
            fh.write("\n")

    print(
        f"Converted {converted} ATR rule(s) to Sigma"
        + (f" -> {args.out}" if args.out else "")
        + f" ({total_warnings} conversion warning(s)).",
        file=sys.stderr,
    )
    print(
        f"RE2 portability: {portable}/{converted} rules runnable on RE2 backends "
        f"({coverage:.1f}%); {len(blocked_rules)} tagged atr.portability.re2-blocked.",
        file=sys.stderr,
    )
    if would_unlock:
        print(
            f"  {len(would_unlock)} of those {len(blocked_rules)} are blocked only by escape "
            f"spelling: re-run with --regex-dialect re2 to make them runnable "
            f"({portable + len(would_unlock)}/{converted}).",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
