#!/usr/bin/env python3
"""Tests for the ATR -> Sigma converter (scripts/generate-sigma.py).

Runnable two ways:
    python3 scripts/test_generate_sigma.py        # standalone, no pytest needed
    pytest scripts/test_generate_sigma.py         # under CI's pytest

What it checks (the load-bearing conversion guarantees):
  1. Converted output is valid YAML and re-parses to a mapping.
  2. Every Sigma-required / expected field is present (title, id, logsource,
     detection.condition, level, status), with values in Sigma's allowed sets.
  3. The ATT&CK join key round-trips: every enterprise ATT&CK id in the source
     ATR rule's references.mitre_attack appears as `attack.txxxx` in Sigma tags,
     and no bogus attack.* tag is minted from an ATLAS id.
  4. The near-universal leading `(?i)` in ATR regexes is turned into the Sigma
     `re|i` modifier, not left inline.
  5. The detection field names survive verbatim (no data loss on the surface).
"""
from __future__ import annotations

import glob
import importlib.util
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CONVERTER_PATH = os.path.join(HERE, "generate-sigma.py")

# Sigma's ratified value sets (from the Sigma rules specification).
SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
SIGMA_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
SIGMA_REQUIRED_TOPLEVEL = {"title", "logsource", "detection"}

# A representative, diverse sample of real ATR rules (kept small so the test is
# fast and deterministic, but spanning: enterprise ATT&CK id, ATLAS-only,
# code-exec, tool_description field, multi-condition).
SAMPLE_RULES = [
    "rules/agent-manipulation/ATR-2026-00030-cross-agent-attack.yaml",
    "rules/agent-manipulation/ATR-2026-00118-approval-fatigue.yaml",
    "rules/agent-manipulation/ATR-2026-00440-semantic-kernel-vector-store-eval-rce.yaml",
    "rules/agent-manipulation/ATR-2026-00074-cross-agent-privilege-escalation.yaml",
    "rules/agent-manipulation/ATR-2026-00119-social-engineering-via-agent.yaml",
]


def _load_converter():
    spec = importlib.util.spec_from_file_location("generate_sigma", CONVERTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


CONV = _load_converter()


def _abs(rel: str) -> str:
    return os.path.join(REPO, rel)


def _load_atr(rel: str) -> dict:
    with open(_abs(rel)) as fh:
        return yaml.safe_load(fh)


def _convert(rel: str):
    doc = _load_atr(rel)
    sigma, warnings = CONV.convert_rule(doc, _abs(rel))
    # Round-trip through YAML the same way the CLI writes it.
    text = CONV.dump_sigma(sigma)
    reparsed = yaml.safe_load(text)
    return doc, sigma, reparsed, warnings, text


def test_output_is_valid_yaml_mapping():
    for rel in SAMPLE_RULES:
        _, _, reparsed, _, _ = _convert(rel)
        assert isinstance(reparsed, dict), f"{rel}: Sigma output did not reparse to a mapping"


def test_required_fields_present_and_valid():
    for rel in SAMPLE_RULES:
        _, _, s, _, _ = _convert(rel)
        for field in SIGMA_REQUIRED_TOPLEVEL:
            assert field in s, f"{rel}: missing required Sigma field '{field}'"
        assert isinstance(s["title"], str) and s["title"], f"{rel}: empty title"
        assert len(s["title"]) <= 256, f"{rel}: title exceeds 256 chars"
        # id must be a UUID.
        assert re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            str(s["id"]),
        ), f"{rel}: id is not a UUID: {s['id']}"
        assert s["level"] in SIGMA_LEVELS, f"{rel}: level '{s['level']}' not a Sigma level"
        assert s["status"] in SIGMA_STATUSES, f"{rel}: status '{s['status']}' not a Sigma status"
        # detection must have a condition and at least one selection.
        det = s["detection"]
        assert "condition" in det, f"{rel}: detection has no condition"
        selections = [k for k in det if k != "condition"]
        assert selections, f"{rel}: detection has no selection blocks"
        # logsource must carry the custom agent product marker.
        assert s["logsource"].get("product") == "ai_agent", f"{rel}: logsource.product != ai_agent"


def _enterprise_attack_ids(atr_doc: dict) -> set[str]:
    refs = atr_doc.get("references") or {}
    ids = set()
    for entry in CONV.as_list(refs.get("mitre_attack")):
        tok = CONV.first_token(entry)
        if CONV.ATTACK_RE.match(tok):
            ids.add(tok.lower())
    return ids


def test_attack_join_key_roundtrips():
    for rel in SAMPLE_RULES:
        atr, s, _, _, _ = _convert(rel)
        expected = _enterprise_attack_ids(atr)
        attack_tags = {t.split(".", 1)[1] for t in s["tags"] if t.startswith("attack.")}
        assert expected <= attack_tags, (
            f"{rel}: enterprise ATT&CK ids {expected - attack_tags} from ATR "
            f"references.mitre_attack are missing from Sigma tags {attack_tags}"
        )


def test_no_bogus_attack_tag_from_atlas():
    # The cross-agent rule carries ATLAS ids (AML.Txxxx) but no enterprise
    # T1xxx; its Sigma output must not invent an attack.* tag.
    _, s, _, _, _ = _convert("rules/agent-manipulation/ATR-2026-00030-cross-agent-attack.yaml")
    attack_tags = [t for t in s["tags"] if t.startswith("attack.")]
    assert not attack_tags, f"minted bogus attack tags from ATLAS ids: {attack_tags}"
    # But the ATLAS ids must be preserved in the atlas.* namespace.
    atlas_tags = [t for t in s["tags"] if t.startswith("atlas.")]
    assert atlas_tags, "expected ATLAS ids preserved as atlas.* tags"


def test_case_insensitive_flag_becomes_re_i_modifier():
    """ATR patterns opening with (?i) must emit field|re|i, not a raw (?i)."""
    saw_re_i = False
    for rel in SAMPLE_RULES:
        atr, s, _, _, _ = _convert(rel)
        det = s["detection"]
        # Which ATR conditions started with (?i)?
        atr_conds = CONV.as_list((atr.get("detection") or {}).get("conditions"))
        for idx, cond in enumerate(atr_conds, start=1):
            if not isinstance(cond, dict) or str(cond.get("operator", "")).lower() != "regex":
                continue
            val = str(cond.get("value", ""))
            sel = det.get(f"sel_{idx}")
            if sel is None:
                continue
            keys = list(sel.keys())
            assert len(keys) == 1, f"{rel} sel_{idx}: expected exactly one field key"
            key = keys[0]
            if re.match(r"^\(\?[a-zA-Z]*i[a-zA-Z]*\)", val):
                assert key.endswith("|re|i"), (
                    f"{rel} sel_{idx}: source had inline (?i) but Sigma key is '{key}'"
                )
                # And the emitted pattern must no longer carry the bare (?i).
                assert not str(sel[key]).startswith("(?i)"), (
                    f"{rel} sel_{idx}: (?i) was not stripped from the pattern"
                )
                saw_re_i = True
            else:
                assert key.endswith("|re") or "|re|" in key, (
                    f"{rel} sel_{idx}: regex condition not emitted with re modifier: '{key}'"
                )
    assert saw_re_i, "sample did not exercise the (?i) -> re|i path; sample is unrepresentative"


def test_detection_field_names_survive():
    """The ATR detection field (content, tool_description, ...) must appear
    verbatim as the Sigma detection field name (before the | modifier)."""
    for rel in SAMPLE_RULES:
        atr, s, _, _, _ = _convert(rel)
        det = s["detection"]
        atr_conds = CONV.as_list((atr.get("detection") or {}).get("conditions"))
        for idx, cond in enumerate(atr_conds, start=1):
            if not isinstance(cond, dict):
                continue
            field = cond.get("field") or cond.get("detection_field") or "content"
            sel = det.get(f"sel_{idx}")
            if sel is None:
                continue
            key = list(sel.keys())[0]
            emitted_field = key.split("|", 1)[0]
            assert emitted_field == field, (
                f"{rel} sel_{idx}: field '{field}' became '{emitted_field}'"
            )


def test_pysigma_parses_output_when_available():
    """If pySigma is installed, the emitted rules must parse into real
    SigmaRule objects with no errors. Skipped (not failed) when pySigma is
    absent, so the test suite still runs in a minimal environment."""
    try:
        from sigma.rule import SigmaRule  # type: ignore
    except Exception:  # noqa: BLE001 - pySigma optional
        print("  (skip: pySigma not installed)")
        return
    for rel in SAMPLE_RULES:
        _, _, _, _, text = _convert(rel)
        rule = SigmaRule.from_yaml(text)
        errors = getattr(rule, "errors", [])
        assert not errors, f"{rel}: pySigma reported errors: {errors}"
        assert rule.title, f"{rel}: pySigma parsed an empty title"
        assert str(rule.level).lower().split(".")[-1] in SIGMA_LEVELS, (
            f"{rel}: pySigma level not recognised: {rule.level}"
        )


def test_whole_corpus_converts_without_crashing():
    """Sanity: every rule in the repo converts to a reparseable Sigma mapping.
    This is the guard that a schema drift in some rule does not silently break
    the converter -- it is allowed to emit warnings, but never crash or produce
    invalid YAML."""
    paths = sorted(glob.glob(os.path.join(REPO, "rules", "**", "*.yaml"), recursive=True))
    assert paths, "no ATR rules found; test environment is wrong"
    failures = []
    for path in paths:
        try:
            doc = yaml.safe_load(open(path))
            if not isinstance(doc, dict):
                continue
            sigma, _ = CONV.convert_rule(doc, path)
            reparsed = yaml.safe_load(CONV.dump_sigma(sigma))
            if not isinstance(reparsed, dict):
                failures.append(f"{path}: did not reparse to mapping")
            elif reparsed.get("level") not in SIGMA_LEVELS:
                failures.append(f"{path}: bad level {reparsed.get('level')}")
            elif reparsed.get("status") not in SIGMA_STATUSES:
                failures.append(f"{path}: bad status {reparsed.get('status')}")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{path}: raised {exc!r}")
    assert not failures, "corpus conversion failures:\n" + "\n".join(failures[:20])


def _run_standalone() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        try:
            t()
        except AssertionError as exc:
            print(f"FAIL {t.__name__}: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR {t.__name__}: {exc!r}", file=sys.stderr)
            return 1
        passed += 1
        print(f"ok   {t.__name__}")
    print(f"\n{passed}/{len(tests)} converter tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
