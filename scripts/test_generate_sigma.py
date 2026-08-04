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
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

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


def _re2_regexes(rel: str, dialect: str) -> tuple[list[str], bool]:
    """Emitted regex patterns for one rule, plus whether it is tagged blocked."""
    doc = _load_atr(rel)
    sigma, _ = CONV.convert_rule(doc, _abs(rel), dialect)
    blocked = "atr.portability.re2-blocked" in (sigma.get("tags") or [])
    patterns = [
        val
        for key, sel in sigma["detection"].items()
        if key != "condition" and isinstance(sel, dict)
        for field, val in sel.items()
        if "|re" in field and isinstance(val, str)
    ]
    return patterns, blocked


def test_every_rule_carries_a_portability_tag():
    """A consumer must be able to tell RE2-runnable from not, per rule."""
    for rel in SAMPLE_RULES:
        _, s, _, _, _ = _convert(rel)
        marks = [t for t in s["tags"] if t.startswith("atr.portability.re2-")]
        assert len(marks) == 1, f"{rel}: expected exactly one portability tag, got {marks}"


def test_re2_dialect_rewrites_unicode_escapes():
    """--regex-dialect re2 emits RE2's escape spelling; pcre leaves it alone."""
    rel = "rules/prompt-injection/ATR-2026-00258-unicode-tag-injection.yaml"
    pcre_pats, _ = _re2_regexes(rel, "pcre")
    re2_pats, _ = _re2_regexes(rel, "re2")
    assert any("\\u{E0000}" in p for p in pcre_pats), "pcre dialect should keep \\u{...}"
    assert any("\\x{E0000}" in p for p in re2_pats), "re2 dialect should emit \\x{...}"
    assert not any("\\u{" in p for p in re2_pats), "re2 dialect must not leave \\u{...} behind"


def test_would_unlock_counts_only_spelling_only_blockers():
    """The advertised count must never include a rule RE2 still cannot run.

    A rule whose blockers include a lookaround stays blocked in both dialects,
    so promising it to a downstream RE2 backend would be a lie the backend only
    discovers at compile time.
    """
    spelling = CONV.SPELLING_BLOCKER
    blocked = [
        {"id": "SPELLING-ONLY", "path": "x", "reasons": [spelling]},
        {"id": "ALSO-LOOKAROUND", "path": "x", "reasons": [spelling, "lookahead ... RE2 rejects it"]},
        {"id": "LOOKAROUND-ONLY", "path": "x", "reasons": ["lookahead ... RE2 rejects it"]},
    ]
    got = CONV.rules_unlocked_by_re2_dialect(blocked, "pcre", {})
    assert got == ["SPELLING-ONLY"], f"expected only the spelling-only rule, got {got}"


def test_would_unlock_excludes_measured_divergences():
    """A rewrite that compiles under RE2 and then matches a different language
    is not an unlock. Those carry their divergence warning only under the re2
    dialect, so counting reasons alone would over-promise by exactly that set.
    """
    blocked = [
        {"id": "CLEAN", "path": "x", "reasons": [CONV.SPELLING_BLOCKER]},
        {"id": "DIVERGENT", "path": "x", "reasons": [CONV.SPELLING_BLOCKER]},
    ]
    got = CONV.rules_unlocked_by_re2_dialect(blocked, "pcre", {"DIVERGENT": [{"causes": ["differs"]}]})
    assert got == ["CLEAN"], f"divergent rule must not be advertised as an unlock, got {got}"


def test_would_unlock_is_empty_under_re2_dialect():
    """Nothing left to advertise once the run already emits RE2 spelling."""
    blocked = [{"id": "SPELLING-ONLY", "path": "x", "reasons": [CONV.SPELLING_BLOCKER]}]
    assert CONV.rules_unlocked_by_re2_dialect(blocked, "re2", {}) == []


def test_would_unlock_matches_a_real_re2_dialect_run():
    """The number the summary advertises has to equal what actually happens.

    Converts the whole corpus twice and asserts that the set the pcre run says
    would unlock is exactly the set that stops being blocked under re2 -- so the
    claim is an identity, not an estimate.
    """
    out = tempfile.mkdtemp(prefix="atr-sigma-unlock-")
    try:
        reports = {}
        for dialect in ("pcre", "re2"):
            rep = os.path.join(out, f"{dialect}.json")
            subprocess.run(
                [sys.executable, os.path.join(REPO, "scripts", "generate-sigma.py"),
                 "--all", "--out", os.path.join(out, dialect), "--quiet",
                 "--regex-dialect", dialect, "--portability-report", rep],
                cwd=REPO, check=True, capture_output=True,
            )
            with open(rep) as fh:
                reports[dialect] = json.load(fh)
        blocked_pcre = {r["id"] for r in reports["pcre"]["blocked"]}
        blocked_re2 = {r["id"] for r in reports["re2"]["blocked"]}
        advertised = set(reports["pcre"]["would_unlock_with_re2_dialect"])
        assert advertised == blocked_pcre - blocked_re2, (
            "advertised unlock set != rules that actually stop being blocked: "
            f"over-promised {sorted(advertised - (blocked_pcre - blocked_re2))}, "
            f"missed {sorted((blocked_pcre - blocked_re2) - advertised)}"
        )
        assert not reports["re2"]["would_unlock_with_re2_dialect"]
    finally:
        shutil.rmtree(out, ignore_errors=True)

def test_logsource_category_is_stable_across_processes():
    """The same rule must convert to the same logsource.category every run.

    `max()` walks its container, so a tie is decided by iteration order. Over a
    set of strings that order depends on per-process hash randomisation, which
    made rules whose top two detection surfaces tie (tool_args vs user_input and
    friends) emit a different category on different runs of identical code.
    Downstream consumers diff these exports, so the churn looks like a rule
    change that never happened.

    Asserted across separate interpreters with different PYTHONHASHSEEDs,
    because within one process the order is already fixed.
    """
    tied = "rules/prompt-injection/ATR-2026-00395-llm-special-token-boundary-injection.yaml"
    if not os.path.exists(_abs(tied)):
        print(f"   (skipped: {tied} no longer in corpus)", file=sys.stderr)
        return
    seen = set()
    for seed in ("0", "1", "42", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, "scripts", "generate-sigma.py"),
             "--rule", _abs(tied), "--stdout", "--quiet"],
            cwd=REPO, check=True, capture_output=True, text=True, env=env,
        )
        doc = yaml.safe_load(proc.stdout)
        seen.add(doc["logsource"].get("category"))
    assert len(seen) == 1, f"logsource.category varies with PYTHONHASHSEED: {sorted(seen)}"


def test_no_untagged_rule_fails_re2_compilation():
    """The load-bearing guarantee: an RE2 backend that honours the
    `atr.portability.re2-blocked` tag never hits a pattern it cannot compile.

    A rule that fails to compile while advertising itself as runnable is the
    exact silent failure this metadata exists to prevent, so it is asserted
    against the real engine rather than against our own classifier.
    """
    if shutil.which("go") is None:
        print("   (skipped: no Go toolchain for the RE2 oracle)", file=sys.stderr)
        return
    go_src = (
        "package main\n"
        'import ("encoding/json";"os";"regexp")\n'
        "func main(){var in []string\n"
        " if err:=json.NewDecoder(os.Stdin).Decode(&in);err!=nil{os.Exit(2)}\n"
        " out:=make([]bool,0,len(in))\n"
        " for _,p:=range in{_,err:=regexp.Compile(p);out=append(out,err==nil)}\n"
        " json.NewEncoder(os.Stdout).Encode(out)}\n"
    )
    paths = sorted(glob.glob(os.path.join(REPO, "rules", "**", "*.yaml"), recursive=True))
    flat: list[str] = []
    owners: list[tuple[str, bool]] = []
    for path in paths:
        pats, blocked = _re2_regexes(os.path.relpath(path, REPO), "re2")
        flat.extend(pats)
        owners.extend((os.path.basename(path), blocked) for _ in pats)
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "main.go")
        with open(src, "w") as fh:
            fh.write(go_src)
        proc = subprocess.run(
            ["go", "run", src], input=json.dumps(flat), capture_output=True, text=True
        )
        assert proc.returncode == 0, f"RE2 oracle failed: {proc.stderr[:300]}"
        ok = json.loads(proc.stdout)
    untagged = [owners[i][0] for i, good in enumerate(ok) if not good and not owners[i][1]]
    assert not untagged, (
        f"{len(untagged)} pattern(s) are rejected by RE2 on rules NOT tagged "
        f"re2-blocked (silent failure): {sorted(set(untagged))[:10]}"
    )


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
