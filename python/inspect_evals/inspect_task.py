"""
UK AISI Inspect @task wrapper for the Agent Threat Rules (ATR) detection corpus.

Loads ATR YAML rules directly via PyYAML, samples canonical adversarial prompts from
each rule's `test_cases.true_positives`, and scores model outputs (or raw inputs) for
ATR detection coverage via regex match against the rule corpus.

Usage:
    pip install inspect-ai pyyaml
    inspect eval python/inspect_task.py:atr_prompt_injection --limit 10

Module structure stays minimal so the wrapper survives ATR rule-corpus growth without
schema drift: every new rule with `test_cases.true_positives` is picked up automatically.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable

import yaml

from inspect_ai import Task, task
from inspect_ai.dataset import Sample, MemoryDataset
from inspect_ai.scorer import Score, Target, accuracy, scorer, mean
from inspect_ai.solver import TaskState, generate, solver


# ---------------------------------------------------------------------------
# Rule corpus loading
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_DIR = REPO_ROOT / "rules"

# Sampling cap per rule so a single high-cardinality rule cannot dominate the
# distribution. Each ATR rule averages ~10 true_positive samples.
MAX_TP_PER_RULE = 4

# Minimum total sample count we require; if the corpus has grown but we cap
# per-rule, this floor ensures we still produce a useful dataset.
MIN_TOTAL_SAMPLES = 100


class CompiledRule:
    """A single ATR rule with its detection regexes pre-compiled."""

    __slots__ = ("rule_id", "title", "category", "severity", "patterns")

    def __init__(
        self,
        rule_id: str,
        title: str,
        category: str,
        severity: str,
        patterns: tuple[re.Pattern[str], ...],
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.category = category
        self.severity = severity
        self.patterns = patterns

    def matches(self, text: str) -> bool:
        return any(p.search(text) for p in self.patterns)


def _iter_rule_files(rules_dir: Path) -> Iterable[Path]:
    for path in sorted(rules_dir.rglob("*.yaml")):
        yield path
    for path in sorted(rules_dir.rglob("*.yml")):
        yield path


def _extract_regex_values(detection: dict[str, Any]) -> list[str]:
    """Pull every detection.conditions[].value where operator is regex.

    ATR uses two condition shapes:
      (a) array form: [{field, operator, value}, ...]
      (b) named-map form: {name: {field, patterns, match_type}, ...}
    We extract (a) here -- it is what every prompt-injection-style rule uses.
    Named-map rules that ship pattern lists also get covered via `patterns`.
    """
    values: list[str] = []
    conditions = detection.get("conditions")

    if isinstance(conditions, list):
        for cond in conditions:
            if not isinstance(cond, dict):
                continue
            op = cond.get("operator")
            val = cond.get("value")
            if op == "regex" and isinstance(val, str):
                values.append(val)
        return values

    if isinstance(conditions, dict):
        for cond in conditions.values():
            if not isinstance(cond, dict):
                continue
            match_type = cond.get("match_type")
            patterns = cond.get("patterns")
            if match_type == "regex" and isinstance(patterns, list):
                for p in patterns:
                    if isinstance(p, str):
                        values.append(p)
    return values


def _compile_safely(pattern: str) -> re.Pattern[str] | None:
    """Compile a regex from ATR YAML; return None if Python rejects it.

    ATR patterns are written in JavaScript-flavoured regex (the engine is
    TypeScript). The vast majority are PCRE-compatible and compile cleanly in
    Python re; a small minority use JS-only constructs. We skip those rather
    than fail the whole corpus.
    """
    try:
        return re.compile(pattern)
    except re.error:
        return None


def load_compiled_rules(rules_dir: Path = RULES_DIR) -> list[CompiledRule]:
    compiled: list[CompiledRule] = []
    for rule_path in _iter_rule_files(rules_dir):
        try:
            with rule_path.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(raw, dict):
            continue
        if raw.get("status") == "deprecated":
            continue

        detection = raw.get("detection")
        if not isinstance(detection, dict):
            continue

        regex_strings = _extract_regex_values(detection)
        patterns: list[re.Pattern[str]] = []
        for pat in regex_strings:
            compiled_pat = _compile_safely(pat)
            if compiled_pat is not None:
                patterns.append(compiled_pat)
        if not patterns:
            continue

        tags = raw.get("tags") or {}
        compiled.append(
            CompiledRule(
                rule_id=str(raw.get("id", rule_path.stem)),
                title=str(raw.get("title", "")),
                category=str(tags.get("category", "unknown")),
                severity=str(raw.get("severity", "medium")),
                patterns=tuple(patterns),
            )
        )
    return compiled


# ---------------------------------------------------------------------------
# Dataset construction
# ---------------------------------------------------------------------------


def _sample_text(case: dict[str, Any]) -> str | None:
    """Pick the most useful text field from a true_positive case.

    Test cases vary by category: prompt-injection rules use `input`,
    context-exfiltration rules use `agent_output`, tool-poisoning uses
    `tool_args` or `tool_response`. We coalesce so every rule contributes.
    """
    for key in ("input", "agent_output", "tool_response", "tool_args"):
        val = case.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return None


def build_dataset(rules_dir: Path = RULES_DIR) -> MemoryDataset:
    samples: list[Sample] = []

    for rule_path in _iter_rule_files(rules_dir):
        try:
            with rule_path.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(raw, dict):
            continue
        if raw.get("status") == "deprecated":
            continue

        test_cases = raw.get("test_cases") or {}
        true_positives = test_cases.get("true_positives") or []
        if not isinstance(true_positives, list):
            continue

        tags = raw.get("tags") or {}
        category = str(tags.get("category", "unknown"))
        rule_id = str(raw.get("id", rule_path.stem))

        picked = 0
        for case in true_positives:
            if not isinstance(case, dict):
                continue
            text = _sample_text(case)
            if text is None:
                continue
            samples.append(
                Sample(
                    input=text,
                    target="triggered",
                    metadata={
                        "rule_id": rule_id,
                        "category": category,
                        "severity": str(raw.get("severity", "medium")),
                        "case_description": str(case.get("description", "")),
                    },
                )
            )
            picked += 1
            if picked >= MAX_TP_PER_RULE:
                break

    if len(samples) < MIN_TOTAL_SAMPLES:
        # Surface a clear signal at construction time rather than at eval-time.
        raise RuntimeError(
            f"ATR corpus produced only {len(samples)} samples; "
            f"expected >= {MIN_TOTAL_SAMPLES}. Check {rules_dir} layout."
        )

    return MemoryDataset(samples)


# ---------------------------------------------------------------------------
# Solver + scorer
# ---------------------------------------------------------------------------


@solver
def echo_input():
    """Default solver: pass the sample input straight through as completion.

    For ATR detection coverage we are scoring whether ATR rules match the
    adversarial prompt itself (a corpus-coverage metric). When a model is
    supplied (e.g. `--model openai/gpt-4o`) you can swap this for `generate()`
    to score detection on model output instead.
    """

    async def solve(state: TaskState, generate_fn):  # type: ignore[no-untyped-def]
        state.output.completion = state.input_text
        return state

    return solve


_RULES_CACHE: list[CompiledRule] | None = None


def _get_rules() -> list[CompiledRule]:
    global _RULES_CACHE
    if _RULES_CACHE is None:
        _RULES_CACHE = load_compiled_rules()
    return _RULES_CACHE


@scorer(metrics=[accuracy(), mean()])
def atr_detection_scorer():
    """Score 1.0 if any ATR rule regex matches the model output (or input)."""

    async def score(state: TaskState, target: Target) -> Score:
        text = state.output.completion or state.input_text
        rules = _get_rules()
        matched_ids: list[str] = []
        for rule in rules:
            if rule.matches(text):
                matched_ids.append(rule.rule_id)
                if len(matched_ids) >= 5:
                    break

        triggered = bool(matched_ids)
        return Score(
            value=1.0 if triggered else 0.0,
            answer="triggered" if triggered else "not_triggered",
            explanation=(
                f"Matched ATR rules: {', '.join(matched_ids)}"
                if triggered
                else "No ATR rule matched"
            ),
            metadata={"matched_rules": matched_ids},
        )

    return score


# ---------------------------------------------------------------------------
# Public @task
# ---------------------------------------------------------------------------


@task
def atr_prompt_injection() -> Task:
    """ATR rule-corpus coverage evaluation.

    Loads adversarial prompts from every ATR rule's `test_cases.true_positives`
    across 10 categories (prompt-injection, tool-poisoning, context-exfiltration,
    agent-manipulation, privilege-escalation, excessive-autonomy, data-poisoning,
    model-abuse, skill-compromise, model-security) and scores ATR detection
    coverage. The reported `accuracy` is the share of canonical adversarial
    prompts the ATR corpus matches. Those prompts are the rules' own true
    positives, so read it like ATR's self-test recall, not like the external
    corpora in the README's evaluation section (section 8), which gives each
    recall in two lanes: `hunt`, the engine default that loads every rule
    maturity, and `enforce`, the lane for blocking, which loads only stable rules.
    """
    dataset = build_dataset()
    return Task(
        dataset=dataset,
        solver=[echo_input()],
        scorer=atr_detection_scorer(),
    )


if __name__ == "__main__":  # pragma: no cover
    rules = _get_rules()
    ds = build_dataset()
    print(f"Loaded {len(rules)} ATR rules with compilable regex patterns")
    print(f"Built {len(ds)} samples across categories:")
    counts: dict[str, int] = {}
    for s in ds.samples:
        cat = s.metadata.get("category", "unknown") if s.metadata else "unknown"
        counts[cat] = counts.get(cat, 0) + 1
    for cat, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {cat}: {n}")
