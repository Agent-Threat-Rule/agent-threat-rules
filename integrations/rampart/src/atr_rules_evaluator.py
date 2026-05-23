"""ATR Rules Evaluator for RAMPART.

Loads detection rules from the Agent Threat Rules (ATR) corpus
(github.com/Agent-Threat-Rule/agent-threat-rules) and exposes them
as a RAMPART evaluator that asserts on rule violations.

ATR is an MIT-licensed open detection corpus (425+ rules across 10
categories) for AI agent threats. It is in production at Microsoft
Agent Governance Toolkit, Cisco AI Defense, MISP CIRCL, and others.
This evaluator lets RAMPART users plug ATR rules into pytest-native
red-team flows without re-implementing rule logic.

Usage:

    from atr_rules_evaluator import ATRRulesEvaluator

    @pytest.mark.parametrize("attack", ATTACK_PROMPTS)
    async def test_agent_blocks_atr_violations(agent, attack):
        result = await agent.run(attack)
        assert_does_not_match(
            result,
            evaluator=ATRRulesEvaluator(
                rules_dir="path/to/agent-threat-rules/rules",
                categories=["prompt-injection", "tool-poisoning"],
            ),
        )

References:
- ATR repo: https://github.com/Agent-Threat-Rule/agent-threat-rules
- Microsoft AGT precedent: microsoft/agent-governance-toolkit#1277 (ATR
  287-rule expansion merged 2026-04-26); #1981 (Copilot SWE Agent +
  ATR v2.1.2 closed CVE-disclosure-to-detection loop in 2h 16m
  2026-05-11).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from rampart.core.evaluator import BaseEvaluator
from rampart.core.types import EvalContext, EvalOutcome, EvalResult

if TYPE_CHECKING:
    from collections.abc import Iterable


_FIELD_RESPONSE = {"response", "llm_output", "model_output", "output"}
_FIELD_USER_INPUT = {"user_input", "prompt", "input"}
_FIELD_TOOL_CALL = {"tool_call", "tool_invocation", "tool_args"}


@dataclass(frozen=True)
class _CompiledRule:
    """Internal representation of a loaded ATR rule.

    Only the fields used at evaluation time. Full rule metadata is
    preserved via `raw` for evidence formatting.
    """

    rule_id: str
    title: str
    severity: str
    category: str
    field_target: str  # one of "response", "user_input", "tool_call"
    pattern: re.Pattern[str]
    description: str
    raw: dict[str, Any] = field(default_factory=dict[str, Any])


class ATRLoadError(Exception):
    """Raised when an ATR YAML rule cannot be parsed into an evaluable form.

    The evaluator skips unsupported rules silently by default; this
    exception is raised only when `strict=True` is passed and a rule
    cannot be compiled.
    """


class ATRRulesEvaluator(BaseEvaluator):
    """RAMPART evaluator backed by the ATR detection rule corpus.

    Loads YAML rules from a local directory (or a list of paths) and
    matches them against the current turn's response text, user input,
    or tool call arguments — depending on each rule's `detection.field`.

    A rule is considered to fire when any of its regex conditions
    match the targeted field. Rules with unsupported condition types
    (non-regex operators, multi-field joins) are skipped at load
    time. Pass `strict=True` to raise on skip instead of swallowing.

    Args:
        rules_dir: Directory containing `*.yaml` ATR rule files.
            The standard layout is `rules/<category>/ATR-YYYY-NNNNN-*.yaml`.
            Either `rules_dir` or `rule_paths` must be provided.
        rule_paths: Explicit list of YAML file paths. Useful when
            pinning to a specific rule subset. Mutually exclusive with
            `rules_dir`.
        categories: Optional allowlist of rule categories (e.g.
            `["prompt-injection", "tool-poisoning"]`). When omitted,
            all categories in `rules_dir` are loaded.
        min_severity: Optional minimum severity gate. One of "low",
            "medium", "high", "critical". Rules below the threshold
            are skipped at load time.
        strict: When True, raise `ATRLoadError` on the first rule
            that cannot be compiled. When False (default), skip
            unsupported rules silently and log to stderr.

    Raises:
        ValueError: If neither `rules_dir` nor `rule_paths` is given,
            or both are given. Also if `rules_dir` does not exist.
        ATRLoadError: When `strict=True` and any rule fails to compile.
    """

    _SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def __init__(
        self,
        *,
        rules_dir: str | Path | None = None,
        rule_paths: Iterable[str | Path] | None = None,
        categories: Iterable[str] | None = None,
        min_severity: str | None = None,
        strict: bool = False,
    ) -> None:
        if (rules_dir is None) == (rule_paths is None):
            msg = "Provide exactly one of rules_dir or rule_paths."
            raise ValueError(msg)

        self._category_allowlist = set(categories) if categories else None
        self._min_severity_rank = (
            self._SEVERITY_ORDER[min_severity.lower()]
            if min_severity is not None
            else None
        )
        self._strict = strict

        paths: list[Path]
        if rules_dir is not None:
            root = Path(rules_dir)
            if not root.is_dir():
                msg = f"rules_dir not found or not a directory: {root}"
                raise ValueError(msg)
            paths = sorted(root.rglob("*.yaml"))
        else:
            assert rule_paths is not None  # narrowed by the XOR above
            paths = [Path(p) for p in rule_paths]

        self._rules: list[_CompiledRule] = self._load_rules(paths)

    @property
    def loaded_rule_count(self) -> int:
        """Number of rules successfully compiled into this evaluator."""
        return len(self._rules)

    @property
    def loaded_rule_ids(self) -> list[str]:
        """Sorted list of rule IDs loaded into this evaluator."""
        return sorted(r.rule_id for r in self._rules)

    async def evaluate_async(self, *, context: EvalContext) -> EvalResult:
        """Return DETECTED if any loaded ATR rule matches the current turn.

        Walks every loaded rule, extracts the targeted field from the
        context, and checks the rule's compiled regex. Aggregates all
        matches into a single EvalResult so a single test failure can
        surface the full set of rule IDs that fired.
        """
        response_text = context.text
        user_input_text = self._extract_user_input(context)
        tool_call_blob = self._extract_tool_call_blob(context)

        matched: list[_CompiledRule] = []
        for rule in self._rules:
            target_text = self._select_target_text(
                rule.field_target,
                response_text=response_text,
                user_input_text=user_input_text,
                tool_call_blob=tool_call_blob,
            )
            if target_text and rule.pattern.search(target_text):
                matched.append(rule)

        if not matched:
            return EvalResult(
                outcome=EvalOutcome.NOT_DETECTED,
                rationale=(
                    f"No ATR rule matched (checked {len(self._rules)} rules "
                    "across response, user_input, and tool_call targets)."
                ),
            )

        return EvalResult(
            outcome=EvalOutcome.DETECTED,
            evidence=[self._format_evidence(m) for m in matched],
            rationale=(
                f"{len(matched)} ATR rule(s) matched: "
                + ", ".join(m.rule_id for m in matched)
            ),
        )

    # --- internals -----------------------------------------------------

    def _load_rules(self, paths: list[Path]) -> list[_CompiledRule]:
        compiled: list[_CompiledRule] = []
        for path in paths:
            try:
                rule = self._compile_one(path)
            except ATRLoadError as exc:
                if self._strict:
                    raise
                # Soft-skip: print to stderr but keep loading.
                import sys

                print(f"[ATRRulesEvaluator] skip {path.name}: {exc}", file=sys.stderr)
                continue
            if rule is not None:
                compiled.append(rule)
        return compiled

    def _compile_one(self, path: Path) -> _CompiledRule | None:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            msg = f"YAML parse error: {exc}"
            raise ATRLoadError(msg) from exc

        if not isinstance(raw, dict):
            msg = f"Top-level YAML is not a mapping: {type(raw).__name__}"
            raise ATRLoadError(msg)

        rule_id = raw.get("id")
        if not isinstance(rule_id, str):
            msg = "Missing or non-string `id` field."
            raise ATRLoadError(msg)

        category = self._extract_category(raw, path)
        if self._category_allowlist and category not in self._category_allowlist:
            return None

        severity = (raw.get("severity") or "medium").lower()
        if self._min_severity_rank is not None:
            rank = self._SEVERITY_ORDER.get(severity, 1)
            if rank < self._min_severity_rank:
                return None

        detection = raw.get("detection") or {}
        conditions = detection.get("conditions") or []
        if not isinstance(conditions, list) or not conditions:
            msg = "No detection.conditions entries."
            raise ATRLoadError(msg)

        # ATR conditions can be many; we compile the first regex
        # condition we find. Rules using only non-regex operators
        # (e.g. "ml_classifier", "ast") are skipped — they need a
        # different evaluator backend.
        regex_cond = next(
            (c for c in conditions if isinstance(c, dict) and c.get("operator") == "regex"),
            None,
        )
        if regex_cond is None:
            msg = "No regex-operator condition found (only regex is supported in v1)."
            raise ATRLoadError(msg)

        pattern_src = regex_cond.get("value")
        if not isinstance(pattern_src, str):
            msg = "Regex condition has non-string `value`."
            raise ATRLoadError(msg)

        try:
            pattern = re.compile(pattern_src, re.IGNORECASE | re.MULTILINE)
        except re.error as exc:
            msg = f"Regex compile failure: {exc}"
            raise ATRLoadError(msg) from exc

        field_target = self._normalize_field(regex_cond.get("field"))

        return _CompiledRule(
            rule_id=rule_id,
            title=str(raw.get("title", rule_id)),
            severity=severity,
            category=category,
            field_target=field_target,
            pattern=pattern,
            description=str(raw.get("description", "")).strip(),
            raw=raw,
        )

    @staticmethod
    def _extract_category(raw: dict[str, Any], path: Path) -> str:
        tags = raw.get("tags") or {}
        if isinstance(tags, dict):
            cat = tags.get("category")
            if isinstance(cat, str):
                return cat
        # Fallback: parent directory name.
        return path.parent.name

    @staticmethod
    def _normalize_field(field_name: Any) -> str:
        if isinstance(field_name, str):
            lower = field_name.lower()
            if lower in _FIELD_RESPONSE:
                return "response"
            if lower in _FIELD_USER_INPUT:
                return "user_input"
            if lower in _FIELD_TOOL_CALL:
                return "tool_call"
        # Default to response; that's the field RAMPART evaluators
        # most commonly inspect.
        return "response"

    @staticmethod
    def _extract_user_input(context: EvalContext) -> str:
        """Best-effort extraction of the user-side text from the latest turn.

        RAMPART's Turn type evolves; we try common attribute names
        and fall back to empty string when none are present.
        """
        turn = context.current_turn
        request = getattr(turn, "request", None)
        if request is None:
            return ""
        for attr in ("text", "prompt", "input", "content"):
            value = getattr(request, attr, None)
            if isinstance(value, str):
                return value
        return ""

    @staticmethod
    def _extract_tool_call_blob(context: EvalContext) -> str:
        """Concatenate all tool calls into a single searchable string.

        Each tool call rendered as `name(arg=value, ...)` so a single
        regex can match against tool names and argument payloads.
        """
        parts: list[str] = []
        for tc in context.all_tool_calls:
            name = getattr(tc, "name", None) or getattr(tc, "tool_name", "")
            args = getattr(tc, "args", None) or getattr(tc, "arguments", None) or {}
            if isinstance(args, dict):
                args_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
            else:
                args_str = str(args)
            parts.append(f"{name}({args_str})")
        return "\n".join(parts)

    @staticmethod
    def _select_target_text(
        field_target: str,
        *,
        response_text: str,
        user_input_text: str,
        tool_call_blob: str,
    ) -> str:
        if field_target == "user_input":
            return user_input_text
        if field_target == "tool_call":
            return tool_call_blob
        return response_text

    @staticmethod
    def _format_evidence(rule: _CompiledRule) -> str:
        return (
            f"[{rule.rule_id}] {rule.title} (severity={rule.severity}, "
            f"category={rule.category}, field={rule.field_target})"
        )
