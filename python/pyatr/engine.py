"""Core ATR engine -- Layer 1 (regex/pattern) detection only."""

from __future__ import annotations

import json
import logging
import os
import re
import unicodedata
from pathlib import Path
from typing import Any

import yaml

from pyatr.types import (
    ATRMatch,
    ATRRule,
    AgentEvent,
    Condition,
    EVENT_TYPE_TO_FIELD,
    SEVERITY_ORDER,
)

logger = logging.getLogger(__name__)

# Zero-width and bidi characters to strip during normalization.
_ZERO_WIDTH_RE = re.compile(
    "[\u200b\u200c\u200d\ufeff\u2060\u180e\u200e\u200f"
    "\u202a-\u202e\u2066-\u2069]"
)

# Inline flags prefix that JS RegExp does not support natively.
_INLINE_FLAGS_RE = re.compile(r"^\(\?[imsx]+\)")


def _normalize_unicode(text: str) -> str:
    """NFC-normalize and strip zero-width / bidi characters."""
    return _ZERO_WIDTH_RE.sub("", unicodedata.normalize("NFC", text))


def _compile_regex(pattern: str) -> re.Pattern[str]:
    """Compile an ATR regex pattern, stripping (?i) prefix and using IGNORECASE."""
    cleaned = _INLINE_FLAGS_RE.sub("", pattern)
    return re.compile(cleaned, re.IGNORECASE)


def _load_yaml_file(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _parse_conditions(raw: list[dict[str, Any]]) -> tuple[Condition, ...]:
    result: list[Condition] = []
    for item in raw:
        result.append(
            Condition(
                field=str(item.get("field", "")),
                operator=str(item.get("operator", "")),
                value=str(item.get("value", "")),
                description=str(item.get("description", "")),
            )
        )
    return tuple(result)


def _parse_rule(data: dict[str, Any]) -> ATRRule:
    detection = data.get("detection", {})
    raw_conditions = detection.get("conditions", [])
    condition_logic = str(detection.get("condition", "any"))
    tags = data.get("tags", {})
    if not isinstance(tags, dict):
        tags = {}

    return ATRRule(
        id=str(data.get("id", "")),
        title=str(data.get("title", "")),
        severity=str(data.get("severity", "medium")).lower(),
        description=str(data.get("description", "")),
        status=str(data.get("status", "")),
        conditions=_parse_conditions(raw_conditions),
        condition_logic=condition_logic,
        tags={str(k): str(v) for k, v in tags.items()},
        references=data.get("references", {}),
        response=data.get("response", {}),
    )


def _read_bundled_rules() -> list[dict[str, Any]]:
    """Read the rules JSON bundled inside the installed package, if present.

    Returns an empty list when no bundle ships with the install (e.g. an
    editable checkout that has not run ``scripts/bundle_rules.py``).
    """
    try:
        import importlib.resources as ir

        resource = ir.files(__package__).joinpath("_bundled_rules.json")
        if resource.is_file():
            return json.loads(resource.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("pyatr: could not read bundled rules: %s", exc)
    return []


class ATREngine:
    """Layer 1 (pattern-only) ATR evaluation engine."""

    def __init__(self) -> None:
        self._rules: list[ATRRule] = []
        # Pre-compiled regex cache: rule_id -> list of (condition_index, compiled_re)
        self._compiled: dict[str, list[tuple[int, re.Pattern[str]]]] = {}

    @property
    def rules(self) -> list[ATRRule]:
        return list(self._rules)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_rules_from_directory(self, directory: str | Path) -> int:
        """Recursively load all .yaml/.yml ATR rule files from *directory*.

        Returns the number of rules loaded.
        """
        directory = Path(directory)
        count = 0
        for root, _dirs, files in os.walk(directory):
            for fname in sorted(files):
                if not (fname.endswith(".yaml") or fname.endswith(".yml")):
                    continue
                path = Path(root) / fname
                try:
                    data = _load_yaml_file(path)
                    if not isinstance(data, dict) or "id" not in data:
                        continue
                    rule = _parse_rule(data)
                    self._add_rule(rule)
                    count += 1
                except Exception:
                    # Skip unparseable files silently.
                    continue
        return count

    def load_rule(self, rule: ATRRule) -> None:
        """Add a single pre-built rule."""
        self._add_rule(rule)

    def load_bundled_rules(self) -> int:
        """Load the rule set bundled inside the installed pyatr package.

        Returns the number of rules loaded (0 when no bundle is present).
        """
        count = 0
        for raw in _read_bundled_rules():
            if not isinstance(raw, dict) or "id" not in raw:
                continue
            try:
                self._add_rule(_parse_rule(raw))
                count += 1
            except Exception:  # pragma: no cover - defensive
                continue
        return count

    def load_default_rules(self) -> int:
        """Load rules from the best available source.

        Order: (1) the rule set bundled in the installed package, then
        (2) the canonical ``rules/`` directory when running from a source
        checkout. Emits a warning -- never fails silently -- when neither
        yields a rule, so a zero-rule engine is visible rather than quietly
        reporting "no threats found".
        """
        count = self.load_bundled_rules()
        if count == 0:
            dev_dir = Path(__file__).resolve().parent.parent.parent / "rules"
            if dev_dir.is_dir():
                count = self.load_rules_from_directory(dev_dir)
        if count == 0:
            logger.warning(
                "pyatr loaded 0 rules: no in-package bundle and no source-tree "
                "rules/ directory found, so scan() will not match anything. "
                "Install pyatr from PyPI (the wheel bundles the rules) or run "
                "scripts/bundle_rules.py in a source checkout."
            )
        return count

    def _add_rule(self, rule: ATRRule) -> None:
        self._rules.append(rule)
        compiled: list[tuple[int, re.Pattern[str]]] = []
        for idx, cond in enumerate(rule.conditions):
            if cond.operator == "regex":
                try:
                    compiled.append((idx, _compile_regex(cond.value)))
                except re.error:
                    pass
        self._compiled[rule.id] = compiled

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, event: AgentEvent) -> list[ATRMatch]:
        """Evaluate *event* against all loaded rules.

        Returns matched rules sorted by severity (critical first).
        """
        matches: list[ATRMatch] = []
        for rule in self._rules:
            # Parity with the TS engine: deprecated/draft rules never fire.
            if rule.status in ("deprecated", "draft"):
                continue
            match = self._evaluate_rule(rule, event)
            if match is not None:
                matches.append(match)
        matches.sort(key=lambda m: SEVERITY_ORDER.get(m.severity, 99))
        return matches

    def _evaluate_rule(self, rule: ATRRule, event: AgentEvent) -> ATRMatch | None:
        matched_patterns: list[str] = []
        condition_results: list[bool] = []

        for idx, cond in enumerate(rule.conditions):
            raw_value = self._resolve_field(cond.field, event)
            if raw_value is None:
                condition_results.append(False)
                continue
            normalized = _normalize_unicode(raw_value)
            hit = self._test_condition(rule.id, idx, cond, normalized, raw_value)
            condition_results.append(hit)
            if hit:
                matched_patterns.append(cond.value)

        triggered: bool
        if rule.condition_logic == "all":
            triggered = len(condition_results) > 0 and all(condition_results)
        else:  # "any"
            triggered = any(condition_results)

        if not triggered:
            return None

        confidence = rule.tags.get("confidence", "medium")
        return ATRMatch(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=confidence,
            matched_patterns=tuple(matched_patterns),
            description=rule.description,
            tags=rule.tags,
        )

    def _test_condition(
        self,
        rule_id: str,
        idx: int,
        cond: Condition,
        normalized: str,
        raw: str,
    ) -> bool:
        op = cond.operator

        if op == "regex":
            return self._test_regex(rule_id, idx, cond.value, normalized, raw)
        elif op == "contains":
            target = cond.value.lower()
            return target in normalized.lower() or target in raw.lower()
        elif op == "exact":
            return normalized == cond.value or raw == cond.value
        elif op == "starts_with":
            target = cond.value.lower()
            return normalized.lower().startswith(target) or raw.lower().startswith(target)
        elif op in ("gt", "lt", "gte", "lte", "eq"):
            try:
                field_num = float(normalized)
                threshold = float(cond.value)
            except (ValueError, TypeError):
                return False
            if op == "gt": return field_num > threshold
            if op == "lt": return field_num < threshold
            if op == "gte": return field_num >= threshold
            if op == "lte": return field_num <= threshold
            if op == "eq": return field_num == threshold
        return False

    def _test_regex(
        self,
        rule_id: str,
        idx: int,
        pattern_str: str,
        normalized: str,
        raw: str,
    ) -> bool:
        # Try pre-compiled first.
        for cidx, compiled in self._compiled.get(rule_id, []):
            if cidx == idx:
                return bool(compiled.search(normalized)) or bool(compiled.search(raw))
        # Fallback: compile on the fly.
        try:
            regex = _compile_regex(pattern_str)
            return bool(regex.search(normalized)) or bool(regex.search(raw))
        except re.error:
            return False

    @staticmethod
    def _resolve_field(field_name: str, event: AgentEvent) -> str | None:
        """Resolve a field value from an AgentEvent, mirroring the TS engine logic."""
        # Explicit fields take priority.
        if field_name in event.fields:
            return event.fields[field_name]

        # Map event_type -> default field name.
        default_field = EVENT_TYPE_TO_FIELD.get(event.event_type)
        if field_name == default_field or field_name == "content":
            return event.content or None

        # Common aliases -- mirrors the TS engine (engine.ts:616-632).
        # For most aliases: if event_type matches, return event.content; else check fields.
        # For tool_name/tool_args: check fields first, fall back to event.content
        # when event_type is tool_call (matching TS ?? operator behavior).
        alias_map: dict[str, str] = {
            "user_input": "llm_input",
            "agent_output": "llm_output",
            "tool_response": "tool_response",
            "agent_message": "multi_agent_message",
        }
        if field_name in alias_map:
            expected_type = alias_map[field_name]
            if event.event_type == expected_type:
                return event.content or None
            return event.fields.get(field_name)

        # tool_name / tool_args: fields take priority, then fall back to
        # event.content when event_type is tool_call (matches TS engine behavior:
        #   event.fields?.['tool_name'] ?? (event.type === 'tool_call' ? event.content : undefined)
        # )
        if field_name in ("tool_name", "tool_args"):
            val = event.fields.get(field_name)
            if val is not None:
                return val
            if event.event_type == "tool_call":
                return event.content or None
            return None

        # Try metadata.
        return event.metadata.get(field_name)
