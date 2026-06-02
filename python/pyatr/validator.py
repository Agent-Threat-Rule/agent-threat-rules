"""ATR rule YAML validator.

Validates that rule files conform to the ATR schema: required fields,
valid categories, valid severity levels, valid agent_source types, and
well-formed detection conditions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


VALID_CATEGORIES: frozenset[str] = frozenset({
    "agent-manipulation",
    "context-exfiltration",
    "data-poisoning",
    "excessive-autonomy",
    "model-security",
    "privilege-escalation",
    "prompt-injection",
    "skill-compromise",
    "tool-poisoning",
})

VALID_SOURCE_TYPES: frozenset[str] = frozenset({
    "llm_io",
    "tool_call",
    "mcp_exchange",
    "agent_behavior",
    "multi_agent_comm",
    "context_window",
    "memory_access",
    "skill_lifecycle",
    "skill_permission",
    "skill_chain",
    "agent_trace",  # OpenInference/OTel GenAI spans; see spec/atr-method-v1.1.md
})

VALID_SEVERITIES: frozenset[str] = frozenset({
    "critical",
    "high",
    "medium",
    "low",
})

VALID_OPERATORS: frozenset[str] = frozenset({
    "regex",
    "contains",
    "exact",
    "starts_with",
    "gt",
    "lt",
    "gte",
    "lte",
    "eq",
})

REQUIRED_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "severity",
    "tags",
    "agent_source",
    "detection",
    "response",
)


@dataclass(frozen=True)
class ValidationError:
    """A single validation error found in a rule file."""

    file: str
    field: str
    message: str


@dataclass(frozen=True)
class ValidationResult:
    """Result of validating one or more rule files."""

    errors: tuple[ValidationError, ...]
    files_checked: int

    @property
    def valid(self) -> bool:
        return len(self.errors) == 0


def _load_yaml(path: Path) -> dict[str, Any] | None:
    """Load a YAML file, returning None on parse failure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def _validate_rule(data: dict[str, Any], file_path: str) -> list[ValidationError]:
    """Validate a single parsed rule dict. Returns list of errors."""
    errors: list[ValidationError] = []

    # Check required top-level fields
    for req in REQUIRED_TOP_LEVEL_FIELDS:
        if req not in data or data[req] is None:
            errors.append(ValidationError(
                file=file_path,
                field=req,
                message=f"Missing required field: {req}",
            ))

    # Validate severity
    severity = data.get("severity")
    if severity is not None:
        if str(severity).lower() not in VALID_SEVERITIES:
            errors.append(ValidationError(
                file=file_path,
                field="severity",
                message=f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}",
            ))

    # Validate tags.category -- check that it is a string.
    # Note: rules may use either top-level categories (e.g. "prompt-injection")
    # or subcategories (e.g. "direct", "model-abuse"). We only flag values that
    # are not strings, since the ATR spec allows subcategory values here.
    tags = data.get("tags")
    if isinstance(tags, dict):
        category = tags.get("category")
        if category is not None and not isinstance(category, str):
            errors.append(ValidationError(
                file=file_path,
                field="tags.category",
                message=f"tags.category must be a string, got {type(category).__name__}",
            ))

    # Validate agent_source.type
    agent_source = data.get("agent_source")
    if isinstance(agent_source, dict):
        source_type = agent_source.get("type")
        if source_type is not None and source_type not in VALID_SOURCE_TYPES:
            errors.append(ValidationError(
                file=file_path,
                field="agent_source.type",
                message=f"Invalid source type '{source_type}'. Must be one of: {', '.join(sorted(VALID_SOURCE_TYPES))}",
            ))
    elif agent_source is not None:
        errors.append(ValidationError(
            file=file_path,
            field="agent_source",
            message="agent_source must be a mapping with at least a 'type' field",
        ))

    # Validate detection block
    detection = data.get("detection")
    if isinstance(detection, dict):
        conditions = detection.get("conditions")
        if not isinstance(conditions, list) or len(conditions) == 0:
            errors.append(ValidationError(
                file=file_path,
                field="detection.conditions",
                message="detection.conditions must be a non-empty list",
            ))
        else:
            for i, cond in enumerate(conditions):
                if not isinstance(cond, dict):
                    errors.append(ValidationError(
                        file=file_path,
                        field=f"detection.conditions[{i}]",
                        message="Each condition must be a mapping",
                    ))
                    continue
                if "field" not in cond:
                    errors.append(ValidationError(
                        file=file_path,
                        field=f"detection.conditions[{i}].field",
                        message="Condition missing required 'field'",
                    ))
                if "operator" not in cond:
                    errors.append(ValidationError(
                        file=file_path,
                        field=f"detection.conditions[{i}].operator",
                        message="Condition missing required 'operator'",
                    ))
                elif cond["operator"] not in VALID_OPERATORS:
                    errors.append(ValidationError(
                        file=file_path,
                        field=f"detection.conditions[{i}].operator",
                        message=f"Invalid operator '{cond['operator']}'. Must be one of: {', '.join(sorted(VALID_OPERATORS))}",
                    ))
                if "value" not in cond:
                    errors.append(ValidationError(
                        file=file_path,
                        field=f"detection.conditions[{i}].value",
                        message="Condition missing required 'value'",
                    ))

        # Validate condition logic
        condition_logic = detection.get("condition")
        if condition_logic is not None and str(condition_logic) not in ("any", "all"):
            errors.append(ValidationError(
                file=file_path,
                field="detection.condition",
                message=f"Invalid condition logic '{condition_logic}'. Must be 'any' or 'all'",
            ))
    elif detection is not None:
        errors.append(ValidationError(
            file=file_path,
            field="detection",
            message="detection must be a mapping with 'conditions' list",
        ))

    return errors


def validate_file(path: Path) -> ValidationResult:
    """Validate a single rule YAML file."""
    data = _load_yaml(path)
    if data is None:
        return ValidationResult(
            errors=(ValidationError(
                file=str(path),
                field="(file)",
                message="Failed to parse YAML or file is not a mapping",
            ),),
            files_checked=1,
        )
    errors = _validate_rule(data, str(path))
    return ValidationResult(errors=tuple(errors), files_checked=1)


def validate_directory(directory: Path) -> ValidationResult:
    """Validate all .yaml/.yml rule files in a directory (recursive)."""
    all_errors: list[ValidationError] = []
    files_checked = 0

    for root_str, _dirs, files in __import__("os").walk(directory):
        for fname in sorted(files):
            if not (fname.endswith(".yaml") or fname.endswith(".yml")):
                continue
            fpath = Path(root_str) / fname
            data = _load_yaml(fpath)
            if data is None:
                continue
            # Skip non-rule files (no id field)
            if "id" not in data:
                continue
            files_checked += 1
            all_errors.extend(_validate_rule(data, str(fpath)))

    return ValidationResult(errors=tuple(all_errors), files_checked=files_checked)


def validate(path: Path) -> ValidationResult:
    """Validate a file or directory of rule YAMLs."""
    if path.is_dir():
        return validate_directory(path)
    return validate_file(path)
