"""Type definitions for pyATR."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Condition:
    """A single detection condition from an ATR rule."""

    field: str
    operator: str
    value: str
    description: str = ""


@dataclass(frozen=True)
class ATRRule:
    """Parsed ATR rule loaded from YAML."""

    id: str
    title: str
    severity: str
    description: str
    status: str
    conditions: tuple[Condition, ...]
    condition_logic: str  # "any" or "all"
    tags: dict[str, str] = field(default_factory=dict)
    references: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    # The rule's agent_source block (type, framework, provider). Its type
    # decides whether user_input / agent_output conditions read the content
    # of a tool_response event (see engine._TOOL_RESPONSE_SOURCE_TYPES).
    agent_source: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentEvent:
    """An event to evaluate against ATR rules.

    Fields map to rule condition field names (user_input, agent_output,
    tool_args, tool_name, etc.). The ``content`` value is used as a
    fallback when a specific field is not present.
    """

    content: str = ""
    event_type: str = "llm_input"
    fields: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)


# Mapping from event_type to the default field name that ``content`` resolves to.
EVENT_TYPE_TO_FIELD: dict[str, str] = {
    "llm_input": "user_input",
    "llm_output": "agent_output",
    "tool_call": "tool_args",
    "tool_response": "tool_response",
    "multi_agent_message": "agent_message",
}

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


@dataclass(frozen=True)
class ATRMatch:
    """Result of a rule matching an event."""

    rule_id: str
    title: str
    severity: str
    confidence: str
    matched_patterns: tuple[str, ...]
    description: str = ""
    tags: dict[str, str] = field(default_factory=dict)
