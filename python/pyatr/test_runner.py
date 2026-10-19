"""Embedded test runner for ATR rule test_cases.

Loads a rule YAML, extracts test_cases (true_positives / true_negatives),
creates AgentEvent instances from each test case, evaluates against the
rule's detection conditions, and reports pass/fail counts.
"""

from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pyatr.engine import ATREngine, _parse_rule
from pyatr.types import AgentEvent


@dataclass(frozen=True)
class TestCaseResult:
    """Result of running a single test case."""

    rule_id: str
    description: str
    case_type: str  # "true_positive" or "true_negative"
    passed: bool
    detail: str


@dataclass(frozen=True)
class RuleTestResult:
    """Aggregated results from testing one rule file."""

    rule_id: str
    file: str
    results: tuple[TestCaseResult, ...]

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0


@dataclass(frozen=True)
class TestRunResult:
    """Aggregated results from testing multiple rule files."""

    rule_results: tuple[RuleTestResult, ...]

    @property
    def passed(self) -> int:
        return sum(r.passed for r in self.rule_results)

    @property
    def failed(self) -> int:
        return sum(r.failed for r in self.rule_results)

    @property
    def total(self) -> int:
        return sum(r.total for r in self.rule_results)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0


def _load_yaml(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


# agent_source.type -> the event type a test case of that rule is built as.
_SOURCE_TO_EVENT: dict[str, str] = {
    "llm_io": "llm_input",
    "tool_call": "tool_call",
    "mcp_exchange": "tool_response",
    "agent_behavior": "agent_behavior",
    "multi_agent_comm": "multi_agent_message",
}

# Extended agent_source types, built as an event of the base type the TS
# engine runs them on (RUNTIME_SOURCE_TYPE in src/engine.ts).
_RUNTIME_SOURCE_TYPE: dict[str, str] = {
    "context_window": "llm_io",
    "skill_lifecycle": "tool_call",
    "skill_permission": "tool_call",
    "skill_chain": "tool_call",
}


def _as_text(value: Any) -> str:
    """A test-case value as text: strings as-is, anything else as compact JSON."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _js_truthy(value: Any) -> bool:
    """JavaScript truthiness, which the TS builder's `&&` tests use: unlike
    Python's, an empty dict or list is truthy."""
    if isinstance(value, (dict, list)):
        return True
    return bool(value)


def _build_event_from_test_case(case: dict[str, Any], rule: dict[str, Any]) -> AgentEvent:
    """Build the AgentEvent a test_case describes, for the rule that declares it.

    Mirrors buildEventFromTestCase in src/testcase-event.ts, the builder the
    TypeScript `atr test` and the rule-testcase validator share, so that a
    rule's cases mean the same thing in both engines. The event type comes from
    the rule's agent_source.type, not from which keys the case happens to use:
    the plain `input:` of an mcp_exchange rule is a tool response and of a
    tool_call rule a tool invocation. Building every `input:` case as llm_input
    left `field: tool_response` and `field: tool_args` conditions unresolvable,
    so those rules failed their own true positives here while the TypeScript
    engine passed them.
    """
    raw_input = case.get("input")
    if raw_input is None:
        # `user_input:` is accepted as a top-level alias for `input:`.
        raw_input = case.get("user_input")
    tool_name = _as_text(case.get("tool_name"))
    tool_args = _as_text(case.get("tool_args"))
    tool_response = _as_text(case.get("tool_response"))
    agent_output = _as_text(case.get("agent_output"))
    agent_message = _as_text(case.get("agent_message"))
    tool_description = _as_text(case.get("tool_description"))
    raw_content = _as_text(case.get("content"))

    # tool_call: {name, args}
    tool_call = case.get("tool_call")
    if isinstance(tool_call, dict):
        if _js_truthy(tool_call.get("name")) and not tool_name:
            tool_name = _as_text(tool_call["name"])
        if _js_truthy(tool_call.get("args")) and not tool_args:
            tool_args = _as_text(tool_call["args"])

    # input: {tool_name, tool_args, response | tool_response}
    if isinstance(raw_input, dict):
        if _js_truthy(raw_input.get("tool_name")) and not tool_name:
            tool_name = _as_text(raw_input["tool_name"])
        if _js_truthy(raw_input.get("tool_args")) and not tool_args:
            tool_args = _as_text(raw_input["tool_args"])
        if _js_truthy(raw_input.get("response")) and not tool_response:
            tool_response = _as_text(raw_input["response"])
        if _js_truthy(raw_input.get("tool_response")) and not tool_response:
            tool_response = _as_text(raw_input["tool_response"])
        if tool_args:
            text = tool_args
        elif not tool_response:
            text = _as_text(raw_input)
        else:
            text = ""
    else:
        text = _as_text(raw_input)

    agent_source = rule.get("agent_source")
    declared = agent_source.get("type") if isinstance(agent_source, dict) else None
    source_type = str(declared or "llm_io")
    source_type = _RUNTIME_SOURCE_TYPE.get(source_type, source_type)
    event_type = _SOURCE_TO_EVENT.get(source_type, "llm_input")

    if tool_response and event_type == "tool_response":
        content = tool_response
    else:
        content = (
            text or tool_description or raw_content or tool_response
            or agent_output or agent_message or ""
        )

    fields: dict[str, str] = {}
    if text:
        fields["user_input"] = text
    if tool_response:
        fields["tool_response"] = tool_response
    if agent_output:
        fields["agent_output"] = agent_output
    if tool_description:
        fields["tool_description"] = tool_description
    # Always set, even empty, as the TS builder does, so the content is not read
    # as a tool name. pyatr's engine honours an empty field; the TS engine
    # treats it as absent and, on a tool_call event, whose default field there
    # is tool_name, reads the content instead.
    fields["tool_name"] = tool_name
    # Production integrations always pass tool_args; only the input text stands
    # in for it, never a tool response.
    if tool_args or text:
        fields["tool_args"] = tool_args or text
    fields["content"] = content
    fields["agent_message"] = content

    return AgentEvent(
        content=content,
        event_type=event_type,
        fields=fields,
    )


def _unloadable(rule_id: str, rule_path: Path, test_cases: dict[str, Any], exc: Exception) -> RuleTestResult:
    """Every case of a rule that could not be loaded, failed with the reason."""
    results = tuple(
        TestCaseResult(
            rule_id=rule_id,
            description=str(case.get("description", "")),
            case_type=case_type,
            passed=False,
            detail=f"Rule could not be loaded: {type(exc).__name__}: {exc}",
        )
        for key, case_type in (("true_positives", "true_positive"), ("true_negatives", "true_negative"))
        if isinstance(test_cases.get(key), list)
        for case in test_cases[key]
        if isinstance(case, dict)
    )
    return RuleTestResult(rule_id=rule_id, file=str(rule_path), results=results)


def run_rule_tests(rule_path: Path) -> RuleTestResult | None:
    """Run embedded test_cases for a single rule YAML file.

    Returns None if the file has no test_cases or cannot be parsed.
    """
    data = _load_yaml(rule_path)
    if data is None:
        return None

    rule_id = str(data.get("id", "unknown"))
    test_cases = data.get("test_cases")
    if not isinstance(test_cases, dict):
        return None

    # An engine holding only this rule, its status overridden so that draft and
    # deprecated rules are tested too (evaluate() skips them otherwise), as the
    # TypeScript `atr test` does.
    engine = ATREngine()
    target_id = rule_id
    try:
        engine.load_rule(dataclasses.replace(_parse_rule(data), status="experimental"))
    except Exception as exc:  # a malformed rule file must not abort the whole run
        return _unloadable(rule_id, rule_path, test_cases, exc)

    results: list[TestCaseResult] = []

    # True positives: should trigger the rule
    true_positives = test_cases.get("true_positives", [])
    if isinstance(true_positives, list):
        for case in true_positives:
            if not isinstance(case, dict):
                continue
            event = _build_event_from_test_case(case, data)
            matches = engine.evaluate(event)
            matched_ids = [m.rule_id for m in matches]
            triggered = target_id in matched_ids
            desc = str(case.get("description", ""))
            results.append(TestCaseResult(
                rule_id=target_id,
                description=desc,
                case_type="true_positive",
                passed=triggered,
                detail=f"Expected trigger, got {'triggered' if triggered else 'not triggered'}",
            ))

    # True negatives: should NOT trigger the rule
    true_negatives = test_cases.get("true_negatives", [])
    if isinstance(true_negatives, list):
        for case in true_negatives:
            if not isinstance(case, dict):
                continue
            event = _build_event_from_test_case(case, data)
            matches = engine.evaluate(event)
            matched_ids = [m.rule_id for m in matches]
            triggered = target_id in matched_ids
            desc = str(case.get("description", ""))
            results.append(TestCaseResult(
                rule_id=target_id,
                description=desc,
                case_type="true_negative",
                passed=not triggered,
                detail=f"Expected no trigger, got {'triggered' if triggered else 'not triggered'}",
            ))

    if not results:
        return None

    return RuleTestResult(
        rule_id=target_id,
        file=str(rule_path),
        results=tuple(results),
    )


def run_tests(path: Path) -> TestRunResult:
    """Run embedded test_cases for a file or directory of rule YAMLs."""
    rule_results: list[RuleTestResult] = []

    if path.is_file():
        result = run_rule_tests(path)
        if result is not None:
            rule_results.append(result)
    elif path.is_dir():
        for root_str, _dirs, files in os.walk(path):
            for fname in sorted(files):
                if not (fname.endswith(".yaml") or fname.endswith(".yml")):
                    continue
                fpath = Path(root_str) / fname
                result = run_rule_tests(fpath)
                if result is not None:
                    rule_results.append(result)

    return TestRunResult(rule_results=tuple(rule_results))
