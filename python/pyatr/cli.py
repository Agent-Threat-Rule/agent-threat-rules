"""CLI for pyATR.

Usage:
    pyatr scan events.json [--rules-dir DIR] [--fail-on {high,critical}]
    pyatr validate <rule.yaml|dir>
    pyatr test <rule.yaml|dir>
    pyatr stats [--rules-dir DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from pyatr.engine import ATREngine
from pyatr.enforcement import BLOCKING_SEVERITIES, blocking_matches, blocking_severities_from
from pyatr.types import AgentEvent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyatr",
        description="pyATR -- Python reference engine for Agent Threat Rules",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    scan_parser = sub.add_parser("scan", help="Scan events against ATR rules")
    scan_parser.add_argument("events_file", help="Path to a JSON file with events")
    scan_parser.add_argument(
        "--rules-dir",
        default=None,
        help="Directory containing ATR YAML rules (default: ../rules/)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=BLOCKING_SEVERITIES,
        default=None,
        help=(
            "Exit 2 when a match from a maturity: stable rule (the enforce lane) "
            "at or above this severity is found, for CI gates. Off by default: "
            "without it the scan reports every match and exits 0."
        ),
    )

    # validate
    validate_parser = sub.add_parser(
        "validate", help="Validate ATR rule YAML files against schema"
    )
    validate_parser.add_argument(
        "path", help="Path to a rule YAML file or directory of rules"
    )

    # test
    test_parser = sub.add_parser(
        "test", help="Run embedded test_cases from ATR rule YAML files"
    )
    test_parser.add_argument(
        "path", help="Path to a rule YAML file or directory of rules"
    )

    # stats
    stats_parser = sub.add_parser("stats", help="Show rule statistics")
    stats_parser.add_argument(
        "--rules-dir",
        default=None,
        help="Directory containing ATR YAML rules (default: ../rules/)",
    )

    return parser


def _default_rules_dir() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "rules"


def _load_events(path: str) -> list[AgentEvent]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = [data]
    events: list[AgentEvent] = []
    for item in data:
        events.append(
            AgentEvent(
                content=str(item.get("content", "")),
                event_type=str(item.get("event_type", item.get("type", "llm_input"))),
                fields=item.get("fields", {}),
                metadata=item.get("metadata", {}),
            )
        )
    return events


def _cmd_scan(args: argparse.Namespace) -> int:
    rules_dir = Path(args.rules_dir) if args.rules_dir else _default_rules_dir()
    if not rules_dir.is_dir():
        print(f"Error: rules directory not found: {rules_dir}", file=sys.stderr)
        return 1

    engine = ATREngine()
    count = engine.load_rules_from_directory(rules_dir)
    print(f"Loaded {count} ATR rules from {rules_dir}")

    events = _load_events(args.events_file)
    print(f"Scanning {len(events)} event(s)...\n")

    # The scan runs in the hunt lane, so every match is reported. Only
    # --fail-on turns a match into a non-zero exit, and only a match that may
    # block (pyatr.enforcement: enforce lane, high/critical). The scan used to
    # exit 2 on any match of any rule at any severity, which made a plain
    # `pyatr scan` in CI a blocking gate on experimental rules.
    fail_severities = blocking_severities_from(args.fail_on) if args.fail_on else ()
    total_matches = 0
    failing = 0
    for i, event in enumerate(events):
        matches = engine.evaluate(event)
        if not matches:
            continue
        total_matches += len(matches)
        gate = {m.rule_id for m in blocking_matches(matches, fail_severities)} if fail_severities else set()
        failing += len(gate)
        _print_event_matches(i, event, matches, gate)

    if total_matches == 0:
        print("No threats detected.")
    else:
        print(f"Total: {total_matches} match(es) across {len(events)} event(s).")
    if args.fail_on:
        print(f"--fail-on {args.fail_on}: {failing} match(es) from maturity: stable rules at or above it.")

    return 2 if failing > 0 else 0


def _print_event_matches(index: int, event: AgentEvent, matches: list[Any], gate: set[str]) -> None:
    snippet = (event.content[:80] + "...") if len(event.content) > 80 else event.content
    print(f"Event {index + 1}: {snippet!r}")
    for m in matches:
        marker = "  [fails --fail-on]" if m.rule_id in gate else ""
        print(f"  [{m.severity.upper()}] {m.rule_id} - {m.title}{marker}")
        print(f"    confidence={m.confidence}, maturity={m.maturity}, patterns_matched={len(m.matched_patterns)}")
    print()


def _cmd_validate(args: argparse.Namespace) -> int:
    from pyatr.validator import validate

    path = Path(args.path)
    if not path.exists():
        print(f"Error: path not found: {path}", file=sys.stderr)
        return 1

    result = validate(path)
    print(f"Checked {result.files_checked} file(s)")

    if result.valid:
        print("All rules valid.")
        return 0

    print(f"Found {len(result.errors)} error(s):\n")
    for err in result.errors:
        print(f"  {err.file}")
        print(f"    [{err.field}] {err.message}")
    print()
    return 1


def _cmd_test(args: argparse.Namespace) -> int:
    from pyatr.test_runner import run_tests

    path = Path(args.path)
    if not path.exists():
        print(f"Error: path not found: {path}", file=sys.stderr)
        return 1

    result = run_tests(path)

    if result.total == 0:
        print("No test cases found.")
        return 0

    for rr in result.rule_results:
        status = "PASS" if rr.all_passed else "FAIL"
        print(f"[{status}] {rr.rule_id} ({rr.passed}/{rr.total} passed) -- {rr.file}")
        for tc in rr.results:
            if not tc.passed:
                marker = "FAIL"
                print(f"  [{marker}] {tc.case_type}: {tc.description}")
                print(f"    {tc.detail}")

    print(f"\nTotal: {result.passed} passed, {result.failed} failed, {result.total} total")

    return 0 if result.all_passed else 1


def _cmd_stats(args: argparse.Namespace) -> int:
    rules_dir = Path(args.rules_dir) if args.rules_dir else _default_rules_dir()
    if not rules_dir.is_dir():
        print(f"Error: rules directory not found: {rules_dir}", file=sys.stderr)
        return 1

    category_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    total = 0

    for root_str, _dirs, files in os.walk(rules_dir):
        for fname in sorted(files):
            if not (fname.endswith(".yaml") or fname.endswith(".yml")):
                continue
            fpath = Path(root_str) / fname
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                if not isinstance(data, dict) or "id" not in data:
                    continue
            except Exception:
                continue

            total += 1
            tags = data.get("tags", {})
            if isinstance(tags, dict):
                cat = tags.get("category", "unknown")
                category_counts[cat] += 1
            severity_counts[str(data.get("severity", "unknown")).lower()] += 1
            status_counts[str(data.get("status", "unknown")).lower()] += 1

    print(f"Total rules: {total}\n")

    print("By category:")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")

    print("\nBy severity:")
    for sev in ("critical", "high", "medium", "low"):
        if sev in severity_counts:
            print(f"  {sev}: {severity_counts[sev]}")

    print("\nBy status:")
    for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        print(f"  {status}: {count}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "validate":
        return _cmd_validate(args)
    elif args.command == "test":
        return _cmd_test(args)
    elif args.command == "stats":
        return _cmd_stats(args)
    else:
        parser.print_help()
        return 1
