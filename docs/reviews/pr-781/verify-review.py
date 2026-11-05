#!/usr/bin/env python3
"""Verify the frozen PR #781 review bundle using local Git objects only.

Dependency: Python 3 and PyYAML (``python -m pip install PyYAML``).
Run from the repository or provide --repo. The default bundle is this file's
parent directory. This command reads files/Git objects and prints JSON; it does
not run the mapping generator, make network/API requests, or modify files.
It verifies provenance, completeness and scope, not semantic correctness of
model-assisted judgments or compliance with NIST requirements.
"""
from __future__ import annotations

import argparse
import collections
import copy
import csv
import difflib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

try:
    import yaml
except ImportError:
    print(json.dumps({"status": "failed", "error": "PyYAML is required. Install it explicitly with: python -m pip install PyYAML"}))
    raise SystemExit(2)

HEAD = "8973e93c89c692806a5011e39b44aff77ce914af"
BASE = "d38e56cba35d268d4d6d19247035ba5a25740412"
COMMENT_ID = 6645073046
EXPECTED_DUPLICATES = {"ATR-2026-00041": 2, "ATR-2026-00101": 2}
PROPOSED_RULES = {
    "rules/data-poisoning/ATR-2026-02408-dataset-loader-code-execution.yaml": (1, "MG.1.3"),
    "rules/privilege-escalation/ATR-2026-02407-agent-workspace-boundary-escape.yaml": (0, "MG.2.4"),
}
EXPECTED_TRANSITIONS = {
    "GV.1.2 -> GV.2.1": 25,
    "MG.2.3 -> MG.1.3": 263,
    "MG.2.3 -> MG.2.4": 242,
}
FLAG_PATTERNS = {
    "value_maintenance_definition_mismatch": r"sustain.{0,50}value.{0,50}deploy",
    "mg24_filter_or_block_language": r"\b(?:block(?:ing)?|saniti[sz]e|filter|strip|reject)\b",
    "mg13_planning_or_priority_language": r"\b(?:plan(?:ned|ning|s)?|document(?:ed|ation)?|priorit(?:y|ies|ized|ised))\b",
}


class ReviewError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ReviewError(message)


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReviewError(f"Cannot read {path.name}: {exc}") from exc


def row_key(row):
    return (row["rule_id"], row["mapping_index"])


def transition_counts(rows):
    return dict(sorted(collections.Counter(
        f'{r["old_mapping"]["subcategory"]} -> {r["new_mapping"]["subcategory"]}'
        for r in rows
    ).items()))


def category_counts(rows):
    return dict(sorted(collections.Counter(r["category"] for r in rows).items()))


def verdict_counts(rows, field):
    # Flat verdict keys are the portable bundle schema. A nested "verdicts"
    # object is also accepted for integrations that preserve that wrapper.
    values = [r.get(field, r.get("verdicts", {}).get(field)) for r in rows]
    require(all(v in {"Y", "N", "?"} for v in values), f"Missing/invalid {field}")
    return {v: values.count(v) for v in ("Y", "N", "?")}


def mappings(rule):
    return (rule.get("compliance") or {}).get("nist_ai_rmf", [])


def without_nist(rule):
    result = copy.deepcopy(rule)
    result.get("compliance", {}).pop("nist_ai_rmf", None)
    return result


class LocalGit:
    def __init__(self, repo):
        self.repo = repo
        self.cache = {}
        self.parsed = {}
        self.env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")

    def command(self, *args):
        result = subprocess.run(
            ["git", "-C", str(self.repo), *args], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode:
            raise ReviewError(f"Local Git command failed ({' '.join(args[:3])}): "
                              + result.stderr.decode("utf-8", errors="replace").strip())
        return result.stdout.decode("utf-8")

    def preload(self, entries):
        entries = list(dict.fromkeys(x for x in entries if x not in self.cache))
        if not entries:
            return
        # One cat-file process reads complete blobs efficiently. Lazy fetching is
        # explicitly disabled: missing objects fail rather than access a network.
        result = subprocess.run(
            ["git", "-C", str(self.repo), "cat-file", "--batch"], env=self.env,
            input="".join(f"{sha}:{path}\n" for sha, path in entries).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        require(result.returncode == 0, "Local git cat-file failed: "
                + result.stderr.decode("utf-8", errors="replace"))
        data = result.stdout
        offset = 0
        for entry in entries:
            end = data.find(b"\n", offset)
            require(end >= 0, f"Truncated git object header: {entry}")
            fields = data[offset:end].split()
            require(len(fields) == 3 and fields[1] == b"blob",
                    f"Missing local blob (network is disabled): {entry}")
            size = int(fields[2])
            offset = end + 1
            require(len(data) >= offset + size + 1, f"Truncated git object: {entry}")
            self.cache[entry] = data[offset:offset + size].decode("utf-8")
            offset += size + 1
        require(offset == len(data), "Unexpected trailing git cat-file data")

    def raw(self, sha, path):
        self.preload([(sha, path)])
        return self.cache[(sha, path)]

    def rule(self, sha, path):
        key = (sha, path)
        if key not in self.parsed:
            self.parsed[key] = yaml.safe_load(self.raw(sha, path))
        return self.parsed[key]


def find_repo(bundle, explicit):
    if explicit:
        return Path(explicit).resolve()
    for directory in (bundle, Path.cwd()):
        result = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode == 0:
            return Path(result.stdout.decode().strip())
    raise ReviewError("Cannot locate the repository; supply --repo /path/to/repository")


def verify_source_row(row, git):
    for field in ("rule_id", "path", "mapping_index", "old_mapping", "new_mapping", "base_yaml", "head_yaml"):
        require(field in row, f"Missing row field {field}: {row.get('rule_id')}")
    path = row["path"]
    index = row["mapping_index"]
    require(isinstance(index, int) and index >= 0, f"Invalid mapping index for {path}")
    for prefix, sha, map_field in (("base", BASE, "old_mapping"), ("head", HEAD, "new_mapping")):
        raw = row[prefix + "_yaml"]
        require(raw == git.raw(sha, path), f"{prefix} raw YAML differs from pinned Git blob: {path}")
        parsed = yaml.safe_load(raw)
        require(parsed == git.rule(sha, path), f"{prefix} parsed source mismatch: {path}")
        require(parsed["id"] == row["rule_id"], f"Rule ID mismatch: {path}")
        source_maps = mappings(parsed)
        require(index < len(source_maps), f"Out-of-range mapping index: {path}:{index}")
        require(source_maps[index] == row[map_field], f"{prefix} full mapping mismatch: {path}:{index}")
        if prefix + "_rule" in row:
            require(row[prefix + "_rule"] == parsed, f"{prefix}_rule differs from raw YAML: {path}")
    for field, sha in (("head_sha", HEAD), ("base_sha", BASE)):
        if field in row:
            require(row[field] == sha, f"Unexpected {field} on row {row['rule_id']}")
    if "reviewed_head_sha" in row:
        require(row["reviewed_head_sha"] == HEAD, f"Reviewed-head metadata mismatch: {path}")
    if "full_rationale" in row:
        require(row["full_rationale"] == row["new_mapping"]["context"], f"Full rationale differs from source: {path}")
    if "source_url" in row:
        require(row["source_url"] == f"https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/{HEAD}/{path}",
                f"Commit-pinned file URL mismatch: {path}")


def build_inventory(git):
    paths = git.command("diff", "--name-only", BASE, HEAD, "--", "rules/").splitlines()
    require(len(paths) == 511, f"Expected 511 changed rule paths; found {len(paths)}")
    require(all(p.startswith("rules/") and p.endswith(".yaml") for p in paths),
            "Original PR contains an unexpected non-YAML change under rules/")
    git.preload([(sha, path) for path in paths for sha in (BASE, HEAD)])
    inventory = []
    for path in paths:
        old = git.rule(BASE, path)
        new = git.rule(HEAD, path)
        require(without_nist(old) == without_nist(new),
                f"Original PR changes rule data outside compliance.nist_ai_rmf: {path}")
        before, after = mappings(old), mappings(new)
        require(len(before) == len(after), f"Original mapping-list length changed: {path}")
        for index, (a, b) in enumerate(zip(before, after)):
            if a != b:
                changed_fields = {k for k in a.keys() | b.keys() if a.get(k) != b.get(k)}
                require(changed_fields <= {"subcategory", "context"},
                        f"Original PR changes strength/function/other mapping data: {path}:{index}")
                require(a.get("strength") == b.get("strength"), f"Original strength changed: {path}:{index}")
                inventory.append({
                    "rule_id": new["id"], "path": path, "mapping_index": index,
                    "old_mapping": a, "new_mapping": b,
                    "category": (new.get("tags") or {}).get("category"), "title": new.get("title"),
                })
    require(len(inventory) == 530, f"Expected 530 changed mapping rows; found {len(inventory)}")
    require(transition_counts(inventory) == EXPECTED_TRANSITIONS, "Original transition counts changed")
    return inventory


def verify_manifest(actual, expected, name):
    require(isinstance(actual, list), f"{name} must be a list")
    actual_keys = [row_key(x) for x in actual]
    require(len(actual_keys) == len(set(actual_keys)), f"Duplicate mapping identities in {name}")
    expected_by_key = {row_key(x): x for x in expected}
    require(set(actual_keys) == set(expected_by_key), f"{name} row identities do not match pinned Git inventory")
    for row in actual:
        reference = expected_by_key[row_key(row)]
        for field, value in reference.items():
            require(row.get(field) == value, f"{name} {field} mismatch: {row_key(row)}")


def original_sample(discussion):
    comments = discussion["comments"] if isinstance(discussion, dict) else discussion
    matches = [c for c in comments if c.get("id") == COMMENT_ID or
               c.get("url", "").endswith(f"issuecomment-{COMMENT_ID}")]
    require(len(matches) == 1, "Expected exactly one frozen sample-request comment")
    result = []
    for line in matches[0]["body"].splitlines():
        if re.match(r"\|\s*\d+\s*\|", line):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            require(len(cells) >= 3, "Malformed frozen sample table row")
            move = re.fullmatch(r"([A-Z]{2}\.\d+\.\d+)\s*->\s*([A-Z]{2}\.\d+\.\d+)", cells[2])
            require(move is not None, f"Malformed sample mapping transition: {cells[2]}")
            result.append((int(cells[0]), cells[1], move.group(1), move.group(2)))
    require(len(result) == 53, f"Expected 53 published sample rows; found {len(result)}")
    return result


def screen_flags(row):
    text = row["new_mapping"]["context"]
    id_ = row["new_mapping"]["subcategory"]
    flags = []
    if id_ != "MG.2.2" and re.search(FLAG_PATTERNS["value_maintenance_definition_mismatch"], text, re.I):
        flags.append("value_maintenance_definition_mismatch")
    if id_ == "GV.2.1":
        flags.append("gv21_organizational_evidence_check")
    if id_ == "MG.2.4" and re.search(FLAG_PATTERNS["mg24_filter_or_block_language"], text, re.I):
        flags.append("mg24_filter_or_block_language")
    if id_ == "MG.2.4" and len(text) < 130:
        flags.append("mg24_short_runtime_label")
    if id_ == "MG.1.3" and not re.search(FLAG_PATTERNS["mg13_planning_or_priority_language"], text, re.I):
        flags.append("mg13_runtime_without_plan_or_priority_language")
    return flags


def verify_batch(batch, inventory, sample, expanded, git):
    require(batch["head_sha"] == HEAD and batch["base_sha"] == BASE, "Batch commit metadata mismatch")
    sample_keys = {row_key(x) for x in sample}
    for key, rows in (("population", inventory), ("sample", sample)):
        section = batch[key]
        require(section["mapping_rows"] == len(rows), f"Batch {key} mapping-row count mismatch")
        require(section["unique_rules"] == len({x["rule_id"] for x in rows}), f"Batch {key} unique-rule count mismatch")
        require(section["transitions"] == transition_counts(rows), f"Batch {key} transition counts mismatch")
        require(section["categories"] == category_counts(rows), f"Batch {key} category counts mismatch")
    expected_missing = sorted(set(category_counts(inventory)) - set(category_counts(sample)))
    require(batch["sample"]["missing_population_categories"] == expected_missing, "Missing-category report mismatch")
    expected = {row_key(x): (x, screen_flags(x)) for x in inventory if screen_flags(x)}
    screened = batch["screened_rows"]
    require(len(screened) == len(expected), "Screened-row count mismatch")
    require(len({row_key(x) for x in screened}) == len(screened), "Duplicate screened row")
    for row in screened:
        k = row_key(row)
        require(k in expected, f"Unexpected screen flag identity: {k}")
        reference, flags = expected[k]
        for field in ("path", "old_mapping", "new_mapping", "category", "title"):
            require(row[field] == reference[field], f"Screened {field} differs from source: {k}")
        require(row["screening_flags"] == flags, f"Screening flags do not reproduce: {k}")
        require(row["sampled"] == (k in sample_keys), f"Screened sample-membership mismatch: {k}")
        require(row["response_actions"] == git.rule(HEAD, row["path"]).get("response", {}).get("actions", []),
                f"Screened response actions mismatch: {k}")
    counts = dict(sorted(collections.Counter(f for _, flags in expected.values() for f in flags).items()))
    require(batch["screening_counts"] == counts, "Screening flag counts mismatch")
    require(batch["screened_unique_rows"] == len(expected), "Screened unique-row count mismatch")
    require(batch["screened_unsampled_rows"] == sum(k not in sample_keys for k in expected), "Screened unsampled count mismatch")
    require(batch["screened_unique_rules"] == len({k[0] for k in expected}), "Screened unique-rule count mismatch")

    # Rebuild the retained-MG.2.3 manifest from complete frozen head rule YAML.
    paths = [p for p in git.command("ls-tree", "-r", "--name-only", HEAD, "--", "rules/").splitlines()
             if p.endswith(".yaml")]
    git.preload([(HEAD, p) for p in paths])
    retained = {}
    for path in paths:
        rule = git.rule(HEAD, path)
        for index, mapping in enumerate(mappings(rule)):
            if mapping.get("subcategory") == "MG.2.3":
                retained[(rule["id"], index)] = (path, mapping, (rule.get("tags") or {}).get("category"))
    reported = batch["retained_mg23"]
    require(len(retained) == reported["mapping_rows"] == 51, "Retained MG.2.3 count mismatch")
    require(reported["unique_rules"] == len({k[0] for k in retained}), "Retained MG.2.3 unique-rule count mismatch")
    require(len(reported["rows"]) == len(retained) and len({row_key(x) for x in reported["rows"]}) == len(retained),
            "Retained MG.2.3 manifest identity count mismatch")
    for row in reported["rows"]:
        k = row_key(row)
        require(k in retained, f"Unexpected retained MG.2.3 identity: {k}")
        path, mapping, category = retained[k]
        require((row["path"], row["mapping"], row["category"]) == (path, mapping, category),
                f"Retained MG.2.3 source mismatch: {k}")
        text = mapping.get("context", "")
        flags = set()
        if not re.search(r"previously\s+unknown|unknown\s+risk|un(?:known|anticipated)|newly\s+(?:identified|emerg)", text, re.I):
            flags.add("no_explicit_previously_unknown_risk_language")
        if re.search(r"novel|new\b|newly|emerg", text, re.I):
            flags.add("novelty_language_requires_deployment_timeline")
        if "(respond to previously unknown identified risks)" in text and "so the risk can be treated" in text:
            flags.add("generic_unknown_risk_template_no_deployment_timeline")
        require(set(row["screening_flags"]) == flags and len(row["screening_flags"]) == len(flags),
                f"Retained MG.2.3 context flags do not reproduce: {k}")
    require(reported["categories"] == dict(sorted(collections.Counter(x[2] for x in retained.values()).items())),
            "Retained MG.2.3 category totals mismatch")
    require(reported["flag_counts"] == dict(sorted(collections.Counter(
        f for x in reported["rows"] for f in x["screening_flags"]).items())), "Retained MG.2.3 flag totals mismatch")

    if "expanded_individual_review" in batch:
        section = batch["expanded_individual_review"]
        require(section["mapping_rows"] == len(expanded), "Expanded count mismatch")
        require(section["unique_rules"] == len({x["rule_id"] for x in expanded}), "Expanded unique-rule count mismatch")
        require(set(section["rules"]) == {x["rule_id"] for x in expanded}, "Expanded rule-list mismatch")
    total = len(sample) + len(expanded)
    scope = batch["scope_accounting"]
    checks = {"original_sample_individual_rows": len(sample), "additional_individual_rows": len(expanded),
              "total_individual_rows": total, "remaining_changed_rows_without_individual_semantic_review": len(inventory) - total,
              "all_changed_rows_programmatically_screened": len(inventory), "retained_mg23_context_only_screened": len(retained)}
    for field, expected_value in checks.items():
        require(scope[field] == expected_value, f"Batch scope count mismatch: {field}")
    return {"screened_rows": len(inventory), "flagged_rows": len(screened), "flag_counts": counts,
            "retained_mg23_contexts": len(retained), "individual_rows": total,
            "changed_rows_without_individual_semantic_review": len(inventory) - total,
            "head_rule_files": len(paths),
            "head_nist_mapping_rows": sum(len(mappings(git.rule(HEAD, path))) for path in paths),
            "other_head_nist_rows_outside_changed_and_retained_screen":
                sum(len(mappings(git.rule(HEAD, path))) for path in paths) - len(inventory) - len(retained)}


def verify_working_tree(git):
    current_head = git.command("rev-parse", "HEAD").strip()
    # A committed follow-up remains verifiable. Original inventory and current
    # rule-data comparisons still use the frozen PR head, never the new HEAD.
    git.command("merge-base", "--is-ancestor", HEAD, current_head)
    paths = git.command("diff", "--name-only", HEAD, "--", "rules/").splitlines()
    untracked = git.command("ls-files", "--others", "--exclude-standard", "--", "rules/").splitlines()
    require(not untracked, "Unexpected untracked rule files")
    require(set(paths) == set(PROPOSED_RULES), "Proposed rule-change paths differ from the approved local scope")
    results = []
    for path in sorted(paths):
        index, expected_id = PROPOSED_RULES[path]
        before = git.rule(HEAD, path)
        current_raw = (git.repo / path).read_text(encoding="utf-8")
        after = yaml.safe_load(current_raw)
        require(without_nist(before) == without_nist(after), f"Proposed edit changes detection/other rule fields: {path}")
        old_maps, new_maps = mappings(before), mappings(after)
        require(len(old_maps) == len(new_maps), f"Proposed edit changes mapping-list length: {path}")
        changed_indices = [i for i, (a, b) in enumerate(zip(old_maps, new_maps)) if a != b]
        require(changed_indices == [index], f"Proposed edit changes unexpected mapping indices: {path}")
        old, new = old_maps[index], new_maps[index]
        fields = {k for k in old.keys() | new.keys() if old.get(k) != new.get(k)}
        require(fields == {"context", "strength"}, f"Proposed edit changes unexpected mapping fields: {path}")
        require(old["subcategory"] == new["subcategory"] == expected_id, f"Proposed mapping ID changed: {path}")
        require(old.get("strength") == "primary" and new.get("strength") == "partial", f"Unexpected strength adjustment: {path}")
        require(isinstance(new.get("context"), str) and bool(new["context"].strip()), f"Empty proposed rationale: {path}")
        # These two proposed edits use single-line quoted contexts. Comparing
        # the raw diff also catches comments/formatting changed outside them.
        removed, added = [], []
        for line in difflib.ndiff(git.raw(HEAD, path).splitlines(), current_raw.splitlines()):
            if line.startswith("- "):
                removed.append(line[2:].strip())
            elif line.startswith("+ "):
                added.append(line[2:].strip())
        require(len(removed) == len(added) == 2 and
                sum(x.startswith("context: ") for x in removed) == 1 and
                sum(x.startswith("context: ") for x in added) == 1 and
                "strength: primary" in removed and "strength: partial" in added,
                f"Raw proposed diff contains changes outside its context/strength scalars: {path}")
        results.append({"rule_id": after["id"], "path": path, "mapping_index": index,
                        "subcategory": expected_id, "changed_fields": sorted(fields), "strength": "primary -> partial"})
    return results


def verify_csv(path, rows):
    with path.open(encoding="utf-8", newline="") as stream:
        csv_rows = list(csv.DictReader(stream))
    require(len(csv_rows) == len(rows), "CSV row count mismatch")
    for expected, actual in zip(rows, csv_rows):
        for field in ("row", "rule_id", "path", "mapping_index", "q1_verdict", "q2_verdict"):
            require(field in actual, f"CSV lacks required column: {field}")
            require(actual[field] == str(expected[field]), f"CSV roundtrip mismatch: row {expected['row']} {field}")
        for field in ("rationale", "full_rationale", "new_rationale"):
            if field in actual:
                require(actual[field] == expected["new_mapping"]["context"], f"CSV truncated rationale: row {expected['row']}")
        for field in ("old_mapping", "new_mapping", "official_nist", "confidence", "human_questions"):
            if field in actual:
                decoded = json.loads(actual[field]) if isinstance(expected[field], (dict, list)) else actual[field]
                require(decoded == expected[field], f"CSV JSON-object/scalar mismatch: row {expected['row']} {field}")
        for field in ("source_url", "reviewed_head_sha", "base_sha", "q1_reason", "q2_reason", "rule_evidence"):
            if field in actual and isinstance(expected.get(field), str):
                require(actual[field] == expected[field], f"CSV text mismatch: row {expected['row']} {field}")
    return {"path": path.name, "rows": len(csv_rows), "identity_and_verdict_roundtrip": "passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--repo", help="Repository root (default: discover using local git rev-parse)")
    parser.add_argument("--csv", type=Path, help="Optional CSV to check; default: bundle/review.csv if present")
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    git = LocalGit(find_repo(bundle, args.repo))
    for sha in (HEAD, BASE):
        require(git.command("cat-file", "-t", sha).strip() == "commit", f"Missing local commit: {sha}")
    review = read_json(bundle / "review.json")
    require(isinstance(review, dict) and isinstance(review.get("rows"), list), "review.json must contain an object.rows list")
    for field, sha in (("head_sha", HEAD), ("base_sha", BASE)):
        if field in review:
            require(review[field] == sha, f"review.json {field} mismatch")
    sample = review["rows"]
    expected_sample = original_sample(read_json(bundle / "source" / "discussion.json"))
    actual_sample = [(r["row"], r["rule_id"], r["old_mapping"]["subcategory"], r["new_mapping"]["subcategory"]) for r in sample]
    require(actual_sample == expected_sample, "53 ordered row identities/transitions differ from the published comment")
    require([r["row"] for r in sample] == list(range(1, 54)), "Sample ordering/numbering mismatch")
    duplicates = {id_: count for id_, count in collections.Counter(r["rule_id"] for r in sample).items() if count > 1}
    require(len({r["rule_id"] for r in sample}) == 51 and duplicates == EXPECTED_DUPLICATES,
            "Sample unique-rule or duplicate-row accounting mismatch")
    rebuilt = build_inventory(git)
    inventory = read_json(bundle / "inventory.json")
    verify_manifest(inventory, rebuilt, "inventory.json")
    inventory_keys = {row_key(x) for x in inventory}
    expanded = read_json(bundle / "expanded-review.json")
    require(isinstance(expanded, list), "expanded-review.json must be a list")
    sample_keys = {row_key(x) for x in sample}
    require(len(sample_keys) == 53, "Duplicate mapping identity within original sample")
    require(len({row_key(x) for x in expanded}) == len(expanded), "Duplicate expanded mapping identity")
    require(not sample_keys.intersection(row_key(x) for x in expanded), "Expanded review overlaps original sample")
    for row in sample + expanded:
        require(row_key(row) in inventory_keys, f"Reviewed row outside original changed inventory: {row_key(row)}")
        verify_source_row(row, git)
    sample_verdicts = {"q1": verdict_counts(sample, "q1_verdict"), "q2": verdict_counts(sample, "q2_verdict")}
    expanded_verdicts = {"q1": verdict_counts(expanded, "q1_verdict"), "q2": verdict_counts(expanded, "q2_verdict")}
    if "statistics" in review:
        require(review["statistics"] == sample_verdicts, "review.json verdict statistics do not match its rows")
    for field, value in (("population_rows", len(inventory)), ("sample_rows", len(sample)), ("sample_unique_rules", 51)):
        if field in review:
            require(review[field] == value, f"review.json {field} mismatch")
    core = read_json(bundle / "nist-core.json")
    require(core.get("publication_date") == "2023-01", "NIST source version mismatch")
    required_ids = {"GV.1.2", "GV.2.1", "MG.1.3", "MG.2.2", "MG.2.3", "MG.2.4"}
    require(required_ids <= set(core.get("subcategories", {})), "Missing relevant official NIST statements")
    for id_ in required_ids:
        entry = core["subcategories"][id_]
        require(bool(entry.get("text")) and entry.get("source_url", "").startswith("https://nvlpubs.nist.gov/"),
                f"NIST evidence lacks text or official PDF source: {id_}")
    for row in sample + expanded:
        if "official_nist" in row:
            for id_, definition in row["official_nist"].items():
                require(definition == core["subcategories"].get(id_), f"Row NIST definition differs from source evidence: {row['rule_id']} {id_}")
    batch_result = verify_batch(read_json(bundle / "batch-analysis.json"), inventory, sample, expanded, git)
    proposed = verify_working_tree(git)
    csv_path = args.csv or (bundle / "review.csv" if (bundle / "review.csv").exists() else None)
    csv_result = verify_csv(csv_path, sample) if csv_path is not None else "not requested"
    return {
        "status": "passed", "network": "disabled; local Git objects only", "files_written": 0,
        "head_sha": HEAD, "base_sha": BASE,
        "original_pr": {"rule_files": 511, "mapping_rows": len(inventory), "transitions": transition_counts(inventory),
                        "outside_nist_rule_data": "unchanged", "mapping_strength": "unchanged"},
        "sample": {"rows": 53, "unique_rules": 51, "duplicate_rule_ids": duplicates, "verdict_counts": sample_verdicts},
        "expanded": {"rows": len(expanded), "verdict_counts": expanded_verdicts},
        "batch": batch_result, "proposed_rule_changes": proposed, "csv": csv_result,
        "limits": "Integrity/scope verifier only; does not certify semantic verdicts, original random draw, deployed enforcement, NIST conformity, or legal compliance.",
    }


if __name__ == "__main__":
    try:
        print(json.dumps(main(), indent=2, ensure_ascii=False))
    except (ReviewError, KeyError, TypeError, ValueError, OSError, yaml.YAMLError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2))
        raise SystemExit(1)
