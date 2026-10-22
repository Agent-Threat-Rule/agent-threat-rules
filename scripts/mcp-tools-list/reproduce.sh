#!/usr/bin/env bash
# Reproduce the benign MCP tools/list false-positive measurement end to end.
#
#   bash scripts/mcp-tools-list/reproduce.sh           # re-extract + compare, re-measure (nothing written)
#   bash scripts/mcp-tools-list/reproduce.sh --write   # same, then write a new report under data/measurements/mcp-tools-list-benign/
#
# Optional: CLI_RESULTS=<dir> adds a cross-check against `atr scan` output from a build that has PR #737
# (<dir>/<lane>/<server>.json, one `atr scan <document> --no-report --json --lane <lane>` per document;
# documents are data/test-corpora/mcp-tools-list-benign/tools/*.json and, for the one source whose licence
# does not allow redistribution, .cache/mcp-tools-list/documents/sentry-mcp.json).
#
# What each step writes:
#   1. fetch-tools-list-corpus.py --check writes nothing in the repository (it fills .cache/mcp-tools-list/):
#      it re-extracts every document from the pinned commits and exits 1 if a document, manifest.json or a
#      LICENSES/ copy differs from the committed one.
#   2. measure-tools-list-benign.ts --check writes nothing (with --write, one report file); it exits 1 if a
#      flag is not covered by fp-classification.json.
#
# Needs: git, python3 >= 3.9, node >= 18 with `npm ci` done, network access to github.com.
# No upstream server is installed or run: tool definitions are read from source at the pinned commits.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "== 1/2 re-extract the tools/list documents from the pinned commits and compare with the committed corpus"
python3 scripts/mcp-tools-list/fetch-tools-list-corpus.py --check

echo "== 2/2 measure hunt / alert / enforce on both event shapes"
args=(--check)
if [[ -n "${CLI_RESULTS:-}" ]]; then args+=(--cli-results "$CLI_RESULTS"); fi
if [[ "${1:-}" == "--write" ]]; then args+=(--write); fi
npx tsx scripts/mcp-tools-list/measure-tools-list-benign.ts "${args[@]}"
