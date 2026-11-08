#!/usr/bin/env bash
# Reproduce the vendor guardrail test-suite measurement end to end.
#
#   bash scripts/vendor-suites/reproduce.sh           # verify, re-audit, re-measure (no measurement file written)
#   bash scripts/vendor-suites/reproduce.sh --write   # same, then write a new measurement file under data/measurements/vendor-guardrail-suites/
#
# What each step writes:
#   1. fetch-vendor-suites.py --check writes nothing in the repository (it fills the fetch cache): it re-extracts the corpus and the LICENSES/ copies from the
#      pinned commits and exits 1 if they differ from the committed files.
#   2. audit-legacy-corpora.py REWRITES data/test-corpora/vendor-guardrail-suites/legacy-corpora-provenance.json in
#      place; the script then runs `git diff --exit-code` on that file, so the step fails (and leaves the rewritten
#      file for inspection) when the re-run audit differs from the committed one.
#   3. measure-vendor-suites.ts --dry-run writes nothing; with --write it writes a measurement file and latest.json.
#
# Needs: git, python3 >= 3.9, node >= 18 with `npm ci` done, network access to github.com.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "== 1/3 re-extract the corpus from the pinned vendor commits and compare with the committed samples.jsonl"
python3 scripts/vendor-suites/fetch-vendor-suites.py --check

echo "== 2/3 re-run the provenance audit of the 2026-05-12 corpora (44 llm-guard + 6 nemo-guardrails + 44 promptfoo)"
python3 scripts/vendor-suites/audit-legacy-corpora.py
git diff --exit-code -- data/test-corpora/vendor-guardrail-suites/legacy-corpora-provenance.json \
  && echo "audit unchanged"

echo "== 3/3 measure every lane"
if [[ "${1:-}" == "--write" ]]; then
  npx tsx scripts/vendor-suites/measure-vendor-suites.ts
else
  npx tsx scripts/vendor-suites/measure-vendor-suites.ts --dry-run
fi
