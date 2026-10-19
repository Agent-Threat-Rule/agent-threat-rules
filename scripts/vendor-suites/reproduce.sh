#!/usr/bin/env bash
# Reproduce the vendor guardrail test-suite measurement end to end.
#
#   bash scripts/vendor-suites/reproduce.sh           # verify corpus against pinned upstream commits, re-audit, re-measure (prints, writes nothing)
#   bash scripts/vendor-suites/reproduce.sh --write   # same, then write a new measurement file under data/measurements/vendor-guardrail-suites/
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
