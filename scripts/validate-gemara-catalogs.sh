#!/usr/bin/env bash
# Validate the Gemara catalogs in spec/category-registry/gemara/ against the
# Gemara CUE schemas.
#
# Usage:
#   scripts/validate-gemara-catalogs.sh <gemara-checkout>
#   GEMARA_SPEC_DIR=<gemara-checkout> scripts/validate-gemara-catalogs.sh
#
# <gemara-checkout> is a clone of https://github.com/gemaraproj/gemara at the
# release named by bundle.gemara-version in
# spec/category-registry/gemara/src/editorial.yaml. Each catalog is checked
# with the same command `grcli validate` runs, plus -c (every value concrete):
#
#   cue vet -c -d '#<metadata.type>' . <catalog>      (run inside the checkout)
#
# The publish workflow (.github/workflows/publish-gemara.yml) runs this before
# anything is pushed. It needs only bash, sed and cue on PATH.
set -euo pipefail

spec_dir="${1:-${GEMARA_SPEC_DIR:-}}"
if [ -z "$spec_dir" ] || [ ! -f "$spec_dir/vectorcatalog.cue" ]; then
  echo "usage: $0 <gemara-checkout>   (a clone of github.com/gemaraproj/gemara)" >&2
  exit 2
fi
command -v cue >/dev/null || { echo "cue is not on PATH (https://cuelang.org)" >&2; exit 2; }

catalog_dir="$(cd "$(dirname "$0")/../spec/category-registry/gemara" && pwd)"
spec_dir="$(cd "$spec_dir" && pwd)"
failed=0
count=0

for file in "$catalog_dir"/*.yaml; do
  # metadata.type is the only key at two-space indentation named `type` in a
  # generated catalog (author.type and actor types sit deeper).
  type="$(sed -n 's/^  type: *//p' "$file" | head -n 1)"
  case "$type" in
    VectorCatalog | CapabilityCatalog | ThreatCatalog | ControlCatalog) ;;
    *)
      echo "FAIL $(basename "$file"): unexpected metadata.type '$type'" >&2
      failed=1
      continue
      ;;
  esac
  count=$((count + 1))
  if (cd "$spec_dir" && cue vet -c -d "#$type" . "$file"); then
    echo "ok   $(basename "$file") as #$type"
  else
    echo "FAIL $(basename "$file") as #$type" >&2
    failed=1
  fi
done

if [ "$count" -eq 0 ]; then
  echo "no catalogs found in $catalog_dir" >&2
  exit 1
fi
exit "$failed"
