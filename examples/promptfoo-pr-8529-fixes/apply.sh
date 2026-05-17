#!/usr/bin/env bash
# Apply the PR #8529 fix draft to a local promptfoo checkout.
#
# Usage:
#   ./apply.sh <path-to-promptfoo-checkout>
#
# The target checkout must already be on the PR's branch
# (examples/redteam-atr-mcp-defense) or a branch forked from it.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <path-to-promptfoo-checkout>" >&2
  exit 2
fi

TARGET="$1"
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="${TARGET%/}/examples/redteam-atr-mcp-defense"

if [[ ! -d "${TARGET%/}/.git" ]]; then
  echo "error: $TARGET is not a git checkout" >&2
  exit 1
fi

mkdir -p "$DEST"

cp "$SRC/atr-assertion.mjs"    "$DEST/atr-assertion.mjs"
cp "$SRC/promptfooconfig.yaml" "$DEST/promptfooconfig.yaml"
cp "$SRC/README.md"            "$DEST/README.md"

echo "wrote:"
echo "  $DEST/atr-assertion.mjs"
echo "  $DEST/promptfooconfig.yaml"
echo "  $DEST/README.md"
echo
echo "next:"
echo "  cd $TARGET"
echo "  git add examples/redteam-atr-mcp-defense"
echo "  git commit -m 'fix(examples/redteam-atr-mcp-defense): docstring coverage + static import + drop stale transformVars'"
echo "  git push"
