#!/usr/bin/env bash
# release.sh — One-command release for ATR
#
# Usage: ./scripts/release.sh [patch|minor|major]
#   Default: patch (0.4.0 → 0.4.1)
#
# What it does:
#   1. Runs tests + eval
#   2. Bumps version in package.json
#   3. Builds
#   4. Commits + tags + pushes
#
# It does not publish to npm. The pushed v* tag triggers
# .github/workflows/publish.yml, which stages the release with
# `npm stage publish`; a maintainer then approves it with 2FA. The package is
# declared dual-use (package.json contentPolicy, DISCLOSURE), and every
# publish attempt goes through npm's automated review, so a second, local
# publish of the same version would only race the staged one.

set -euo pipefail

BUMP_TYPE="${1:-patch}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ── Preflight checks ────────────────────────────────────
echo "=== Preflight ==="

if [ -n "$(git status --porcelain)" ]; then
  echo "ERROR: Working tree is dirty. Commit or stash changes first."
  exit 1
fi

echo "Running tests..."
npm test || { echo "ERROR: Tests failed."; exit 1; }

echo "Running eval..."
npm run eval || { echo "ERROR: Eval failed."; exit 1; }

# ── Read current version ─────────────────────────────────
CURRENT=$(node -e "console.log(require('./package.json').version)")
echo "Current version: $CURRENT"

# ── Calculate new version ────────────────────────────────
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"
case "$BUMP_TYPE" in
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  patch) PATCH=$((PATCH + 1)) ;;
  *) echo "ERROR: Invalid bump type '$BUMP_TYPE'. Use patch|minor|major."; exit 1 ;;
esac
NEW="$MAJOR.$MINOR.$PATCH"
echo "New version: $NEW"

# ── Bump version ──────────────────────────────────────────
node -e "
  const fs = require('fs');
  const p = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  p.version = '$NEW';
  fs.writeFileSync('package.json', JSON.stringify(p, null, 2) + '\n');
"
echo "  package.json → $NEW"

# ── Build ─────────────────────────────────────────────────
echo "Building..."
npm run build

# ── Commit + tag + push ──────────────────────────────────
echo "=== Releasing ==="
git add package.json
git commit -m "release: v$NEW"
git tag "v$NEW"
git push origin main
git push origin "v$NEW"

echo ""
echo "======================================="
echo "  v$NEW tagged and pushed"
echo "======================================="
echo ""
echo "publish.yml is now staging agent-threat-rules@$NEW on npm. Next:"
echo "  1. Approve the staged version with 2FA: npmjs.com -> Staged Packages,"
echo "     or: npm stage list agent-threat-rules && npm stage approve <stage-id>"
echo "  2. If the publish.yml run timed out waiting for the approval, re-run it"
echo "     to create the GitHub release."
echo "  3. Confirm on the registry: npm view agent-threat-rules@$NEW version"
