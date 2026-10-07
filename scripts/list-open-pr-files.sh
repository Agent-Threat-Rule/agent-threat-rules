#!/usr/bin/env bash
# Write every path the repository's open PRs touch to FILE, one per line.
#
# The lanes that allocate rule ids (fn-mine-scheduled.yml, promote-semantic.yml)
# skip the ids in these paths, because another lane's open PR holds ids main
# does not have yet. `gh pr list --json files` returns at most 100 files per PR,
# sorted by path, so a large PR's rules/ files can fall off the end and their
# ids look free. A PR that lists fewer files than it changed is read in full
# from the REST API instead.
#
# Run from the checkout, with gh authenticated (GH_TOKEN). Any gh failure fails
# the script and leaves FILE unwritten: an empty list is how ids collide.
#
# USAGE: scripts/list-open-pr-files.sh FILE
set -euo pipefail
out="${1:?usage: scripts/list-open-pr-files.sh FILE}"

listing=$(gh pr list --state open --limit 1000 --json number,changedFiles,files)
complete=$(jq -r '.[] | select((.files | length) >= .changedFiles) | .files[].path' <<<"$listing")
truncated=$(jq -r '.[] | select((.files | length) < .changedFiles) | .number' <<<"$listing")

{
  [ -z "$complete" ] || printf '%s\n' "$complete"
  for n in $truncated; do
    gh api --paginate "repos/{owner}/{repo}/pulls/$n/files" --jq '.[].filename'
  done
} > "$out.partial"
mv "$out.partial" "$out"
