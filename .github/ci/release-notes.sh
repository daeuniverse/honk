#!/usr/bin/env bash
# Print the draft notes for a formal release: commits since the previous v* tag,
# grouped by their type(scope) prefix and credited to GitHub logins.
# Usage: release-notes.sh <tag>   (run inside a full clone; gh resolves logins
# through GH_TOKEN and GITHUB_REPOSITORY, and a failed lookup omits the login)
set -euo pipefail

tag=${1:?usage: release-notes.sh <tag>}
repo=${GITHUB_REPOSITORY:-daeuniverse/honk}
prev=$(git describe --tags --abbrev=0 --match 'v*' "$tag^" 2>/dev/null || true)
range=${prev:+$prev..}$tag

declare -A title=([feat]='New Features' [fix]='Bug Fixes' [perf]='Performance' [docs]='Documentation') sections=()
other=0

while IFS=$'\t' read -r sha subject; do
  if [[ ! $subject =~ ^([a-z]+)(\([^\)]*\))?!?:\ (.+)$ ]]; then
    other=$((other + 1))
    continue
  fi
  type=${BASH_REMATCH[1]}
  [[ $type == bench ]] && type=docs
  if [[ -z ${title[$type]+set} ]]; then
    other=$((other + 1))
    continue
  fi
  user=$(gh api "repos/$repo/commits/$sha" --jq '.author.login // empty' 2>/dev/null || true)
  sections[$type]+="- $subject${user:+ by @$user} in ${sha:0:9}"$'\n'
done < <(git log --no-merges --reverse --format='%H%x09%s' "$range")

printf '## Highlights\n\n<!-- Maintainer: two to five bullets on what this release means to a gateway operator. -->\n\n## What'"'"'s Changed\n'
for type in feat fix perf docs; do
  [[ -z ${sections[$type]-} ]] && continue
  printf '\n### %s\n\n%s' "${title[$type]}" "${sections[$type]}"
done
if (( other > 0 )); then
  printf '\n%d refactoring, test and maintenance commits are not listed.\n' "$other"
fi
if [[ -n $prev ]]; then
  printf '\n**Full Changelog**: https://github.com/%s/compare/%s...%s\n' "$repo" "$prev" "$tag"
fi
