#!/usr/bin/env bash
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
: "${BASE_SHA:?}" "${HEAD_SHA:?}"
[[ $BASE_SHA =~ ^[a-f0-9]{40,64}$ && $HEAD_SHA =~ ^[a-f0-9]{40,64}$ ]]
diff=$(mktemp)
trap 'rm -f "$diff"' EXIT
git diff --name-status -z -M "$BASE_SHA...$HEAD_SHA" > "$diff"
required=false added=false
while IFS= read -r -d '' status; do
  IFS= read -r -d '' path
  paths=("$path")
  if [[ $status =~ ^[RC][0-9]+$ ]]; then
    IFS= read -r -d '' path
    paths+=("$path")
  else
    [[ $status =~ ^[ADMTUXB]$ ]]
  fi
  for changed in "${paths[@]}"; do
    case $changed in
      crates/*/tests/*|*.md) ;;
      crates/*|Cargo.toml|Cargo.lock|ci/fetch-doona.sh|.github/ci/pins.env) required=true ;;
    esac
  done
  if [[ $status != D && $path =~ ^changes/[^/]+\.md$ && $path != changes/README.md ]]; then
    git show "$HEAD_SHA:$path" | PYTHONPATH="$ci_dir" python3 -c '
import sys
from changelog import parse_fragment
try:
    parse_fragment(sys.stdin.read(), sys.argv[1])
except ValueError as error:
    sys.exit(str(error))
' "$path"
    [[ $status != A ]] || added=true
  fi
done < "$diff"
if [[ $required == true && $added == false && ${NO_CHANGELOG:-false} != true ]]; then
  echo '::error::This PR must add a new changes/<branch-slug>.md fragment or have the no-changelog label; see changes/README.md.' >&2
  exit 1
fi
