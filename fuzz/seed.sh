#!/bin/bash
# Regenerate the committed seed corpus from repository-owned inputs. The corpus
# holds seeds only; inputs a fuzz run grows go to a scratch directory (the
# weekly job uploads them as an artefact), never here.
# Files are named by content hash so regeneration is idempotent.
set -euo pipefail
cd "$(dirname "$0")/.."
seed() { # target file
  local sum; sum=$(sha1sum < "$2" | cut -c1-40)
  cp "$2" "fuzz/corpus/$1/$sum"
}
rm -rf fuzz/corpus/document fuzz/corpus/lexer fuzz/corpus/share_link
mkdir -p fuzz/corpus/document fuzz/corpus/lexer fuzz/corpus/share_link
while IFS= read -r f; do seed document "$f"; seed lexer "$f"; done < <(
  find crates/honk-config/conformance/cases crates/honk-config/tests/fixtures -name '*.dae' | sort
  printf '%s\n' example.dae config.dae config.min.dae)
# Share links: every URI literal in the share-link tests, the node reference and the cases.
grep -rhoE "[a-z][a-z0-9+.-]*://[^\"' \`<>)]+" crates/honk-config/tests/share_link.rs \
  crates/honk-config/src/share_link.rs crates/honk-config/src/share_link/ doc/en/reference/nodes.md \
  crates/honk-config/conformance/cases 2>/dev/null | sort -u | while IFS= read -r uri; do
  printf '%s' "$uri" > /tmp/seed.$$; seed share_link /tmp/seed.$$
done; rm -f /tmp/seed.$$
for t in document lexer share_link; do printf '%s: %s seeds\n' "$t" "$(find fuzz/corpus/$t -type f | wc -l)"; done
