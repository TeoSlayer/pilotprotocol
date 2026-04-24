#!/bin/bash
# One-shot migration: insert `source ./_lib.sh` into every test_*.sh in
# this directory, right after the shebang. Idempotent — running twice
# is a no-op.
#
# This ONLY sources the lib; it does NOT remove the duplicated color/log
# helpers that most tests define inline. The lib's definitions are
# identical, so redefinition is harmless. Cleanup of those duplicates
# is a follow-up (mechanical sed pass per-file, easier once the shared
# lib is proven in a run).
#
# Does not touch test scripts that already source _lib.sh.
#
# Dry-run:  DRY=1 ./migrate-tests.sh
# Apply:    ./migrate-tests.sh

set -euo pipefail
cd "$(dirname "$0")"

applied=0
skipped=0

for f in test_*.sh; do
  [ -f "$f" ] || continue
  if grep -qF "source ./_lib.sh" "$f"; then
    skipped=$((skipped+1))
    continue
  fi
  if [ "${DRY:-0}" = "1" ]; then
    echo "would migrate: $f"
    applied=$((applied+1))
    continue
  fi
  # Insert at line 2 — before line 2's content, after the shebang at
  # line 1. awk's `NR==2` block prints the source line, then falls
  # through to `{print}` which prints line 2 and every subsequent line.
  awk 'NR==2 {print "source \"$(dirname \"$0\")/_lib.sh\""; print ""} {print}' \
    "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  chmod +x "$f"
  applied=$((applied+1))
done

echo "migrate-tests.sh: applied=$applied skipped=$skipped"
