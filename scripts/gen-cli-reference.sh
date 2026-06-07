#!/usr/bin/env bash
# PILOT-54: regenerate docs/cli-reference.md from `pilotctl --help`.
# Invoked by CI (.github/workflows/cli-reference-check.yml) to guard
# against the reference doc drifting from the actual binary.
set -euo pipefail

cd "$(dirname "$0")/.."

# Build a fresh pilotctl so the doc reflects HEAD, not whatever happens
# to be on $PATH on the runner.
if [ ! -x ./pilotctl ]; then
    go build -o ./pilotctl ./cmd/pilotctl
fi

OUT=docs/cli-reference.md
TMP="$(mktemp)"

{
    echo '# pilotctl Reference'
    echo ''
    echo '> **Auto-generated** from `pilotctl --help`. Do not edit by hand — CI regenerates'
    echo '> on every PR via `scripts/gen-cli-reference.sh` and fails if the committed copy'
    echo '> differs from a fresh `pilotctl --help` capture (PILOT-54).'
    echo '>'
    echo '> Source: [`cmd/pilotctl/main.go`](../cmd/pilotctl/main.go).'
    echo ''
    echo '```text'
    ./pilotctl --help
    echo '```'
} > "$TMP"

mv "$TMP" "$OUT"
echo "Wrote $OUT ($(wc -l < "$OUT") lines)"
