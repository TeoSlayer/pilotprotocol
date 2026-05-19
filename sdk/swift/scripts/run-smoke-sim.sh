#!/usr/bin/env bash
# Build pilot-smoke-swift for the iOS simulator (arm64) and run it
# inside a booted simulator via simctl spawn. Mirrors the Go
# embedded-smoke runner.
#
# Usage:
#   run-smoke-sim.sh info
#   run-smoke-sim.sh alice
#   run-smoke-sim.sh bob PEER_ID PEER_ADDR
#
# Env:
#   PILOT_SIM_UDID — UDID of the booted simulator (default: picks the
#                    first booted device).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SWIFT_DIR="$REPO_ROOT/sdk/swift"
XCFW="$SWIFT_DIR/Frameworks/Pilot.xcframework"
SIM_SLICE="$XCFW/ios-arm64-simulator"

OUT_BIN="/tmp/pilot-smoke-swift"
SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"

UDID="${PILOT_SIM_UDID:-}"
if [ -z "$UDID" ]; then
    UDID="$(xcrun simctl list devices booted 2>/dev/null \
            | grep -oE '[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}' \
            | head -1)"
fi
if [ -z "$UDID" ]; then
    echo "no booted simulator; boot one with 'xcrun simctl boot <udid>'" >&2
    exit 1
fi

# Compile.
swiftc \
    -target arm64-apple-ios14.0-simulator \
    -sdk "$SDK" \
    -I "$SIM_SLICE/Headers" \
    -Xcc -fmodule-map-file="$SIM_SLICE/Headers/module.modulemap" \
    "$SWIFT_DIR/Sources/Pilot/Pilot.swift" \
    "$SWIFT_DIR/Examples/pilot-smoke-swift/main.swift" \
    "$SIM_SLICE/libPilot.a" \
    -framework Foundation \
    -lresolv \
    -o "$OUT_BIN"

echo ">>> built $OUT_BIN, spawning in simulator $UDID"
exec xcrun simctl spawn "$UDID" "$OUT_BIN" "$@"
