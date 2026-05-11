#!/usr/bin/env bash
# Build complete Pilot Protocol suite for Node SDK distribution.
#
# Local-dev only — CI publish jobs pull executables from the GitHub release
# and build libpilot themselves; see .github/workflows/publish-node-sdk.yml.
#
# Output: writes binaries into the matching per-platform sub-package at
#   sdk/node/packages/<os>-<node-arch>/bin/
# which the runtime resolver finds via the in-repo fallback path when the
# sub-package is not yet on npm (i.e. when developing locally).

set -euo pipefail

cd "$(dirname "$0")/../../.."  # Go to repo root

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Both go-style (amd64/arm64) and node-style (x64/arm64) names are needed:
# go for the build target, node for the sub-package directory.
case "$ARCH" in
    x86_64)  GOARCH="amd64"; NODEARCH="x64"   ;;
    aarch64) GOARCH="arm64"; NODEARCH="arm64" ;;
    arm64)   GOARCH="arm64"; NODEARCH="arm64" ;;
    *)       echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux)   EXT="so" ;;
    darwin)  EXT="dylib" ;;
    *)       echo "Error: unsupported OS: $OS (Windows support coming)"; exit 1 ;;
esac

echo "================================================================"
echo "Building Pilot Protocol Suite for ${OS}/${GOARCH} (npm: ${OS}-${NODEARCH})"
echo "================================================================"
echo ""

# Sub-package bin/ — picked up by cli.ts / ffi.ts via require.resolve in
# production, or via the in-repo fallback path during local dev.
OUTPUT_DIR="sdk/node/packages/${OS}-${NODEARCH}/bin"
mkdir -p "$OUTPUT_DIR"

# 1. Build daemon
echo "1. Building pilot-daemon..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$GOARCH" go build -ldflags="-s -w" -o "$OUTPUT_DIR/pilot-daemon" ./cmd/daemon
echo "   ✓ Built: $OUTPUT_DIR/pilot-daemon"
echo ""

# 2. Build pilotctl
echo "2. Building pilotctl..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$GOARCH" go build -ldflags="-s -w" -o "$OUTPUT_DIR/pilotctl" ./cmd/pilotctl
echo "   ✓ Built: $OUTPUT_DIR/pilotctl"
echo ""

# 3. Build gateway
echo "3. Building pilot-gateway..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$GOARCH" go build -ldflags="-s -w" -o "$OUTPUT_DIR/pilot-gateway" ./cmd/gateway
echo "   ✓ Built: $OUTPUT_DIR/pilot-gateway"
echo ""

# 4. Build updater
echo "4. Building pilot-updater..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$GOARCH" go build -ldflags="-s -w" -o "$OUTPUT_DIR/pilot-updater" ./cmd/updater
echo "   ✓ Built: $OUTPUT_DIR/pilot-updater"
echo ""

# 5. Build CGO bindings
echo "5. Building libpilot CGO bindings..."
cd sdk/cgo
CGO_ENABLED=1 GOOS="$OS" GOARCH="$GOARCH" go build -buildmode=c-shared -ldflags="-s -w" -o "../../$OUTPUT_DIR/libpilot.$EXT" .
cd ../..
echo "   ✓ Built: $OUTPUT_DIR/libpilot.$EXT"
echo ""

# Show sizes
echo "================================================================"
echo "Build Summary:"
echo "================================================================"
du -h "$OUTPUT_DIR"/* | awk '{printf "  %-30s %s\n", $2, $1}'
echo ""
echo "Total size:"
du -sh "$OUTPUT_DIR" | awk '{printf "  %s\n", $1}'
echo ""
echo "✓ All binaries built successfully for ${OS}/${GOARCH}"
echo ""
echo "Next steps:"
echo "  cd sdk/node"
echo "  npm run build"
echo "  npm pack"
echo ""
