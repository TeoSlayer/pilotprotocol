#!/usr/bin/env bash
# Build complete Pilot Protocol suite for Python SDK distribution
# This builds: daemon, pilotctl, gateway, and CGO bindings

set -euo pipefail

cd "$(dirname "$0")/../../.."  # Go to repo root

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)       echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux)   EXT="so" ;;
    darwin)  EXT="dylib" ;;
    *)       echo "Error: unsupported OS: $OS (Windows support coming)"; exit 1 ;;
esac

echo "================================================================"
echo "Building Pilot Protocol Suite for ${OS}/${ARCH}"
echo "================================================================"
echo ""

OUTPUT_DIR="sdk/python/pilotprotocol/bin"
mkdir -p "$OUTPUT_DIR"

# 1. Build daemon
echo "1. Building pilot-daemon..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -ldflags="-s -w" -o "$OUTPUT_DIR/pilot-daemon" ./cmd/daemon
echo "   ✓ Built: $OUTPUT_DIR/pilot-daemon"
echo ""

# 2. Build pilotctl
echo "2. Building pilotctl..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -ldflags="-s -w" -o "$OUTPUT_DIR/pilotctl" ./cmd/pilotctl
echo "   ✓ Built: $OUTPUT_DIR/pilotctl"
echo ""

# 3. Build gateway
echo "3. Building pilot-gateway..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -ldflags="-s -w" -o "$OUTPUT_DIR/pilot-gateway" ./cmd/gateway
echo "   ✓ Built: $OUTPUT_DIR/pilot-gateway"
echo ""

# 4. Build CGO bindings
echo "4. Building libpilot CGO bindings..."
cd sdk/cgo
CGO_ENABLED=1 GOOS="$OS" GOARCH="$ARCH" go build -buildmode=c-shared -ldflags="-s -w" -o "../../$OUTPUT_DIR/libpilot.$EXT" .
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
echo "✓ All binaries built successfully for ${OS}/${ARCH}"
echo ""
echo "Next steps:"
echo "  cd sdk/python"
echo "  python -m build"
echo ""
