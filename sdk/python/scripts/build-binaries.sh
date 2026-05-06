#!/usr/bin/env bash
# Build complete Pilot Protocol suite for Python SDK distribution
# This builds: daemon, pilotctl, gateway, and CGO bindings

set -euo pipefail

cd "$(dirname "$0")/../../.."  # Go to repo root

# Read SDK version from pyproject.toml so the seeder marker matches it.
SDK_VERSION=$(awk -F\" '/^version = /{print $2; exit}' sdk/python/pyproject.toml)

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

# 4. Build updater
echo "4. Building pilot-updater..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -ldflags="-s -w" -o "$OUTPUT_DIR/pilot-updater" ./cmd/updater
echo "   ✓ Built: $OUTPUT_DIR/pilot-updater"
echo ""

# 5. Build CGO bindings
echo "5. Building libpilot CGO bindings..."
cd sdk/cgo
CGO_ENABLED=1 GOOS="$OS" GOARCH="$ARCH" go build -buildmode=c-shared -ldflags="-s -w" -o "../../$OUTPUT_DIR/libpilot.$EXT" .
cd ../..
echo "   ✓ Built: $OUTPUT_DIR/libpilot.$EXT"
echo ""

# 6. Write .pilot-version marker so the runtime seeder can compare against
#    whatever's already installed at ~/.pilot/bin/.
echo "$SDK_VERSION" > "$OUTPUT_DIR/.pilot-version"
echo "6. Wrote $OUTPUT_DIR/.pilot-version → $SDK_VERSION"
echo ""

# 7. macOS ad-hoc codesign + strip quarantine. Mirrors the main release
#    workflow so SDK-shipped binaries don't trigger Gatekeeper "killed: 9"
#    or "cannot be opened because Apple cannot check it for malicious
#    software" when downloaded via pip.
if [ "$OS" = "darwin" ]; then
    echo "7. macOS ad-hoc codesign + strip quarantine..."
    for bin in "$OUTPUT_DIR/pilot-daemon" "$OUTPUT_DIR/pilotctl" "$OUTPUT_DIR/pilot-gateway" "$OUTPUT_DIR/pilot-updater" "$OUTPUT_DIR/libpilot.$EXT"; do
        codesign --force --deep --sign - "$bin"
        xattr -cr "$bin" || true
        codesign -dv "$bin" 2>&1 | grep -E "Signature|Authority|TeamIdentifier" | head -1 || true
    done
    echo "   ✓ codesigned ${OS} binaries"
    echo ""
fi

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
