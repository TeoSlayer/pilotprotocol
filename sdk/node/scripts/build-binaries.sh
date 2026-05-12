#!/usr/bin/env bash
# Build complete Pilot Protocol suite for Node SDK distribution
# This builds: daemon, pilotctl, gateway, and CGO bindings

set -euo pipefail

cd "$(dirname "$0")/../../.."  # Go to repo root

# Read SDK version (from package.json) so the seeder marker matches it.
SDK_VERSION=$(node -e "console.log(JSON.parse(require('fs').readFileSync('sdk/node/package.json','utf8')).version)")

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

BIN_ROOT="sdk/node/bin"
PLATFORM_DIR="$BIN_ROOT/${OS}-${ARCH}"
mkdir -p "$PLATFORM_DIR"

# 1. Build daemon
echo "1. Building pilot-daemon..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -ldflags="-s -w" -o "$PLATFORM_DIR/pilot-daemon" ./cmd/daemon
echo "   ✓ Built: $PLATFORM_DIR/pilot-daemon"
echo ""

# 2. Build pilotctl
echo "2. Building pilotctl..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -ldflags="-s -w" -o "$PLATFORM_DIR/pilotctl" ./cmd/pilotctl
echo "   ✓ Built: $PLATFORM_DIR/pilotctl"
echo ""

# 3. Build gateway
echo "3. Building pilot-gateway..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -ldflags="-s -w" -o "$PLATFORM_DIR/pilot-gateway" ./cmd/gateway
echo "   ✓ Built: $PLATFORM_DIR/pilot-gateway"
echo ""

# 4. Build updater
echo "4. Building pilot-updater..."
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -ldflags="-s -w" -o "$PLATFORM_DIR/pilot-updater" ./cmd/updater
echo "   ✓ Built: $PLATFORM_DIR/pilot-updater"
echo ""

# 5. Build CGO bindings
echo "5. Building libpilot CGO bindings..."
cd sdk/cgo
CGO_ENABLED=1 GOOS="$OS" GOARCH="$ARCH" go build -buildmode=c-shared -ldflags="-s -w" -o "../../$PLATFORM_DIR/libpilot.$EXT" .
cd ../..
echo "   ✓ Built: $PLATFORM_DIR/libpilot.$EXT"
echo ""

# 6. Write .pilot-version marker at the bin/ root (shared across all platform
#    subdirs). The runtime seeder reads this to compare against whatever's
#    already installed at ~/.pilot/bin/.
echo "$SDK_VERSION" > "$BIN_ROOT/.pilot-version"
echo "6. Wrote $BIN_ROOT/.pilot-version → $SDK_VERSION"
echo ""

# 7. macOS ad-hoc codesign + strip quarantine. Mirrors the main release
#    workflow so SDK-shipped binaries don't trigger Gatekeeper "killed: 9"
#    or "cannot be opened because Apple cannot check it for malicious
#    software" when downloaded via npm.
if [ "$OS" = "darwin" ]; then
    echo "7. macOS ad-hoc codesign + strip quarantine..."
    for bin in "$PLATFORM_DIR/pilot-daemon" "$PLATFORM_DIR/pilotctl" "$PLATFORM_DIR/pilot-gateway" "$PLATFORM_DIR/pilot-updater" "$PLATFORM_DIR/libpilot.$EXT"; do
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
du -h "$PLATFORM_DIR"/* | awk '{printf "  %-30s %s\n", $2, $1}'
echo ""
echo "Total size:"
du -sh "$PLATFORM_DIR" | awk '{printf "  %s\n", $1}'
echo ""
echo "✓ All binaries built successfully for ${OS}/${ARCH}"
echo ""
echo "Next steps:"
echo "  cd sdk/node"
echo "  npm run build"
echo "  npm pack"
echo ""
