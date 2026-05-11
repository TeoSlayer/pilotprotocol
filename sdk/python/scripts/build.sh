#!/usr/bin/env bash
# Build Python distribution packages (wheel + source distribution)

set -euo pipefail

cd "$(dirname "$0")/.."

echo "================================================================"
echo "Building Pilot Protocol Python SDK"
echo "================================================================"
echo ""

# Step 1: Build all binaries (CI publish workflows pre-populate pilotprotocol/bin/
# from the release tarball and skip this step via PILOT_SKIP_BUILD_BINARIES=1).
if [ "${PILOT_SKIP_BUILD_BINARIES:-0}" = "1" ]; then
    echo "1. Skipping binary build (PILOT_SKIP_BUILD_BINARIES=1)"
    if [ ! -f "pilotprotocol/bin/pilot-daemon" ]; then
        echo "   Error: pilotprotocol/bin/ is empty but PILOT_SKIP_BUILD_BINARIES=1." >&2
        echo "   The caller must populate it (e.g. extract from release tarball) first." >&2
        exit 1
    fi
    echo "   Found pre-populated binaries in pilotprotocol/bin/"
else
    echo "1. Building platform binaries..."
    ./scripts/build-binaries.sh
fi
echo ""

# Step 2: Clean old builds
echo "2. Cleaning old builds..."
rm -rf dist/ build/ *.egg-info
echo "   ✓ Cleaned"
echo ""

# Step 3: Build wheel and sdist
echo "3. Building wheel and source distribution..."
# Build platform-specific wheel (contains native binaries)
# All package metadata remains in pyproject.toml (PEP 621 compliant).
cat > setup.py << 'EOF'
from setuptools import setup
from setuptools.dist import Distribution
class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True
setup(distclass=BinaryDistribution)
EOF

if [ -n "${VIRTUAL_ENV:-}" ]; then
    python -m build --wheel
    python -m build --sdist
else
    python3 -m build --wheel
    python3 -m build --sdist
fi

# Clean up temporary setup.py
rm -f setup.py
echo ""

# Step 4: Verify with twine (skip in CI/Docker)
if [ "${SKIP_TWINE_CHECK:-}" != "1" ]; then
    echo "4. Verifying package..."
    python3 -m twine check dist/*
    echo ""
fi

echo "================================================================"
echo "✓ Build complete!"
echo "================================================================"
echo ""
echo "Created:"
ls -lh dist/
echo ""
