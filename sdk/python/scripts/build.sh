#!/usr/bin/env bash
# Build Python distribution packages (wheel + source distribution)

set -euo pipefail

cd "$(dirname "$0")/.."

echo "================================================================"
echo "Building Pilot Protocol Python SDK"
echo "================================================================"
echo ""

# Step 1: Build all binaries
echo "1. Building platform binaries..."
./scripts/build-binaries.sh
echo ""

# Step 2: Clean old builds
echo "2. Cleaning old builds..."
rm -rf dist/ build/ *.egg-info
echo "   ✓ Cleaned"
echo ""

# Step 3: Build wheel and sdist
echo "3. Building wheel and source distribution..."
if [ -n "$VIRTUAL_ENV" ]; then
    python -m build
else
    python3 -m build
fi
echo ""

# Step 4: Verify with twine
echo "4. Verifying package..."
python3 -m twine check dist/*
echo ""

echo "================================================================"
echo "✓ Build complete!"
echo "================================================================"
echo ""
echo "Created:"
ls -lh dist/
echo ""
echo "Next steps:"
echo "  - Test locally: python3 -m venv /tmp/test && /tmp/test/bin/pip install dist/*.whl"
echo "  - Publish to TestPyPI: ./scripts/publish.sh testpypi"
echo "  - Publish to PyPI: ./scripts/publish.sh pypi"
echo ""
