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
