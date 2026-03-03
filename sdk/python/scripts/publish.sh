#!/usr/bin/env bash
# Publish to PyPI or TestPyPI

set -euo pipefail

cd "$(dirname "$0")/.."

# Determine Python command
if [ -n "${VIRTUAL_ENV:-}" ]; then
    PYTHON="python"
else
    PYTHON="python3"
fi

REPO="${1:-}"

if [ -z "$REPO" ]; then
    echo "Usage: $0 [pypi|testpypi]"
    echo ""
    echo "  pypi      - Publish to PyPI (production)"
    echo "  testpypi  - Publish to TestPyPI (testing)"
    echo ""
    exit 1
fi

if [ "$REPO" != "pypi" ] && [ "$REPO" != "testpypi" ]; then
    echo "Error: Invalid repository '${REPO}'"
    echo ""
    echo "Usage: $0 [pypi|testpypi]"
    echo ""
    echo "  pypi      - Publish to PyPI (production)"
    echo "  testpypi  - Publish to TestPyPI (testing)"
    exit 1
fi

# Check dist/ exists and has files
if [ ! -d dist/ ]; then
    echo "Error: dist/ directory not found."
    echo "Run './scripts/build.sh' first to build the package."
    exit 1
fi

if [ -z "$(ls -A dist/)" ]; then
    echo "Error: dist/ directory is empty."
    echo "Run './scripts/build.sh' first to build the package."
    exit 1
fi

# Check twine is installed
if ! $PYTHON -m twine --version >/dev/null 2>&1; then
    echo "Error: twine is not installed."
    echo ""
    echo "Install it with:"
    echo "  pip install twine"
    exit 1
fi

echo "================================================================"
echo "Publishing to ${REPO^^}"
echo "================================================================"
echo ""

# Show what will be published
echo "Package files to upload:"
ls -lh dist/
echo ""

# Verify package integrity
echo "Verifying package integrity..."
$PYTHON -m twine check dist/*
if [ $? -ne 0 ]; then
    echo ""
    echo "Error: Package verification failed."
    echo "Fix the issues above before publishing."
    exit 1
fi
echo "✓ Package verification passed"
echo ""

# Confirmation for production PyPI
if [ "$REPO" = "pypi" ]; then
    echo "⚠️  WARNING: You are about to publish to PRODUCTION PyPI!"
    echo ""
    echo "This action:"
    echo "  - Cannot be undone"
    echo "  - Makes the package publicly available"
    echo "  - Version numbers cannot be reused"
    echo ""
    read -p "Are you sure you want to continue? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    echo ""
fi

# Upload to repository
echo "Uploading to ${REPO}..."
echo ""

if [ "$REPO" = "testpypi" ]; then
    $PYTHON -m twine upload --repository testpypi dist/*
else
    $PYTHON -m twine upload dist/*
fi

UPLOAD_STATUS=$?

if [ $UPLOAD_STATUS -eq 0 ]; then
    echo ""
    echo "================================================================"
    echo "✓ Successfully published to ${REPO^^}!"
    echo "================================================================"
    echo ""
    
    if [ "$REPO" = "testpypi" ]; then
        echo "Test installation:"
        echo "  pip install --index-url https://test.pypi.org/simple/ --no-deps pilotprotocol"
        echo ""
        echo "Note: Use --no-deps to avoid dependency issues on TestPyPI"
        echo ""
        echo "View package:"
        echo "  https://test.pypi.org/project/pilotprotocol/"
    else
        echo "Installation:"
        echo "  pip install pilotprotocol"
        echo ""
        echo "View package:"
        echo "  https://pypi.org/project/pilotprotocol/"
        echo ""
        echo "Test the installation:"
        echo "  python3 -m venv /tmp/test-install"
        echo "  source /tmp/test-install/bin/activate"
        echo "  pip install pilotprotocol"
        echo "  pilotctl info"
        echo "  python -c 'from pilotprotocol import Driver; print(Driver.__doc__)'"
    fi
    echo ""
else
    echo ""
    echo "================================================================"
    echo "⚠ Upload failed"
    echo "================================================================"
    echo ""
    echo "Common issues:"
    echo "  1. Authentication error: Set up ~/.pypirc with API tokens"
    echo "  2. Version already exists: Update version in pyproject.toml"
    echo "  3. Package name already taken: Change project name"
    echo ""
    echo "For TestPyPI setup:"
    echo "  https://test.pypi.org/manage/account/#api-tokens"
    echo ""
    echo "For PyPI setup:"
    echo "  https://pypi.org/manage/account/#api-tokens"
    echo ""
    exit 1
fi
