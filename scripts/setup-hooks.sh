#!/bin/bash

# Setup pre-commit hooks for Pilot Protocol
# Run this script after cloning the repository

HOOKS_DIR=".git/hooks"
HOOK_FILE="$HOOKS_DIR/pre-commit"

echo "Setting up pre-commit hooks..."

# Check if .git directory exists
if [ ! -d ".git" ]; then
    echo "Error: Not a git repository. Run this from the project root."
    exit 1
fi

# Create pre-commit hook
cat > "$HOOK_FILE" << 'EOF'
#!/bin/sh

# Pre-commit hook for Pilot Protocol
# Runs go fmt, go vet, tests, and updates coverage

echo "Running pre-commit checks..."

# 1. Format code
echo "→ Running go fmt..."
if ! gofmt -w -s .; then
    echo "✗ go fmt failed"
    exit 1
fi

# 2. Vet code
echo "→ Running go vet..."
if ! go vet ./...; then
    echo "✗ go vet failed"
    exit 1
fi

# 3. Run tests
echo "→ Running tests..."
if ! (cd tests && go test -v -timeout 30s); then
    echo "✗ tests failed"
    exit 1
fi

# 4. Update coverage
echo "→ Updating coverage badge..."
if ! make coverage > /dev/null 2>&1; then
    echo "✗ coverage generation failed"
    exit 1
fi

# Stage any changes from gofmt and coverage
git add -A

echo "✓ All pre-commit checks passed"
exit 0
EOF

# Make hook executable
chmod +x "$HOOK_FILE"

echo "✓ Pre-commit hook installed successfully!"
echo ""
echo "The hook will run on every commit and check:"
echo "  - Code formatting (go fmt)"
echo "  - Static analysis (go vet)"
echo "  - Tests (go test)"
echo "  - Coverage badge update"
echo ""
echo "To skip the hook temporarily, use: git commit --no-verify"
