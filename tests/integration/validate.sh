#!/bin/bash
# Quick test runner - validates integration test setup

set -e

echo "Validating integration test setup..."
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed"
    exit 1
fi
echo "✓ Docker is installed"

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not installed"
    exit 1
fi
echo "✓ Docker Compose is available"

# Check if required files exist
for file in Dockerfile docker-compose.yml test_cli.sh test_sdk.py Makefile README.md; do
    if [ ! -f "$file" ]; then
        echo "❌ Missing file: $file"
        exit 1
    fi
done
echo "✓ All required files present"

# Check if scripts are executable
if [ ! -x test_cli.sh ] || [ ! -x test_sdk.py ]; then
    echo "❌ Test scripts are not executable"
    echo "Run: chmod +x test_cli.sh test_sdk.py"
    exit 1
fi
echo "✓ Test scripts are executable"

# Check Docker daemon
if ! docker ps &> /dev/null; then
    echo "❌ Docker daemon is not running"
    exit 1
fi
echo "✓ Docker daemon is running"

echo ""
echo "========================================="
echo "Integration test setup is valid!"
echo "========================================="
echo ""
echo "Quick start:"
echo "  make test        # Run all tests"
echo "  make test-cli    # Run CLI tests only"
echo "  make test-sdk    # Run SDK tests only"
echo ""
echo "Using Docker Compose:"
echo "  docker-compose up --build"
echo ""
echo "See README.md for full documentation"
echo ""
