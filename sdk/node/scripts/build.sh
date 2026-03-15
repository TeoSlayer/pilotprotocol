#!/usr/bin/env bash
# Build Node SDK distribution package (TypeScript + platform binaries)

set -euo pipefail

cd "$(dirname "$0")/.."

echo "================================================================"
echo "Building Pilot Protocol Node SDK"
echo "================================================================"
echo ""

# Step 1: Build platform binaries
echo "1. Building platform binaries..."
./scripts/build-binaries.sh
echo ""

# Step 2: Clean old builds
echo "2. Cleaning old builds..."
rm -rf dist/
echo "   ✓ Cleaned"
echo ""

# Step 3: Install dependencies
echo "3. Installing dependencies..."
npm ci
echo "   ✓ Dependencies installed"
echo ""

# Step 4: Build TypeScript
echo "4. Building TypeScript..."
npx tsc
echo "   ✓ TypeScript compiled"
echo ""

# Step 5: Pack for verification
echo "5. Creating package..."
npm pack --dry-run
echo ""

echo "================================================================"
echo "✓ Build complete!"
echo "================================================================"
echo ""
echo "To publish:"
echo "  npm publish"
echo ""
