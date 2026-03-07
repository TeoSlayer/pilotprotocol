#!/usr/bin/env bash
# Generate coverage badge SVG from coverage.json

set -euo pipefail

# Go to SDK root directory
cd "$(dirname "$0")/.."

# Check if coverage.json exists
if [ ! -f coverage.json ]; then
    echo "Error: coverage.json not found. Run 'make test-coverage' first."
    exit 1
fi

# Extract coverage percentage
coverage=$(/Users/alexgodo/web4/pilotprotocol/.venv/bin/python -c "import json; data=json.load(open('coverage.json')); print(int(data['totals']['percent_covered']))")

echo "Coverage: ${coverage}%"

# Determine badge color
if [ "$coverage" -ge 90 ]; then
    color="brightgreen"
elif [ "$coverage" -ge 80 ]; then
    color="green"
elif [ "$coverage" -ge 70 ]; then
    color="yellowgreen"
elif [ "$coverage" -ge 60 ]; then
    color="yellow"
else
    color="red"
fi

# Generate badge SVG
badge_url="https://img.shields.io/badge/coverage-${coverage}%25-${color}"

# Download badge
curl -s "${badge_url}" -o coverage-badge.svg

echo "Coverage badge generated: coverage-badge.svg (${coverage}%, ${color})"
