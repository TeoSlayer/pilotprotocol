#!/usr/bin/env bash
# Run full test suite with coverage

set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Running tests with coverage ==="
python -m pytest tests/ \
    --cov=pilotprotocol \
    --cov-report=term-missing \
    --cov-report=html:htmlcov \
    --cov-report=json:coverage.json \
    -v

echo ""
echo "=== Coverage Summary ==="
python -c "import json; data=json.load(open('coverage.json')); print(f\"Total coverage: {data['totals']['percent_covered']:.2f}%\")"

echo ""
echo "✓ Tests complete!"
echo "  - HTML report: htmlcov/index.html"
echo "  - JSON report: coverage.json"
