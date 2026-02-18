#!/bin/bash
set -e

COVERAGE_FILE="coverage/coverage.out"
BADGE_DIR="coverage"
BADGE_FILE="$BADGE_DIR/badge.svg"

if [ ! -f "$COVERAGE_FILE" ]; then
    echo "Coverage file not found: $COVERAGE_FILE"
    exit 1
fi

# Extract total coverage percentage
COVERAGE=$(go tool cover -func="$COVERAGE_FILE" | tail -1 | awk '{print $3}' | sed 's/%//')

# Round to integer
COVERAGE_INT=$(printf "%.0f" "$COVERAGE")

# Determine badge color based on coverage
if [ "$COVERAGE_INT" -ge 80 ]; then
    COLOR="brightgreen"
elif [ "$COVERAGE_INT" -ge 60 ]; then
    COLOR="green"
elif [ "$COVERAGE_INT" -ge 40 ]; then
    COLOR="yellow"
elif [ "$COVERAGE_INT" -ge 20 ]; then
    COLOR="orange"
else
    COLOR="red"
fi

# Generate SVG badge
cat > "$BADGE_FILE" << EOF
<svg xmlns="http://www.w3.org/2000/svg" width="110" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width="110" height="20" rx="3" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <path fill="#555" d="M0 0h63v20H0z"/>
    <path fill="#$([ "$COLOR" = "brightgreen" ] && echo "4c1" || [ "$COLOR" = "green" ] && echo "97ca00" || [ "$COLOR" = "yellow" ] && echo "dfb317" || [ "$COLOR" = "orange" ] && echo "fe7d37" || echo "e05d44")" d="M63 0h47v20H63z"/>
    <path fill="url(#b)" d="M0 0h110v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="31.5" y="15" fill="#010101" fill-opacity=".3">coverage</text>
    <text x="31.5" y="14">coverage</text>
    <text x="86.5" y="15" fill="#010101" fill-opacity=".3">${COVERAGE_INT}%</text>
    <text x="86.5" y="14">${COVERAGE_INT}%</text>
  </g>
</svg>
EOF

echo "Coverage badge generated: $BADGE_FILE (${COVERAGE_INT}%)"
