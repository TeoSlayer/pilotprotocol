#!/bin/bash
# Script to run a local dashboard with seeded test data
# Usage: ./tests/pilot_dashboard/run-dashboard.sh

set -e

cd "$(dirname "$0")/../.."

echo "Building binaries..."
make -s

echo ""
echo "Starting rendezvous server with dashboard..."
echo ""

# Start rendezvous in background
./bin/rendezvous \
  -registry-addr "127.0.0.1:9001" \
  -beacon-addr "127.0.0.1:9002" \
  -http "127.0.0.1:8080" &

RENDEZVOUS_PID=$!

# Cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down rendezvous server..."
    kill $RENDEZVOUS_PID 2>/dev/null || true
    exit 0
}
trap cleanup EXIT INT TERM

# Wait for server to start
echo "Waiting for server to start..."
sleep 2

# Seed the registry
echo ""
echo "Seeding registry with test data..."
echo ""

go run tests/pilot_dashboard/seed_dashboard_main.go 127.0.0.1:9001

echo ""
echo "======================================================================"
echo "✅ Dashboard is running!"
echo ""
echo "   Dashboard URL:  http://127.0.0.1:8080"
echo "   Registry Addr:  127.0.0.1:9001"
echo "   Beacon Addr:    127.0.0.1:9002"
echo ""
echo "   Press Ctrl+C to stop the server"
echo "======================================================================"
echo ""

# Wait for interrupt
wait $RENDEZVOUS_PID
