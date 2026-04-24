#!/bin/bash
# Parallel NAT suite driver. Each test gets:
#   - a unique COMPOSE_PROJECT_NAME (prevents container/network name clash),
#   - a unique pair of subnet prefixes (prevents Docker "pool overlaps"
#     errors; RFC2544 198.18.0.0/15 sub-allocated by slot index).
# Concurrency is controlled by NAT_PARALLEL (default 4).
#
# The 198.18/15 range is NOT treated as "private" by Go's net.IP.IsPrivate(),
# so the daemon's STUN-override logic behaves the same as with RFC5737 —
# which is the reason we can't just use 10.x.x.x here.
#
# Usage:
#   bash run_nat_suite_parallel.sh                  # 4-way parallel, all tests
#   NAT_PARALLEL=8 bash run_nat_suite_parallel.sh   # 8-way parallel
#   NAT_TESTS="test_nat_full_cone.sh test_nat_hairpin.sh" bash ...
set -u

cd "$(dirname "$0")" || exit 1

: "${NAT_PARALLEL:=4}"
: "${NAT_TIMEOUT:=300}"
: "${NAT_TESTS:=}"
LOG_DIR="/tmp/nat_logs_par"
SUMMARY="/tmp/nat_suite_par.log"
SLOT_FILE="/tmp/nat_suite_par.slots"
mkdir -p "$LOG_DIR"
: > "$SUMMARY"
rm -f "${SLOT_FILE}".*

# Slot acquisition without flock (macOS lacks it). Each slot has a lock
# file; workers race to create one via `set -o noclobber` (atomic on
# most filesystems). Holders release the slot when the test finishes.
acquire_slot() {
    local attempt i
    for attempt in $(seq 1 600); do
        for i in $(seq 1 "$NAT_PARALLEL"); do
            if ( set -o noclobber; echo $$ > "${SLOT_FILE}.${i}" ) 2>/dev/null; then
                echo "$i"
                return 0
            fi
        done
        sleep 0.1
    done
    echo 1  # fallback — should never happen with xargs -P=NAT_PARALLEL
}

release_slot() { rm -f "${SLOT_FILE}.$1" 2>/dev/null; }

run_one() {
    local t="$1"
    local name="${t%.sh}"
    local slot
    slot=$(acquire_slot)
    # Map slot -> unique /24 prefixes. We keep 4 distinct bridge roles:
    #   NAT_PUB   — simulated "public internet"
    #   NAT_PRV   — first private LAN (agent-a)
    #   NAT_PRV_B — second private LAN (agent-b, dual-NAT)
    #   NAT_PUB2  — second public iface (multihomed)
    #   NAT_CGN   — carrier-grade NAT middle layer
    # All live inside 198.18/15 (RFC2544) with slot * 5 octets spacing
    # so /24s don't overlap within a slot or across slots.
    local base=$((slot * 5))
    export COMPOSE_PROJECT_NAME="nat${slot}_${name}"
    export NAT_PUB="198.18.$((base + 0))"
    export NAT_PRV="198.18.$((base + 1))"
    export NAT_PRV_B="198.18.$((base + 2))"
    export NAT_PUB2="198.18.$((base + 3))"
    export NAT_CGN="198.18.$((base + 4))"
    timeout "$NAT_TIMEOUT" bash "$t" \
        > "$LOG_DIR/$name.log" 2>&1
    local rc=$?
    release_slot "$slot"
    local tail_line
    tail_line=$(grep -E '^Passed:' "$LOG_DIR/$name.log" | tail -1 \
        | sed -E 's/\x1B\[[0-9;]*[mK]//g')
    printf "%-42s slot=%d rc=%d  %s\n" "$name" "$slot" "$rc" "${tail_line:-no-summary}"
}
export -f acquire_slot release_slot run_one
export NAT_TIMEOUT NAT_PARALLEL LOG_DIR SLOT_FILE

echo "[parallel nat suite] NAT_PARALLEL=$NAT_PARALLEL  timeout=${NAT_TIMEOUT}s"
echo "[parallel nat suite] log dir:  $LOG_DIR"
echo "[parallel nat suite] summary:  $SUMMARY"
echo "[parallel nat suite] subnets:  198.18.{slot*5+0..4}.0/24 per slot"
echo

if [ -n "$NAT_TESTS" ]; then
    tests=$NAT_TESTS
else
    tests=$(ls test_nat_*.sh)
fi

echo "$tests" \
    | tr ' ' '\n' \
    | xargs -n 1 -P "$NAT_PARALLEL" -I {} bash -c 'run_one "$@"' _ {} \
    | tee "$SUMMARY"

echo
echo "=== totals ==="
pass=$(grep -c 'rc=0' "$SUMMARY" 2>/dev/null || echo 0)
total=$(wc -l < "$SUMMARY")
fail=$((total - pass))
echo "passed: $pass / $total"
[ "$fail" -eq 0 ]
