#!/bin/bash
# Parallel integration-test runner.
#
# Discovers every test_*.sh in this directory, distributes them across N
# worker slots, and runs them concurrently. Each worker gets its own
# Docker Compose project name + its own /24 subnet, so `$DC down -v` and
# `$DC up -d` inside each test stay scoped to that worker's topology and
# don't collide with other workers.
#
# Usage:
#   ./run-all.sh                 # default concurrency=2
#   ./run-all.sh -j 4            # 4 workers
#   ./run-all.sh -j 4 test_task_*.sh
#   ./run-all.sh --list          # print discovered tests and exit
#
# Output:
#   logs/<test_name>.log         # full stdout+stderr per test
#   logs/summary.md              # aggregated pass/fail/timing markdown
#
# Exit code: 0 if all passed, 1 if any failed.

cd "$(dirname "$0")" || exit 1

JOBS=2
LIST_ONLY=0
PATTERNS=""

while [ $# -gt 0 ]; do
    case "$1" in
        -j)
            JOBS="$2"
            shift 2
            ;;
        -j*)
            JOBS="${1#-j}"
            shift
            ;;
        --list)
            LIST_ONLY=1
            shift
            ;;
        -h|--help)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        *)
            PATTERNS="$PATTERNS $1"
            shift
            ;;
    esac
done

# Discover tests into a newline-separated list.
if [ -z "$PATTERNS" ]; then
    TESTS=$(ls test_*.sh 2>/dev/null | sort)
else
    TESTS=""
    for pat in $PATTERNS; do
        for f in $pat; do
            [ -f "$f" ] && TESTS="$TESTS
$f"
        done
    done
    TESTS=$(printf '%s\n' "$TESTS" | sed '/^$/d' | sort -u)
fi

# Always exclude:
#   - run-all.sh itself (not a test)
#   - test_p2p.sh (runs inside the runner container via compose, not host)
#   - test_sdk.py (needs its own setup, not a .sh)
TESTS=$(printf '%s\n' "$TESTS" | grep -v '^run-all\.sh$' | grep -v '^test_p2p\.sh$' | grep -v '^test_sdk\.py$')

if [ -z "$TESTS" ]; then
    echo "no tests matched" >&2
    exit 2
fi

if [ "$LIST_ONLY" = "1" ]; then
    printf '%s\n' "$TESTS"
    exit 0
fi

NTESTS=$(printf '%s\n' "$TESTS" | wc -l | tr -d ' ')

LOGDIR="logs"
rm -rf "$LOGDIR"
mkdir -p "$LOGDIR"

QUEUE="$LOGDIR/.queue"
RESULTS="$LOGDIR/.results"
LOCKDIR="$LOGDIR/.lock.d"
printf '%s\n' "$TESTS" >"$QUEUE"
: >"$RESULTS"
rmdir "$LOCKDIR" 2>/dev/null || true

# Portable mutex (macOS lacks flock). mkdir is atomic on POSIX fs.
acquire_lock() {
    while ! mkdir "$LOCKDIR" 2>/dev/null; do
        sleep 0.05
    done
}
release_lock() {
    rmdir "$LOCKDIR" 2>/dev/null || true
}

echo "==> $NTESTS tests, $JOBS parallel workers"
RUN_START=$(date +%s)

# Worker: pops tests one at a time from $QUEUE under flock; each test
# runs with a worker-scoped compose project + subnet so parallel workers
# don't fight over container names or IPs.
worker() {
    wid="$1"
    proj="pilot-w${wid}"
    prefix="172.29.$((10+wid))"
    export COMPOSE_PROJECT_NAME="$proj"
    export PILOT_SUBNET_PREFIX="$prefix"

    while true; do
        acquire_lock
        test=$(head -n 1 "$QUEUE")
        if [ -n "$test" ]; then
            # BSD sed (macOS) requires -i '' backup suffix; using .bak + rm is portable.
            sed -i.bak '1d' "$QUEUE"
            rm -f "$QUEUE.bak"
        fi
        release_lock

        if [ -z "$test" ]; then
            break
        fi

        log="$LOGDIR/${test%.sh}.log"
        t0=$(date +%s)
        echo "[worker-$wid] $test start" >&2
        bash "$test" >"$log" 2>&1
        rc=$?
        t1=$(date +%s)
        dur=$((t1 - t0))
        status="PASS"
        [ $rc -ne 0 ] && status="FAIL"
        echo "[worker-$wid] $test $status (${dur}s)" >&2

        acquire_lock
        printf '%s\t%s\t%s\t%s\n' "$test" "$status" "$dur" "$rc" >>"$RESULTS"
        release_lock

        # Best-effort cleanup so the next test this worker picks up starts
        # from a clean slate.
        docker compose -f docker-compose.multi.yml down -v >/dev/null 2>&1 || true
    done
}

# Spawn workers.
PIDS=""
i=0
while [ $i -lt "$JOBS" ]; do
    worker "$i" &
    PIDS="$PIDS $!"
    i=$((i+1))
done

for p in $PIDS; do
    wait "$p"
done

RUN_END=$(date +%s)
TOTAL_DUR=$((RUN_END - RUN_START))

# Aggregate summary.
PASS=0
FAIL=0
TOTAL=0
while IFS="$(printf '\t')" read -r t_test t_status t_dur t_rc; do
    TOTAL=$((TOTAL + 1))
    case "$t_status" in
        PASS) PASS=$((PASS + 1)) ;;
        *)    FAIL=$((FAIL + 1)) ;;
    esac
done <"$RESULTS"

{
    echo "# Integration test run summary"
    echo
    echo "- Run duration: ${TOTAL_DUR}s"
    echo "- Workers: $JOBS"
    echo "- Tests: $TOTAL (pass=$PASS, fail=$FAIL)"
    echo
    echo "| Status | Test | Duration | Exit |"
    echo "|--------|------|----------|------|"
    # Failures first, then by duration desc — makes triage easier.
    awk -F'\t' '{printf "%s\t%s\t%s\t%s\n", ($2=="FAIL"?"0":"1"), $3, $1, $4}' "$RESULTS" \
        | sort -k1,1 -k2,2nr \
        | awk -F'\t' '{print $3 "\t" ($1=="0"?"FAIL":"PASS") "\t" $2 "\t" $4}' \
        | while IFS="$(printf '\t')" read -r r_test r_status r_dur r_rc; do
            echo "| $r_status | \`$r_test\` | ${r_dur}s | $r_rc |"
        done
    echo
    if [ "$FAIL" -gt 0 ]; then
        echo "## Failed logs"
        echo
        while IFS="$(printf '\t')" read -r f_test f_status f_dur f_rc; do
            [ "$f_status" = "FAIL" ] || continue
            echo "### \`$f_test\` (exit=$f_rc, ${f_dur}s)"
            echo
            echo '```'
            tail -n 30 "$LOGDIR/${f_test%.sh}.log" 2>/dev/null || echo "(no log)"
            echo '```'
            echo
        done <"$RESULTS"
    fi
} >"$LOGDIR/summary.md"

rm -f "$QUEUE" "$RESULTS"
rmdir "$LOCKDIR" 2>/dev/null || true

echo
cat "$LOGDIR/summary.md"
echo
echo "==> full logs in $LOGDIR/"
[ "$FAIL" -eq 0 ]
