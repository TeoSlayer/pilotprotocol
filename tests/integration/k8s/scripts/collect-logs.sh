#!/bin/bash
# Watch integration-test Jobs and capture their logs + metadata BEFORE
# ttlSecondsAfterFinished fires. Must run in parallel with the Helm
# release so nothing gets GC'd out from under us.
#
# Writes to: tests/integration/logs/runs/<RUN_ID>/
#   <test_name>.log         — full kubectl logs from the pod
#   <test_name>.describe    — kubectl describe job/<name> (events)
#   <test_name>.status      — one of PASS/FAIL/TIMEOUT/UNKNOWN
#   events.log              — cluster-wide events for the namespace
#   summary.md              — per-test pass/fail table
#   junit.xml               — jenkins-style results
#
# Usage:
#   RUN_ID=2026-04-22T21-00 bash tests/integration/k8s/scripts/collect-logs.sh
#
# Env:
#   NAMESPACE      (default: default)
#   RELEASE        (default: integration)
#   KUBECONFIG     (default: ~/.kube/jetson-cluster-config)
#   POLL_INTERVAL  (default: 3 seconds)
#   MAX_WAIT       (default: 3600 seconds — hard stop)
#   RUN_ID         (default: UTC timestamp)

set -uo pipefail

NAMESPACE="${NAMESPACE:-default}"
RELEASE="${RELEASE:-integration}"
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/jetson-cluster-config}"
POLL_INTERVAL="${POLL_INTERVAL:-3}"
MAX_WAIT="${MAX_WAIT:-3600}"
RUN_ID="${RUN_ID:-$(date -u +%Y-%m-%dT%H-%M-%S)}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)/logs/runs"
OUT_DIR="$LOG_ROOT/$RUN_ID"
mkdir -p "$OUT_DIR"

# Symlink latest for convenience.
ln -sfn "$RUN_ID" "$LOG_ROOT/latest"

export KUBECONFIG

k() { kubectl -n "$NAMESPACE" "$@"; }

echo "[collect] namespace=$NAMESPACE release=$RELEASE out=$OUT_DIR"
echo "[collect] poll=${POLL_INTERVAL}s max_wait=${MAX_WAIT}s"

# Tracks which jobs we've already captured so we don't re-read after
# the pod gets GC'd and kubectl logs starts returning errors. macOS ships
# bash 3.2 which lacks `declare -A`, so we use a directory of marker files.
STATE_DIR="$OUT_DIR/.captured"
TAIL_DIR="$OUT_DIR/.tailing"
mkdir -p "$STATE_DIR" "$TAIL_DIR"
captured_count() { find "$STATE_DIR" -type f 2>/dev/null | wc -l | tr -d ' '; }
is_captured() { [ -f "$STATE_DIR/$1" ]; }
mark_captured() { touch "$STATE_DIR/$1"; }

# Spawn `kubectl logs -f` for every pod of a Job the moment we first
# see it. This captures output while the pod is alive, so even when
# ttlSecondsAfterFinished GCs the pod later, the log file is complete.
# Tracks started tails via $TAIL_DIR marker files keyed by pod name.
start_tail_for_pods() {
    local job="$1" test_name="$2"
    # Only consider pods past ContainerCreating. `kubectl logs -f` against
    # a Pending pod returns immediately with "pod is pending" — if we
    # marked on Pending we'd never retry. Filter by phase=Running and also
    # accept Succeeded/Failed (terminal but still log-readable until TTL).
    local pods
    pods="$(k get pods -l "batch.kubernetes.io/job-name=$job" \
        -o jsonpath='{range .items[?(@.status.phase!="Pending")]}{.metadata.name}{" "}{.status.phase}{"\n"}{end}' \
        2>/dev/null)"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local p phase
        p=$(echo "$line" | awk '{print $1}')
        phase=$(echo "$line" | awk '{print $2}')
        [ -z "$p" ] && continue
        [ -f "$TAIL_DIR/$p" ] && continue
        touch "$TAIL_DIR/$p"
        # Retry the attach a few times — apiserver hiccups shouldn't
        # leave us without logs. `kubectl logs -f` exits when the
        # container ends; that's the natural end of the stream.
        (
            for _ in 1 2 3; do
                k logs -f "$p" --all-containers=true >> "$OUT_DIR/${test_name}.log" 2>>"$OUT_DIR/.tail-errors.log"
                # If stream ended because pod is gone, stop.
                if ! k get pod "$p" >/dev/null 2>&1; then break; fi
                sleep 2
            done
        ) &
    done <<< "$pods"
}

start_ts=$(date +%s)

# Selector shared by all Jobs the chart creates.
SEL="app.kubernetes.io/name=pilot-integration"

capture_job() {
    local job="$1"
    local test_name
    test_name="$(k get job "$job" -o jsonpath='{.metadata.labels.pilot-integration/test}' 2>/dev/null)"
    [ -z "$test_name" ] && test_name="$job"

    local status="UNKNOWN"
    local complete failed
    complete="$(k get job "$job" -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null)"
    failed="$(k get job "$job" -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null)"
    if [ "$complete" = "True" ]; then
        status="PASS"
    elif [ "$failed" = "True" ]; then
        status="FAIL"
    fi

    # Append status header — log body may already be present from the
    # background `kubectl logs -f` stream started while the pod was alive.
    {
        echo "=== job=$job test=$test_name status=$status ==="
        echo "=== captured=$(date -u +%FT%TZ) ==="
    } >> "$OUT_DIR/${test_name}.log"

    # If no log body was streamed (pod went from 0→done between ticks),
    # fall back to a direct logs fetch — may still succeed briefly
    # before TTL fires.
    if [ "$(wc -c <"$OUT_DIR/${test_name}.log" 2>/dev/null || echo 0)" -lt 300 ]; then
        local pods
        pods="$(k get pods -l "batch.kubernetes.io/job-name=$job" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)"
        for p in $pods; do
            echo "----- pod: $p (post-mortem) -----" >> "$OUT_DIR/${test_name}.log"
            k logs "$p" --all-containers=true >> "$OUT_DIR/${test_name}.log" 2>&1 \
                || echo "[collect] logs failed for $p" >> "$OUT_DIR/${test_name}.log"
        done
    fi

    k describe job "$job" > "$OUT_DIR/${test_name}.describe" 2>&1 || true
    echo "$status" > "$OUT_DIR/${test_name}.status"
    echo "[collect] captured $test_name → $status"
    mark_captured "$job"
}

# Main loop.
while :; do
    now=$(date +%s)
    if [ $((now - start_ts)) -gt "$MAX_WAIT" ]; then
        echo "[collect] hit MAX_WAIT=${MAX_WAIT}s — stopping"
        break
    fi

    # List all Jobs matching the chart selector. Include fields we need
    # in one call to minimise API round-trips. Stream via a tempfile so
    # this works under bash 3.2 (no mapfile).
    tmp_jobs="$OUT_DIR/.jobs.tmp"
    k get jobs -l "$SEL" \
        -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.conditions[?(@.type=="Complete")].status}{" "}{.status.conditions[?(@.type=="Failed")].status}{"\n"}{end}' \
        > "$tmp_jobs" 2>/dev/null || true

    total=0; done_count=0; pending=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        total=$((total+1))
        job=$(echo "$line" | awk '{print $1}')
        cs=$(echo "$line" | awk '{print $2}')
        fs=$(echo "$line" | awk '{print $3}')
        if [ "$cs" = "True" ] || [ "$fs" = "True" ]; then
            done_count=$((done_count+1))
            if ! is_captured "$job"; then
                capture_job "$job"
            fi
        else
            pending=$((pending+1))
            # Pod may be alive right now — start streaming its logs so
            # we have them even if TTL GCs the pod before we revisit.
            tname="$(k get job "$job" -o jsonpath='{.metadata.labels.pilot-integration/test}' 2>/dev/null)"
            [ -z "$tname" ] && tname="$job"
            start_tail_for_pods "$job" "$tname"
        fi
    done < "$tmp_jobs"

    cap_now=$(captured_count)
    # Status line.
    printf "[collect] t+%ds total=%d done=%d pending=%d captured=%d\n" \
        $((now - start_ts)) "$total" "$done_count" "$pending" "$cap_now"

    # Exit when no Jobs are pending. captured can exceed done_count
    # because TTL removes completed Jobs between ticks, so don't gate
    # on captured==done_count — once pending==0 the run is finished.
    if [ "$total" -gt 0 ] && [ "$pending" -eq 0 ]; then
        echo "[collect] all $total jobs finished, captured=$cap_now"
        break
    fi

    sleep "$POLL_INTERVAL"
done

# Namespace-wide events as a cushion for scheduler-level failures
# (FailedAttachVolume, FailedScheduling) that don't show up in pod logs.
k get events --sort-by=.lastTimestamp > "$OUT_DIR/events.log" 2>&1 || true

# Build summary.md.
{
    echo "# Integration test run $RUN_ID"
    echo
    echo "- namespace: \`$NAMESPACE\`"
    echo "- release:   \`$RELEASE\`"
    echo "- captured:  $(date -u +%FT%TZ)"
    echo
    pass=0; fail=0; unk=0
    echo "| Test | Status |"
    echo "| ---- | ------ |"
    for f in "$OUT_DIR"/*.status; do
        [ -f "$f" ] || continue
        name="$(basename "$f" .status)"
        st="$(cat "$f")"
        case "$st" in
            PASS) pass=$((pass+1)) ;;
            FAIL) fail=$((fail+1)) ;;
            *)    unk=$((unk+1)) ;;
        esac
        echo "| $name | $st |"
    done
    echo
    echo "**Pass: $pass  Fail: $fail  Unknown: $unk**"
} > "$OUT_DIR/summary.md"

# Minimal JUnit XML for CI consumers.
{
    total_tests=0; total_fail=0
    for f in "$OUT_DIR"/*.status; do
        [ -f "$f" ] || continue
        total_tests=$((total_tests+1))
        [ "$(cat "$f")" = "FAIL" ] && total_fail=$((total_fail+1))
    done
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    printf '<testsuite name="pilot-integration" tests="%d" failures="%d">\n' "$total_tests" "$total_fail"
    for f in "$OUT_DIR"/*.status; do
        [ -f "$f" ] || continue
        name="$(basename "$f" .status)"
        st="$(cat "$f")"
        if [ "$st" = "FAIL" ]; then
            printf '  <testcase name="%s"><failure/></testcase>\n' "$name"
        else
            printf '  <testcase name="%s"/>\n' "$name"
        fi
    done
    echo '</testsuite>'
} > "$OUT_DIR/junit.xml"

echo "[collect] wrote $OUT_DIR/summary.md"
cat "$OUT_DIR/summary.md" | tail -20
