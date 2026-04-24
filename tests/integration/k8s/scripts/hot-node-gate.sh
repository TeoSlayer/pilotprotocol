#!/bin/bash
# Hot-node gate: dynamic scheduling bias against saturated nodes.
#
# Polls `kubectl top nodes` on an interval and maintains a
# PreferNoSchedule taint on any node whose CPU% exceeds HIGH. Removes
# the taint when it drops below LOW (hysteresis — avoids flapping).
#
# Only affects *new* pods. Running pods are untouched; completing tests
# continue on whichever node they landed on. New Jobs the Helm release
# is still creating, and re-creations from failed pods, get routed to
# cooler nodes instead.
#
# Taint:   saturation=hot:PreferNoSchedule
#
# Usage:
#   bash tests/integration/k8s/scripts/hot-node-gate.sh
#
# Env:
#   KUBECONFIG     (default: ~/.kube/jetson-cluster-config)
#   POLL_INTERVAL  (default: 5)
#   HIGH           (default: 90  — taint when node CPU% >= this)
#   LOW            (default: 70  — untaint when node CPU% <= this)
#   LABEL_SELECTOR (default: "" — all nodes; e.g. "role=worker")

set -uo pipefail

KUBECONFIG="${KUBECONFIG:-$HOME/.kube/jetson-cluster-config}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
HIGH="${HIGH:-90}"
LOW="${LOW:-70}"
LABEL_SELECTOR="${LABEL_SELECTOR:-}"
# Per-node threshold overrides. Format: NODE_OVERRIDE_<sanitized_node_name>
# = "<high>:<low>" — sanitize replaces "-" with "_". Example for
# worker-node-4 reserving 50% CPU for Prometheus/Grafana:
#   NODE_OVERRIDE_worker_node_4="50:40"
# Any node without an override uses the global HIGH/LOW.
node_high() {
    local n="$1" ov
    ov="$(eval echo \${NODE_OVERRIDE_${n//-/_}:-})"
    [ -n "$ov" ] && echo "${ov%%:*}" || echo "$HIGH"
}
node_low() {
    local n="$1" ov
    ov="$(eval echo \${NODE_OVERRIDE_${n//-/_}:-})"
    [ -n "$ov" ] && echo "${ov##*:}" || echo "$LOW"
}
TAINT_KEY="saturation"
TAINT_VAL="hot"
TAINT_EFFECT="PreferNoSchedule"
# Per-node effect override. PreferNoSchedule is soft (scheduler prefers
# elsewhere but will place if needed). NoSchedule is hard (blocks new
# pods entirely until untainted). Override with NODE_EFFECT_<sanitized>
# env, e.g. NODE_EFFECT_worker_node_4=NoSchedule to reserve capacity
# for system workloads on that node.
node_effect() {
    local n="$1" ov
    ov="$(eval echo \${NODE_EFFECT_${n//-/_}:-})"
    [ -n "$ov" ] && echo "$ov" || echo "$TAINT_EFFECT"
}

export KUBECONFIG

ts() { date -u +%FT%TZ; }
log() { echo "[$(ts)] $*"; }

has_taint() {
    local node="$1" effect
    effect="$(node_effect "$node")"
    kubectl get node "$node" \
        -o jsonpath="{.spec.taints[?(@.key=='$TAINT_KEY')].effect}" 2>/dev/null \
        | grep -q "$effect"
}

add_taint() {
    local node="$1" effect
    effect="$(node_effect "$node")"
    kubectl taint node "$node" \
        "${TAINT_KEY}=${TAINT_VAL}:${effect}" \
        --overwrite >/dev/null 2>&1
}

remove_taint() {
    local node="$1"
    kubectl taint node "$node" "${TAINT_KEY}-" >/dev/null 2>&1 || true
}

cleanup() {
    log "shutting down — removing all saturation taints"
    local nodes
    nodes="$(kubectl get nodes ${LABEL_SELECTOR:+-l "$LABEL_SELECTOR"} \
        -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)"
    for n in $nodes; do remove_taint "$n"; done
}
trap cleanup EXIT INT TERM

log "hot-node-gate starting: HIGH=${HIGH}% LOW=${LOW}% poll=${POLL_INTERVAL}s"
log "taint: ${TAINT_KEY}=${TAINT_VAL}:${TAINT_EFFECT}"

while :; do
    # `kubectl top nodes` output: NAME CPU(cores) CPU% MEMORY MEM%
    # Example:  worker-node-4  11726m  97%  20020Mi  32%
    top_out="$(kubectl top nodes ${LABEL_SELECTOR:+-l "$LABEL_SELECTOR"} \
        --no-headers 2>/dev/null)"
    if [ -z "$top_out" ]; then
        log "WARN: kubectl top returned nothing — metrics-server down?"
        sleep "$POLL_INTERVAL"
        continue
    fi

    hot_count=0
    cold_count=0
    summary=""
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        name=$(echo "$line" | awk '{print $1}')
        pct=$(echo "$line" | awk '{print $3}' | tr -d '%')
        # Skip header stragglers / malformed rows.
        case "$pct" in ''|*[!0-9]*) continue ;; esac

        tainted="no"
        has_taint "$name" && tainted="yes"

        nh="$(node_high "$name")"
        nl="$(node_low "$name")"

        if [ "$pct" -ge "$nh" ] && [ "$tainted" = "no" ]; then
            add_taint "$name"
            log "TAINT   $name cpu=${pct}% (>=${nh}%)"
            hot_count=$((hot_count+1))
        elif [ "$pct" -le "$nl" ] && [ "$tainted" = "yes" ]; then
            remove_taint "$name"
            log "UNTAINT $name cpu=${pct}% (<=${nl}%)"
            cold_count=$((cold_count+1))
        fi

        summary+=" ${name}=${pct}%$([ "$tainted" = "yes" ] && echo '*')"
    done <<< "$top_out"

    log "tick:${summary}  (* = tainted; hot+${hot_count} cold+${cold_count})"
    sleep "$POLL_INTERVAL"
done
