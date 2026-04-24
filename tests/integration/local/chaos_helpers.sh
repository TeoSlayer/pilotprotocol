#!/bin/bash
# chaos_helpers.sh — sourceable helpers that apply tc netem + iptables
# chaos inside the compose agent containers.
#
# Usage:
#   source chaos_helpers.sh
#   DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.chaos.yml"
#   apply_loss agent-b 30
#   ...
#   strip_chaos agent-b
#
# All helpers take the service name (agent-a / agent-b / rendezvous) as
# the first argument and shell out to `$DC exec -T`. The overlay compose
# file `docker-compose.multi.chaos.yml` grants NET_ADMIN; without it
# every one of these will fail with "Operation not permitted".
#
# Helpers are idempotent in the sense that strip_chaos is safe to call
# even when no qdisc is present, and iptables rules are keyed on
# --comment pilot-chaos so repeated partition/heal don't leak state.
#
# DC env var MUST be set by the caller — we do not hardcode the compose
# file list so tests can compose additional overlays (webhooks, etc.).

: "${DC:?chaos_helpers: caller must export DC (docker compose -f ...)}"

# Apply symmetric packet loss on a service's eth0 (root qdisc).
# apply_loss <service> <percent>
apply_loss() {
    local svc="$1" pct="$2"
    # Clean any previous root qdisc first so repeated calls work.
    $DC exec -T "$svc" tc qdisc del dev eth0 root 2>/dev/null || true
    $DC exec -T "$svc" tc qdisc add dev eth0 root netem loss "${pct}%"
}

# Reorder pct% of packets with a 50% correlation (default netem shape).
# apply_reorder <service> <percent>
apply_reorder() {
    local svc="$1" pct="$2"
    $DC exec -T "$svc" tc qdisc del dev eth0 root 2>/dev/null || true
    # netem reorder requires a nonzero delay to actually reorder packets
    # (else there is no queue to shuffle). 10ms is fine for local tests.
    $DC exec -T "$svc" tc qdisc add dev eth0 root netem delay 10ms reorder "${pct}%" 50%
}

# Add fixed delay (ms) with +/-50ms jitter.
# apply_delay <service> <ms>
apply_delay() {
    local svc="$1" ms="$2"
    $DC exec -T "$svc" tc qdisc del dev eth0 root 2>/dev/null || true
    $DC exec -T "$svc" tc qdisc add dev eth0 root netem delay "${ms}ms" 50ms distribution normal
}

# Strip any netem qdisc AND iptables chaos rules from a service.
# strip_chaos <service>
strip_chaos() {
    local svc="$1"
    $DC exec -T "$svc" tc qdisc del dev eth0 root 2>/dev/null || true
    # Clear any partition rules we may have inserted.
    # We tag all of our rules with --comment pilot-chaos for easy removal.
    $DC exec -T "$svc" bash -c '
        while iptables -C INPUT -m comment --comment pilot-chaos -j DROP 2>/dev/null; do
            iptables -D INPUT -m comment --comment pilot-chaos -j DROP || break
        done
        while iptables -C OUTPUT -m comment --comment pilot-chaos -j DROP 2>/dev/null; do
            iptables -D OUTPUT -m comment --comment pilot-chaos -j DROP || break
        done
        # Src/dst-specific partition drops (dropped by remove below too).
        iptables -S INPUT 2>/dev/null | grep -- "--comment pilot-chaos" | while read -r line; do
            rule=$(echo "$line" | sed "s/^-A /-D /")
            iptables $rule 2>/dev/null || true
        done
        iptables -S OUTPUT 2>/dev/null | grep -- "--comment pilot-chaos" | while read -r line; do
            rule=$(echo "$line" | sed "s/^-A /-D /")
            iptables $rule 2>/dev/null || true
        done
        true
    ' 2>/dev/null || true
}

# Partition src from dst (one-way drop, run twice for bidirectional).
# apply_partition <src_service> <dst_ip>
#
# Note: we must pass an IP, not a hostname, because iptables inside the
# container cannot resolve compose service names reliably. Callers
# typically resolve with: $DC exec -T rendezvous getent hosts agent-b
apply_partition() {
    local src="$1" dst_ip="$2"
    # Drop both directions so tunnel traffic cannot sneak out on return
    # path. Tag with --comment pilot-chaos for strip_chaos cleanup.
    $DC exec -T "$src" iptables -I OUTPUT -d "$dst_ip" -m comment --comment pilot-chaos -j DROP
    $DC exec -T "$src" iptables -I INPUT -s "$dst_ip" -m comment --comment pilot-chaos -j DROP
}

# Heal a partition previously applied with apply_partition.
# heal_partition <src_service> <dst_ip>
heal_partition() {
    local src="$1" dst_ip="$2"
    $DC exec -T "$src" iptables -D OUTPUT -d "$dst_ip" -m comment --comment pilot-chaos -j DROP 2>/dev/null || true
    $DC exec -T "$src" iptables -D INPUT -s "$dst_ip" -m comment --comment pilot-chaos -j DROP 2>/dev/null || true
}

# Resolve a compose service hostname to its network IP from INSIDE the
# compose network. Uses rendezvous as the resolver container (always up
# in this stack). Echoes the v4 IP or empty.
# resolve_service_ip <service>
resolve_service_ip() {
    local svc="$1"
    $DC exec -T rendezvous getent hosts "$svc" 2>/dev/null | awk '{print $1}' | head -n1
}
