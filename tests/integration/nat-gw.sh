#!/bin/bash
# NAT gateway bootstrap for docker-compose.multi.nat.yml.
#
# This container sits between a private-network agent and the public
# network that holds rendezvous + the peer. We set up MASQUERADE on the
# public-side interface and rely on the private-side agent having its
# default route pointed at us (done via `sysctl` + route commands the
# agent container itself runs at boot — see docker-compose.multi.nat.yml
# `command:` block for agent-a).
#
# NAT_MODE env selects behaviour:
#   cone       (default) — stock Linux stateful NAT (~ port-restricted cone)
#   symmetric           — per-destination source-port randomisation so
#                         the STUN-discovered endpoint for one peer is
#                         NOT the endpoint seen by a second peer; Pilot
#                         MUST fall back to beacon-relay.
set -euo pipefail

NAT_MODE="${NAT_MODE:-cone}"

# Docker doesn't guarantee network attachment order (mapping syntax in
# YAML is unordered). Detect which interface holds which subnet by IP,
# so the MASQUERADE + FORWARD rules point the correct way regardless.
PUBLIC_SUBNET="${PUBLIC_SUBNET:-172.30.10}"
PRIVATE_SUBNET="${PRIVATE_SUBNET:-172.30.11}"

detect_iface() {
    local subnet="$1"
    ip -o -4 addr show \
        | awk -v s="$subnet" '$4 ~ "^"s"\\." {print $2; exit}'
}

PUBLIC_IFACE=$(detect_iface "$PUBLIC_SUBNET")
PRIVATE_IFACE=$(detect_iface "$PRIVATE_SUBNET")
if [ -z "$PUBLIC_IFACE" ] || [ -z "$PRIVATE_IFACE" ]; then
    echo "[nat-gw] could not detect interfaces (pub=$PUBLIC_IFACE priv=$PRIVATE_IFACE)" >&2
    ip -o -4 addr show >&2
    exit 1
fi

echo "[nat-gw] mode=$NAT_MODE public=$PUBLIC_IFACE private=$PRIVATE_IFACE"
ip addr show >&2 || true

# Enable forwarding on both interfaces. The compose `sysctls:` directive
# sets net.ipv4.ip_forward=1 at namespace creation time; re-writing
# /proc/sys from the script fails on some kernels because the file is
# marked RO inside an unprivileged container. Make both best-effort.
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -w net.ipv4.conf.all.forwarding=1 2>/dev/null || true

# Clean slate.
iptables -t nat -F
iptables -F FORWARD

case "$NAT_MODE" in
    cone)
        # Stock Linux NAT: keeps conntrack per (src, dst) pair. Returning
        # packets from the same (dst_ip, dst_port) are allowed. Other
        # external peers can hit the mapped port IF they send to it —
        # i.e. this is approximately a restricted-cone NAT, good enough
        # to exercise Pilot's hole-punch via beacon.
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" -j MASQUERADE
        ;;
    symmetric)
        # Force a fresh source port for every new destination by
        # combining SNAT --random-fully (randomise within the whole
        # ephemeral range) with --persistent disabled. Linux stateful
        # NAT normally reuses a single external port; with --random-fully
        # each new (dst_ip, dst_port) tuple gets an independent random
        # external source port — which is exactly the symmetric-NAT
        # property that breaks STUN-discovered direct connectivity.
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" \
            -p udp -j MASQUERADE --random-fully
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" \
            -p tcp -j MASQUERADE --random-fully
        ;;
    *)
        echo "[nat-gw] unknown NAT_MODE=$NAT_MODE" >&2
        exit 1
        ;;
esac

iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" -j ACCEPT
iptables -A FORWARD -i "$PUBLIC_IFACE" -o "$PRIVATE_IFACE" \
    -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "[nat-gw] rules installed:"
iptables -t nat -S POSTROUTING
iptables -S FORWARD

# Stay alive forever; docker logs tail this.
exec tail -f /dev/null
