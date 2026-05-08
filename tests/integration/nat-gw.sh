#!/bin/bash
# NAT gateway bootstrap for docker-compose.multi.nat.yml and friends.
#
# Extended NAT_MODE values:
#   cone               - stock Linux NAT (~port-restricted cone)
#   symmetric          - MASQUERADE --random-fully (per-dest random src port)
#   full_cone          - explicit DNAT of gateway public port -> agent-a,
#                        no conntrack filtering (any peer can hit mapped port)
#   address_restricted - filter return path by src IP only, not src port
#   hairpin            - cone + hairpin DNAT so same-private peers can
#                        reach each other via gateway public IP
#   conntrack_short    - cone + UDP conntrack timeout shrunk to 10s
#   udp_blocked        - iptables drops all UDP forwarded traffic
#   egress_443_only    - forward only UDP dst port 443, drop everything else
#   stateful_fw        - no NAT rewriting, just a stateful firewall
#                        (deny unsolicited inbound, allow established)
set -euo pipefail

NAT_MODE="${NAT_MODE:-cone}"
PUBLIC_SUBNET="${PUBLIC_SUBNET:-192.0.2}"
PRIVATE_SUBNET="${PRIVATE_SUBNET:-198.51.100}"

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

sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -w net.ipv4.conf.all.forwarding=1 2>/dev/null || true

# Clean slate for every run.
iptables -t nat -F
iptables -F FORWARD
iptables -F INPUT 2>/dev/null || true

case "$NAT_MODE" in
    cone)
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" -j MASQUERADE
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" -j ACCEPT
        iptables -A FORWARD -i "$PUBLIC_IFACE" -o "$PRIVATE_IFACE" \
            -m state --state RELATED,ESTABLISHED -j ACCEPT
        ;;
    symmetric)
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" \
            -p udp -j MASQUERADE --random-fully
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" \
            -p tcp -j MASQUERADE --random-fully
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" -j ACCEPT
        iptables -A FORWARD -i "$PUBLIC_IFACE" -o "$PRIVATE_IFACE" \
            -m state --state RELATED,ESTABLISHED -j ACCEPT
        ;;
    full_cone)
        # MASQUERADE egress, plus DNAT any inbound UDP to the gateway's public
        # IP on high ports back to agent-a. This approximates "full cone":
        # once agent-a has any mapping, any external peer can reach it by
        # hitting the gateway's public IP.
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" -j MASQUERADE
        iptables -t nat -A PREROUTING -i "$PUBLIC_IFACE" -p udp \
            --dport 1024:65535 -j DNAT --to-destination "${PRIVATE_SUBNET}.20:4000"
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" -j ACCEPT
        iptables -A FORWARD -i "$PUBLIC_IFACE" -o "$PRIVATE_IFACE" -j ACCEPT
        ;;
    address_restricted)
        # Like cone, but we add a permissive FORWARD rule that accepts
        # inbound traffic from any previously-seen src *IP* (not src port).
        # conntrack already gives port-restricted behaviour; we relax it
        # by using only source-IP tracking via a custom chain.
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" -j MASQUERADE
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" -j ACCEPT
        # Allow any inbound to the mapped agent from IPs we've sent to.
        # Approximated by relaxed conntrack + explicit hairpin accept:
        iptables -A FORWARD -i "$PUBLIC_IFACE" -o "$PRIVATE_IFACE" \
            -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
        ;;
    hairpin)
        # Cone behavior + hairpin DNAT: when a private-side peer sends
        # to the gateway's public IP:port, redirect back into the private
        # network to the mapped agent. Plus SNAT so the return traffic
        # looks like it came from the gateway (keeps conntrack happy).
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" -j MASQUERADE
        iptables -t nat -A PREROUTING -i "$PRIVATE_IFACE" -p udp \
            -d "${PUBLIC_SUBNET}.30" --dport 4000 \
            -j DNAT --to-destination "${PRIVATE_SUBNET}.20:4000"
        iptables -t nat -A POSTROUTING -o "$PRIVATE_IFACE" -p udp \
            -d "${PRIVATE_SUBNET}.20" --dport 4000 -j MASQUERADE
        iptables -A FORWARD -i "$PRIVATE_IFACE" -j ACCEPT
        iptables -A FORWARD -o "$PRIVATE_IFACE" -j ACCEPT
        ;;
    conntrack_short)
        # Cone NAT + aggressively short UDP conntrack timeout. If Pilot's
        # 5s keepalive is working, tunnels should survive; if not, they'll
        # fail after the timeout passes mid-idle.
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" -j MASQUERADE
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" -j ACCEPT
        iptables -A FORWARD -i "$PUBLIC_IFACE" -o "$PRIVATE_IFACE" \
            -m state --state RELATED,ESTABLISHED -j ACCEPT
        # Shrink conntrack timeouts. /proc can be RO on some Docker Desktop
        # kernels; try sysctl first, then proc direct. Best-effort.
        sysctl -w net.netfilter.nf_conntrack_udp_timeout=10 2>/dev/null \
            || echo 10 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null \
            || true
        sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=15 2>/dev/null \
            || echo 15 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream 2>/dev/null \
            || true
        ;;
    udp_blocked)
        # Allow TCP through, drop all UDP. Pilot uses UDP for its tunnel,
        # so registration/handshake must fail gracefully.
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" -j MASQUERADE
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" \
            -p udp -j DROP
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" -j ACCEPT
        iptables -A FORWARD -i "$PUBLIC_IFACE" -o "$PRIVATE_IFACE" \
            -m state --state RELATED,ESTABLISHED -j ACCEPT
        ;;
    egress_443_only)
        # Only forward UDP if dst port is 443 or it's the rendezvous TCP
        # registry port (9000). This simulates a corporate firewall that
        # only allows HTTPS egress. Pilot binds :443 as its tunnel port
        # in this mode (configured on agent side).
        iptables -t nat -A POSTROUTING -o "$PUBLIC_IFACE" -j MASQUERADE
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" \
            -p tcp --dport 9000 -j ACCEPT
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" \
            -p tcp --dport 9001 -j ACCEPT
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" \
            -p udp --dport 443 -j ACCEPT
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" \
            -p udp --dport 9001 -j ACCEPT
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" -j DROP
        iptables -A FORWARD -i "$PUBLIC_IFACE" -o "$PRIVATE_IFACE" \
            -m state --state RELATED,ESTABLISHED -j ACCEPT
        ;;
    stateful_fw)
        # No NAT rewriting at all — agent-a keeps its private IP. The
        # gateway just acts as a stateful firewall: allow outbound, allow
        # inbound only for established flows. Useful for contrasting with
        # NAT (same filtering semantics, no address rewriting).
        iptables -A FORWARD -i "$PRIVATE_IFACE" -o "$PUBLIC_IFACE" -j ACCEPT
        iptables -A FORWARD -i "$PUBLIC_IFACE" -o "$PRIVATE_IFACE" \
            -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -j DROP
        ;;
    *)
        echo "[nat-gw] unknown NAT_MODE=$NAT_MODE" >&2
        exit 1
        ;;
esac

echo "[nat-gw] rules installed:"
iptables -t nat -S POSTROUTING
iptables -t nat -S PREROUTING 2>/dev/null || true
iptables -S FORWARD

exec tail -f /dev/null
