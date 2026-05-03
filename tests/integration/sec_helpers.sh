#!/bin/bash
# sec_helpers.sh — sourceable helpers for Chunk D (security / adversarial)
# integration tests. All helpers run inside the compose network and rely on
# `raw_udp.py` being available on PATH inside a container with python3.
#
# Required caller exports:
#   DC   — docker compose invocation (e.g. "docker compose -f docker-compose.multi.yml")
#
# Conventions:
#   - "service" args are compose service names (agent-a, agent-b, rendezvous).
#   - Returned hex strings are lowercase, no 0x prefix, no whitespace.
#   - Packet crafting follows the tunnel wire format in pkg/daemon/tunnel.go:
#         [MAGIC(4)][nodeID(4)][...]
#     PILT = 50 49 4C 54 (plaintext)
#     PILS = 50 49 4C 53 (encrypted)
#     PILK = 50 49 4C 4B (unauth key exchange)
#     PILA = 50 49 4C 41 (authenticated key exchange)
#     PILP = 50 49 4C 50 (NAT punch)
#
# Beacon magic bytes (single byte, < 0x10):
#     0x01 discover, 0x03 punch-request, 0x05 relay
#
# This file is intentionally dependency-free (pure bash + python3). No
# scapy, no Go test harnesses.

: "${DC:?sec_helpers: caller must export DC (docker compose -f ...)}"

# --- hex utilities ----------------------------------------------------------

# hex_u32 <uint32> -> big-endian 4-byte hex.
hex_u32() {
    printf '%08x' "$1"
}

# hex_u16 <uint16> -> big-endian 2-byte hex.
hex_u16() {
    printf '%04x' "$1"
}

# hex_rand <bytes> -> hex string of that many random bytes (from /dev/urandom).
hex_rand() {
    local n="$1"
    head -c "$n" /dev/urandom | xxd -p -c 1000
}

# --- tunnel frame crafting --------------------------------------------------

# craft_plaintext_frame <senderNodeID> <raw_payload_hex>
# Builds [PILT][nodeID][payload]. NOTE: daemon rejects this on encrypted
# tunnels (no decrypt path). Useful for malformed-frame testing.
craft_plaintext_frame() {
    local nid="$1" payload="$2"
    printf '50494C54%s%s' "$(hex_u32 "$nid")" "$payload"
}

# craft_encrypted_frame <senderNodeID> <nonce_hex_12> <ciphertext_hex>
# Builds [PILS][nodeID][nonce(12)][ciphertext+tag]. Does NOT derive any key —
# intended for replay and spoofed-node-id tests where we feed captured /
# adversarially-chosen bytes.
craft_encrypted_frame() {
    local nid="$1" nonce="$2" ct="$3"
    printf '50494C53%s%s%s' "$(hex_u32 "$nid")" "$nonce" "$ct"
}

# craft_keyex_frame <senderNodeID> <x25519_pub_hex_32>
# Builds [PILK][nodeID][pubkey(32)] — unauth key exchange.
craft_keyex_frame() {
    local nid="$1" pub="$2"
    printf '50494C4B%s%s' "$(hex_u32 "$nid")" "$pub"
}

# craft_beacon_relay <senderNodeID> <destNodeID> <payload_hex>
# Builds [0x05][sender(4)][dest(4)][payload]. Sent TO the beacon.
craft_beacon_relay() {
    local snid="$1" dnid="$2" payload="$3"
    printf '05%s%s%s' "$(hex_u32 "$snid")" "$(hex_u32 "$dnid")" "$payload"
}

# craft_beacon_discover <nodeID>
craft_beacon_discover() {
    local nid="$1"
    printf '01%s' "$(hex_u32 "$nid")"
}

# --- send helpers -----------------------------------------------------------

# send_raw_udp <from_service> <host> <port> <hex_payload>
# Runs raw_udp.py inside the named container. host may be a service name
# (compose DNS resolves it) or an IP.
send_raw_udp() {
    local svc="$1" host="$2" port="$3" payload="$4"
    $DC exec -T "$svc" python3 /tests/raw_udp.py send "$host" "$port" "$payload"
}

# flood_raw_udp <from_service> <host> <port> <hex_payload> <count> [pps]
flood_raw_udp() {
    local svc="$1" host="$2" port="$3" payload="$4" count="$5" pps="${6:-0}"
    if [ "$pps" -gt 0 ]; then
        $DC exec -T "$svc" python3 /tests/raw_udp.py flood "$host" "$port" "$payload" "$count" --rate "$pps"
    else
        $DC exec -T "$svc" python3 /tests/raw_udp.py flood "$host" "$port" "$payload" "$count"
    fi
}

# --- capture helpers --------------------------------------------------------

# tcpdump_available <service>
# Returns 0 if tcpdump is callable inside the container, 1 otherwise.
# Dockerfile.multi does NOT install tcpdump by default — tests that need
# capture should `apt-get install -y tcpdump` at test start (cost ~3s).
tcpdump_available() {
    local svc="$1"
    $DC exec -T "$svc" sh -c 'command -v tcpdump >/dev/null 2>&1'
}

# ensure_tcpdump <service>
# Installs tcpdump into a running container if not present. Idempotent.
# The image is Debian-based so apt-get works. Requires the container to
# have network (which compose gives it). Tests MUST call this before
# start_capture.
ensure_tcpdump() {
    local svc="$1"
    if tcpdump_available "$svc"; then
        return 0
    fi
    $DC exec -T "$svc" sh -c '
        apt-get update -qq >/dev/null 2>&1 &&
        apt-get install -y -qq --no-install-recommends tcpdump >/dev/null 2>&1
    '
}

# start_capture <service> <iface> <filter> <outfile_in_container>
# Runs tcpdump in the background inside the container; returns the PID.
# Use stop_capture <service> <pid> to terminate.
start_capture() {
    local svc="$1" iface="$2" filter="$3" out="$4"
    # -s 0 = full snap, -U = unbuffered, -w = pcap out, -i = iface.
    $DC exec -d "$svc" sh -c "tcpdump -U -s 0 -n -i '$iface' -w '$out' $filter >/dev/null 2>&1" || return 1
    # Return a well-known sentinel — the caller can check file growth instead
    # of PID because `exec -d` does not return the child PID portably.
    return 0
}

# stop_capture <service>
# Kills any tcpdump inside the container. Simple pkill; captures are one-off.
stop_capture() {
    local svc="$1"
    $DC exec -T "$svc" pkill -TERM tcpdump 2>/dev/null || true
}

# extract_first_pils <service> <pcap_path>
# Reads the given pcap and prints the first PILS (encrypted tunnel) payload
# as hex. Requires tcpdump+od in the container. Empty string if none found.
#
# This uses tcpdump's -xx mode to dump the link-layer+UDP bytes, greps for
# the PILS magic (50494C53), and prints the matched frame's hex payload.
extract_first_pils() {
    local svc="$1" pcap="$2"
    $DC exec -T "$svc" sh -c "
        tcpdump -r '$pcap' -xx -nn 2>/dev/null |
        awk '
            /^[0-9]/ { if (frame != \"\") print frame; frame = \"\"; next }
            /0x[0-9a-f]+:/ {
                line = \$0
                sub(/^[^:]*:[ \t]*/, \"\", line)
                gsub(/ /, \"\", line)
                frame = frame line
            }
            END { if (frame != \"\") print frame }
        ' |
        grep -o '50494c53[0-9a-f]*' |
        head -n1
    "
}

# --- node id discovery ------------------------------------------------------

# node_id_of <service>
# Returns the numeric node_id of the daemon running in the named service.
node_id_of() {
    local svc="$1"
    $DC exec -T "$svc" pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty'
}

# ip_of <service>
# Returns the compose network IPv4 address of the named service (uses getent).
ip_of() {
    local svc="$1"
    $DC exec -T rendezvous getent hosts "$svc" 2>/dev/null | awk '{print $1}' | head -n1
}

# --- bounded wait -----------------------------------------------------------

# wait_for <seconds> <condition_command...>
# Blocks until the condition returns 0 or the timeout expires.
wait_for() {
    local secs="$1"; shift
    local i
    for i in $(seq 1 "$secs"); do
        if "$@"; then return 0; fi
        sleep 1
    done
    return 1
}
