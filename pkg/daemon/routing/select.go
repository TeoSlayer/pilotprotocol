// SPDX-License-Identifier: AGPL-3.0-or-later

package routing

import (
	"hash/fnv"
	"net"
	"strings"
	"time"
)

// IsUnreachableBeaconHost reports whether host is an RFC1918 / loopback /
// link-local / unspecified address — an address that a public-internet
// daemon cannot reach. The registry's beacon_list endpoint can return
// internal addresses for beacons running on the same VPC (e.g. GCP
// 10.128.0.0/16); those are useless to off-VPC daemons and, if picked,
// silently black-hole all relay traffic. Only IP literals are checked
// — DNS hostnames are kept (they may resolve to public addresses).
func IsUnreachableBeaconHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// FilterUnreachable removes addresses whose host part is an RFC1918 /
// loopback / link-local literal. Used on the DISCOVERED list before
// merging with bootstrap — the operator's bootstrap list is preserved
// verbatim (intra-VPC deployments can still pin a private beacon there).
func FilterUnreachable(addrs []string) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			// Fall back to the whole string if there's no port.
			host = a
		}
		if IsUnreachableBeaconHost(host) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// Multi-beacon support
//
// A daemon may be configured with EITHER:
//
//	-beacon HOST:PORT                                  (single beacon, current default)
//	-beacon HOST1:PORT,HOST2:PORT,HOST3:PORT           (comma-separated list)
//
// When the list has more than one entry, the daemon picks ONE beacon
// deterministically using FNV-32 of its identity public key, modulo the
// list length. This is "sticky per node" — the same daemon always picks
// the same beacon across restarts (because pubkey is stable), and across
// 100k+ nodes, FNV's uniform distribution spreads load evenly across N
// beacons (~33k nodes per beacon at N=3).
//
// All other code paths (relay/punch/STUN) continue to use a SINGLE
// beaconAddr — the picked one. The cross-beacon Tier 2 forwarding mesh
// in pkg/beacon/server.go handles routing relay packets to whichever
// beacon owns the destination node, transparent to the daemon.
//
// BACKWARDS COMPATIBILITY: a single-host config (-beacon HOST:PORT) is
// indistinguishable from current behavior — ParseBeaconList yields a
// 1-element slice, hash%1 = 0, picks the only entry. No relay-path
// change.

// ParseBeaconList splits the -beacon flag value on commas and returns
// the list of trimmed, non-empty entries. An empty input returns nil.
func ParseBeaconList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// PickBeacon returns one beacon address chosen deterministically from the
// list using FNV-32 of key. Stable across restarts when key is stable
// (e.g. the daemon's Ed25519 public key bytes). Returns "" if the list is
// empty.
//
// With len(list)==1, always returns list[0] regardless of key — guarantees
// the back-compat path for single-beacon configs.
func PickBeacon(list []string, key []byte) string {
	if len(list) == 0 {
		return ""
	}
	if len(list) == 1 {
		return list[0]
	}
	h := fnv.New32a()
	h.Write(key)
	idx := int(h.Sum32() % uint32(len(list)))
	return list[idx]
}

// PickBeaconWithRTT selects a beacon using measured RTT data as a
// tiebreaker. The hash-based pick (PickBeacon) is preferred to maintain
// load distribution across the fleet, but is overridden when it is more
// than 2× slower than the fastest measured beacon — a strong signal that
// geography or routing has placed this node far from its hash pick.
//
// rttMap maps beacon address → measured probe RTT. Beacons absent from
// rttMap (probe timed out or failed) are treated as unreachable and
// excluded from RTT comparison. When rttMap is empty, falls back to the
// pure hash pick. When the hash pick itself failed to probe but others
// succeeded, the fastest responding beacon is used.
//
// This function is gated behind the BeaconRTTProbe feature flag in
// pkg/daemon — call PickBeacon directly when the flag is off.
func PickBeaconWithRTT(list []string, key []byte, rttMap map[string]time.Duration) string {
	if len(list) == 0 {
		return ""
	}
	if len(rttMap) == 0 {
		return PickBeacon(list, key)
	}
	hashPick := PickBeacon(list, key)
	hashRTT, hashReachable := rttMap[hashPick]

	bestAddr := ""
	var bestRTT time.Duration
	for _, addr := range list {
		rtt, ok := rttMap[addr]
		if !ok {
			continue
		}
		if bestAddr == "" || rtt < bestRTT {
			bestRTT = rtt
			bestAddr = addr
		}
	}

	if bestAddr == "" {
		// No probe responded — fall back to hash pick.
		return hashPick
	}
	if !hashReachable {
		// Hash pick didn't respond but at least one other did.
		return bestAddr
	}
	// Override only when hash pick is >2× slower than the fastest beacon.
	if hashRTT > 2*bestRTT {
		return bestAddr
	}
	return hashPick
}

// FirstBeacon returns the first entry of a parsed beacon list, used for
// pre-identity STUN discovery where any beacon will do. Returns "" if
// the list is empty.
func FirstBeacon(s string) string {
	list := ParseBeaconList(s)
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

// MergeBeaconLists combines the operator-configured bootstrap list with
// addresses discovered from the registry's beacon_list endpoint. The
// bootstrap entries always come first in the result and are deduplicated
// — discovered entries that match a bootstrap entry are dropped, not
// duplicated. The returned slice is stable-ordered: bootstrap entries
// in their input order, then unique discovered entries in their input
// order. This determinism matters because PickBeacon hashes-modulo-N and
// any reordering would cause sticky picks to flip when set membership
// is unchanged.
func MergeBeaconLists(bootstrap, discovered []string) []string {
	if len(bootstrap) == 0 && len(discovered) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(bootstrap)+len(discovered))
	out := make([]string, 0, len(bootstrap)+len(discovered))
	for _, a := range bootstrap {
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	for _, a := range discovered {
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}
