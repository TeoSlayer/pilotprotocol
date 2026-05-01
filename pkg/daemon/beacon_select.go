// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"hash/fnv"
	"strings"
)

// Multi-beacon support
//
// A daemon may be configured with EITHER:
//
//   -beacon HOST:PORT                                  (single beacon, current default)
//   -beacon HOST1:PORT,HOST2:PORT,HOST3:PORT           (comma-separated list)
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
// indistinguishable from current behavior — parseBeaconList yields a
// 1-element slice, hash%1 = 0, picks the only entry. No relay-path
// change.

// parseBeaconList splits the -beacon flag value on commas and returns
// the list of trimmed, non-empty entries. An empty input returns nil.
func parseBeaconList(s string) []string {
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

// pickBeacon returns one beacon address chosen deterministically from the
// list using FNV-32 of key. Stable across restarts when key is stable
// (e.g. the daemon's Ed25519 public key bytes). Returns "" if the list is
// empty.
//
// With len(list)==1, always returns list[0] regardless of key — guarantees
// the back-compat path for single-beacon configs.
func pickBeacon(list []string, key []byte) string {
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

// firstBeacon returns the first entry of a parsed beacon list, used for
// pre-identity STUN discovery where any beacon will do. Returns "" if
// the list is empty.
func firstBeacon(s string) string {
	list := parseBeaconList(s)
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

// mergeBeaconLists combines the operator-configured bootstrap list with
// addresses discovered from the registry's beacon_list endpoint. The
// bootstrap entries always come first in the result and are deduplicated
// — discovered entries that match a bootstrap entry are dropped, not
// duplicated. The returned slice is stable-ordered: bootstrap entries
// in their input order, then unique discovered entries in their input
// order. This determinism matters because pickBeacon hashes-modulo-N and
// any reordering would cause sticky picks to flip when set membership
// is unchanged.
func mergeBeaconLists(bootstrap, discovered []string) []string {
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
