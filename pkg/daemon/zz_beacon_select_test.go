// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
)

// TestParseBeaconListSingle covers the back-compat default: a single
// host:port string yields exactly one entry. This is what every existing
// production daemon passes today.
func TestParseBeaconListSingle(t *testing.T) {
	t.Parallel()
	got := parseBeaconList("34.71.57.205:9001")
	if len(got) != 1 || got[0] != "34.71.57.205:9001" {
		t.Fatalf("single-beacon parse = %v, want [34.71.57.205:9001]", got)
	}
}

// TestParseBeaconListEmpty: empty input returns nil (not panic, not crash).
func TestParseBeaconListEmpty(t *testing.T) {
	t.Parallel()
	if got := parseBeaconList(""); got != nil {
		t.Fatalf("empty input parse = %v, want nil", got)
	}
}

// TestParseBeaconListCommaSeparated covers the new path.
func TestParseBeaconListCommaSeparated(t *testing.T) {
	t.Parallel()
	got := parseBeaconList("a:1,b:2,c:3")
	want := []string{"a:1", "b:2", "c:3"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestParseBeaconListIgnoresWhitespaceAndEmptyEntries: tolerate
// whitespace + double-commas without crashing.
func TestParseBeaconListIgnoresWhitespaceAndEmptyEntries(t *testing.T) {
	t.Parallel()
	got := parseBeaconList(" a:1 ,, b:2 ,")
	want := []string{"a:1", "b:2"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (got=%v)", len(got), len(want), got)
	}
}

// TestPickBeaconSingleAlwaysReturnsIt is the back-compat invariant:
// with a single-beacon list, any key returns that beacon. Production
// daemons today have 1 beacon — this test guarantees they keep behaving
// identically.
func TestPickBeaconSingleAlwaysReturnsIt(t *testing.T) {
	t.Parallel()
	list := []string{"34.71.57.205:9001"}
	for i := 0; i < 100; i++ {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		if got := pickBeacon(list, key); got != list[0] {
			t.Fatalf("single-list pick returned %q, want %q (key=%x)", got, list[0], key)
		}
	}
}

// TestPickBeaconEmptyReturnsEmpty: defensive for misconfigured daemons.
func TestPickBeaconEmptyReturnsEmpty(t *testing.T) {
	t.Parallel()
	if got := pickBeacon(nil, []byte("x")); got != "" {
		t.Fatalf("empty list returned %q, want empty", got)
	}
	if got := pickBeacon([]string{}, []byte("x")); got != "" {
		t.Fatalf("zero-len list returned %q, want empty", got)
	}
}

// TestPickBeaconStableForSameKey is the "sticky per node" property:
// the same identity always picks the same beacon, no matter how many
// times the daemon restarts.
func TestPickBeaconStableForSameKey(t *testing.T) {
	t.Parallel()
	list := []string{"a:1", "b:2", "c:3", "d:4"}
	key := []byte("stable-pubkey-bytes")
	first := pickBeacon(list, key)
	for i := 0; i < 1000; i++ {
		if got := pickBeacon(list, key); got != first {
			t.Fatalf("pickBeacon non-deterministic on iter %d: got %q, want %q", i, got, first)
		}
	}
}

// TestPickBeaconUniformDistribution confirms FNV+modulo gives roughly
// even load across the beacon set. With 1k random pubkeys across 4
// beacons, each should get ~250 ± 50.
func TestPickBeaconUniformDistribution(t *testing.T) {
	t.Parallel()
	list := []string{"a:1", "b:2", "c:3", "d:4"}
	const N = 4000
	counts := make(map[string]int, len(list))
	for i := 0; i < N; i++ {
		// Use SHA-256 of the iteration index as a stand-in for a random
		// Ed25519 pubkey — gives well-distributed bytes.
		h := sha256.Sum256(fmt.Appendf(nil, "node-%d", i))
		got := pickBeacon(list, h[:])
		counts[got]++
	}
	expected := N / len(list)
	tolerance := expected / 5 // ±20%
	for _, beacon := range list {
		got := counts[beacon]
		if got < expected-tolerance || got > expected+tolerance {
			t.Fatalf("beacon %s got %d hits, want %d ± %d", beacon, got, expected, tolerance)
		}
	}
}

// TestFirstBeaconCompatible: pre-identity STUN path uses firstBeacon —
// must return the first (or only) entry, never blank for a non-empty
// input.
func TestFirstBeaconCompatible(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"single:1", "single:1"},
		{"a:1,b:2", "a:1"},
		{"  spaced:1  ", "spaced:1"},
	}
	for _, tc := range cases {
		if got := firstBeacon(tc.in); got != tc.want {
			t.Fatalf("firstBeacon(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestPickBeaconChangesWithListSizeButStableWithinSize: if you add a
// beacon to the list, hash%N may move some nodes — that's expected and
// fine. The invariant we DO want: within the same N, the same key always
// picks the same beacon.
func TestPickBeaconStableAcrossSeparateListInstances(t *testing.T) {
	t.Parallel()
	listA := []string{"a:1", "b:2", "c:3"}
	listB := []string{"a:1", "b:2", "c:3"} // same content, separate slice
	for i := 0; i < 100; i++ {
		key := []byte(fmt.Sprintf("k-%d", i))
		if pickBeacon(listA, key) != pickBeacon(listB, key) {
			t.Fatalf("pick differs across separate list instances at i=%d", i)
		}
	}
}

// TestFilterUnreachableDropsPrivateAndLoopback covers the silent-blackhole
// fix: discovered beacon lists from the registry can include addresses
// running on a private VPC (e.g. GCP 10.128.0.x). When the daemon's
// pickBeacon hash lands on one of those, all relay traffic vanishes
// because off-VPC clients cannot reach it. filterUnreachable must drop
// RFC1918, loopback, link-local and unspecified literals. DNS hostnames
// are kept because they may resolve to public IPs.
func TestFilterUnreachableDropsPrivateAndLoopback(t *testing.T) {
	t.Parallel()
	in := []string{
		"34.71.57.205:9001",       // public — kept
		"10.128.0.78:9001",        // private RFC1918 — dropped
		"192.168.1.5:9001",        // private RFC1918 — dropped
		"172.16.0.5:9001",         // private RFC1918 — dropped
		"127.0.0.1:9001",          // loopback — dropped
		"169.254.1.1:9001",        // link-local — dropped
		"0.0.0.0:9001",            // unspecified — dropped
		"beacon.example.com:9001", // DNS hostname — kept
		"8.8.8.8:9001",            // public — kept
	}
	got := filterUnreachable(in)
	want := []string{
		"34.71.57.205:9001",
		"beacon.example.com:9001",
		"8.8.8.8:9001",
	}
	if len(got) != len(want) {
		t.Fatalf("filtered len = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestFilterUnreachableEmptyInputs guards against panics on edge inputs.
func TestFilterUnreachableEmptyInputs(t *testing.T) {
	t.Parallel()
	if got := filterUnreachable(nil); len(got) != 0 {
		t.Fatalf("nil input -> %v, want empty", got)
	}
	if got := filterUnreachable([]string{}); len(got) != 0 {
		t.Fatalf("empty input -> %v, want empty", got)
	}
	if got := filterUnreachable([]string{"malformed-no-port"}); len(got) != 1 {
		t.Fatalf("malformed entry should be kept (host parses cleanly w/o port): got %v", got)
	}
}
