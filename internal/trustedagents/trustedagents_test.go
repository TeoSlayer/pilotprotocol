// SPDX-License-Identifier: AGPL-3.0-or-later

package trustedagents

import (
	"testing"
)

// TestEmbeddedListLoads is the build-time guard: the JSON shipped in
// the binary must parse cleanly. CI catches a malformed commit before
// it ships in a release.
func TestEmbeddedListLoads(t *testing.T) {
	mu.RLock()
	defer mu.RUnlock()
	if byNode == nil {
		t.Fatal("byNode nil — package init() failed to load embedded blob")
	}
}

func TestIsTrusted(t *testing.T) {
	if err := load([]byte(`{"agents":[
		{"name":"list-agents","node_id":14161},
		{"name":"search-agent","node_id":42}
	]}`)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = load(embeddedJSON) })

	if name, ok := IsTrusted(14161); !ok || name != "list-agents" {
		t.Fatalf("IsTrusted(14161): got (%q,%v), want (list-agents,true)", name, ok)
	}
	if _, ok := IsTrusted(99); ok {
		t.Fatal("IsTrusted(99): unknown node must not match")
	}
	if _, ok := IsTrusted(0); ok {
		t.Fatal("IsTrusted(0): node 0 must never match (reserved)")
	}
}

func TestZeroNodeIDIgnored(t *testing.T) {
	// Defensive: an entry with node_id=0 in the JSON must be dropped, so
	// a typo or missing field can't accidentally trust an unset peer.
	if err := load([]byte(`{"agents":[
		{"name":"oops","node_id":0},
		{"name":"valid","node_id":7}
	]}`)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = load(embeddedJSON) })

	if _, ok := IsTrusted(0); ok {
		t.Fatal("IsTrusted(0) must never match, even if the JSON declares it")
	}
	if _, ok := IsTrusted(7); !ok {
		t.Fatal("IsTrusted(7): valid entry should still match")
	}
}

func TestMalformedRejected(t *testing.T) {
	if err := load([]byte(`{not json`)); err == nil {
		t.Fatal("garbage JSON must return an error")
	}
}

func TestAllReturnsCopy(t *testing.T) {
	if err := load([]byte(`{"agents":[{"name":"a","node_id":1}]}`)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = load(embeddedJSON) })

	got := All()
	if len(got) != 1 || got[0].NodeID != 1 {
		t.Fatalf("All(): got %+v", got)
	}
	got[0].Name = "tampered"
	if got2 := All(); got2[0].Name != "a" {
		t.Fatalf("All() must return a copy; mutation leaked: %+v", got2)
	}
}
