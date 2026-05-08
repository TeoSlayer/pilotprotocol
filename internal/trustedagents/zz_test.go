// SPDX-License-Identifier: AGPL-3.0-or-later

package trustedagents

import (
	"testing"
)

// TestEmbeddedListLoads is the build-time guard: the JSON shipped in
// the binary must parse cleanly. CI catches a malformed commit before
// it ships in a release.
func TestEmbeddedListLoads(t *testing.T) {
	t.Parallel()
	mu.RLock()
	defer mu.RUnlock()
	if byNode == nil {
		t.Fatal("byNode nil — package init() failed to load embedded blob")
	}
}

func TestIsTrusted(t *testing.T) {
	t.Parallel()
	restore := SetForTest([]Agent{
		{Hostname: "list-agents", NodeID: 14161},
		{Hostname: "search-agent", NodeID: 42},
	})
	defer restore()

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
	t.Parallel()
	// Defensive: an entry with node_id=0 in the JSON must be dropped, so
	// a typo or missing field can't accidentally trust an unset peer.
	restore := SetForTest([]Agent{
		{Hostname: "oops", NodeID: 0},
		{Hostname: "valid", NodeID: 7},
	})
	defer restore()

	if _, ok := IsTrusted(0); ok {
		t.Fatal("IsTrusted(0) must never match, even if the JSON declares it")
	}
	if _, ok := IsTrusted(7); !ok {
		t.Fatal("IsTrusted(7): valid entry should still match")
	}
}

func TestExtraJSONFieldsIgnored(t *testing.T) {
	// Not parallel: calls Load() which mutates shared global state.
	// The source file ships fields we don't care about (tier, description).
	// Those must unmarshal cleanly without errors and without polluting
	// the Agent struct.
	if err := Load([]byte(`{"agents":[
		{"hostname":"x","address":"0:0:1","node_id":1,"tier":"premium","description":"ignored"}
	]}`)); err != nil {
		t.Fatalf("extra JSON fields must not break unmarshal: %v", err)
	}
	_ = Load(embeddedJSON)
}

func TestMalformedRejected(t *testing.T) {
	t.Parallel()
	if err := Load([]byte(`{not json`)); err == nil {
		t.Fatal("garbage JSON must return an error")
	}
}

func TestAllReturnsCopy(t *testing.T) {
	t.Parallel()
	restore := SetForTest([]Agent{{Hostname: "a", NodeID: 1}})
	defer restore()

	got := All()
	if len(got) != 1 || got[0].NodeID != 1 {
		t.Fatalf("All(): got %+v", got)
	}
	got[0].Hostname = "tampered"
	if got2 := All(); got2[0].Hostname != "a" {
		t.Fatalf("All() must return a copy; mutation leaked: %+v", got2)
	}
}
