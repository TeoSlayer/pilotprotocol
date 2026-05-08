// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"sync"
	"testing"
)

// Test-only TrustChecker. Holds an in-memory allowlist; tests populate it
// via setTestTrustedAgents before exercising handshake auto-accept paths.
//
// Replaces an earlier helper that imported plugins/trustedagents to read
// its package-global SetForTest state. That import was an L7→L11 upward
// edge invisible to the layer-check until --tests was added (P5). With
// this helper, pkg/daemon's test suite does not reference any L11
// package directly.

type testAgent struct {
	Hostname string
	NodeID   uint32
}

var (
	testTrustedAgentsMu sync.RWMutex
	testTrustedAgents   = map[uint32]string{} // nodeID → hostname
)

// setTestTrustedAgents installs the given allowlist for the duration of
// the test, swapping back the previous list on cleanup. Safe for parallel
// subtests because writes happen behind a mutex; concurrent tests should
// not assume global isolation, mirroring the prior SetForTest semantics.
func setTestTrustedAgents(t *testing.T, agents []testAgent) {
	t.Helper()
	testTrustedAgentsMu.Lock()
	prev := testTrustedAgents
	next := make(map[uint32]string, len(agents))
	for _, a := range agents {
		next[a.NodeID] = a.Hostname
	}
	testTrustedAgents = next
	testTrustedAgentsMu.Unlock()
	t.Cleanup(func() {
		testTrustedAgentsMu.Lock()
		testTrustedAgents = prev
		testTrustedAgentsMu.Unlock()
	})
}

func testTrustedAgentsLookup(nodeID uint32) (string, bool) {
	testTrustedAgentsMu.RLock()
	defer testTrustedAgentsMu.RUnlock()
	name, ok := testTrustedAgents[nodeID]
	return name, ok
}
