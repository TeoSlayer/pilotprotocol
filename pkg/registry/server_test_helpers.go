// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

// GetPoloScoreForTest returns a node's polo score for in-process tests.
// Lives on the Server type only — never exposed over the wire, unlike
// the signed self-read get_polo_score handler. Tests living in the same
// process (tests/polo_score_test.go) use this to verify mutations.
// Returns 0 if the node isn't registered.
func (s *Server) GetPoloScoreForTest(nodeID uint32) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n, ok := s.nodes[nodeID]; ok {
		return n.PoloScore
	}
	return 0
}
