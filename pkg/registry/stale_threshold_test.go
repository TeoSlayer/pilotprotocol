// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"testing"
	"time"
)

// TestStaleNodeThresholdDefault confirms a freshly constructed Server uses
// the package-default threshold (matches historical hardcoded value).
func TestStaleNodeThresholdDefault(t *testing.T) {
	s := newTestServer(t, "")
	if got := s.StaleNodeThreshold(); got != defaultStaleNodeThreshold {
		t.Fatalf("default threshold = %v, want %v", got, defaultStaleNodeThreshold)
	}
}

// TestStaleNodeThresholdConfigurable confirms SetStaleNodeThreshold honors
// non-zero positive values.
func TestStaleNodeThresholdConfigurable(t *testing.T) {
	s := newTestServer(t, "")
	s.SetStaleNodeThreshold(5 * time.Minute)
	if got := s.StaleNodeThreshold(); got != 5*time.Minute {
		t.Fatalf("threshold after SetStaleNodeThreshold(5m) = %v, want 5m", got)
	}
}

// TestStaleNodeThresholdRejectsZeroAndNegative ensures bad input is ignored
// (preserve operator-set or default value rather than disable the threshold).
func TestStaleNodeThresholdRejectsZeroAndNegative(t *testing.T) {
	s := newTestServer(t, "")
	s.SetStaleNodeThreshold(7 * time.Minute)
	s.SetStaleNodeThreshold(0)
	if got := s.StaleNodeThreshold(); got != 7*time.Minute {
		t.Fatalf("zero arg should be ignored; got %v, want 7m", got)
	}
	s.SetStaleNodeThreshold(-1 * time.Hour)
	if got := s.StaleNodeThreshold(); got != 7*time.Minute {
		t.Fatalf("negative arg should be ignored; got %v, want 7m", got)
	}
}

// TestSampleStatsHonorsConfigurableThreshold verifies the threshold actually
// drives the online-count read paths. We insert a node whose LastSeen is 10m
// in the past:
//   - default 30m threshold → counts as online
//   - configured  5m threshold → counts as offline
func TestSampleStatsHonorsConfigurableThreshold(t *testing.T) {
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	tenMinAgo := now.Add(-10 * time.Minute)

	mkServer := func() *Server {
		s := newTestServer(t, "")
		s.now = func() time.Time { return now }
		s.mu.Lock()
		n := &NodeInfo{ID: 1001, Owner: "test", PublicKey: []byte("pk")}
		n.setLastSeen(tenMinAgo)
		s.nodes[1001] = n
		s.mu.Unlock()
		return s
	}

	// Default threshold (30m): node from 10m ago is online.
	sDefault := mkServer()
	defaultResult := sDefault.sampleStats()
	if defaultResult.global.OnlineNodes != 1 {
		t.Fatalf("with default 30m threshold, 10m-old node should be online; got %d", defaultResult.global.OnlineNodes)
	}

	// Tighter 5m threshold: same node should now be offline.
	sTight := mkServer()
	sTight.SetStaleNodeThreshold(5 * time.Minute)
	tightResult := sTight.sampleStats()
	if tightResult.global.OnlineNodes != 0 {
		t.Fatalf("with 5m threshold, 10m-old node should be offline; got %d", tightResult.global.OnlineNodes)
	}
}
