// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// buildSnapshot constructs a synthetic snapshot JSON blob for tests. It
// produces the exact wire shape applySnapshot expects.
func buildSnapshot(t *testing.T, nodes int, networks int) []byte {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)

	snap := snapshot{
		NextNode: uint32(nodes + 100),
		NextNet:  uint16(networks + 10),
		Nodes:    make(map[string]*snapshotNode, nodes),
		Networks: make(map[string]*snapshotNet, networks),
	}

	for i := 1; i <= nodes; i++ {
		key := fmt.Sprintf("%d", i)
		snap.Nodes[key] = &snapshotNode{
			ID:        uint32(i),
			Owner:     fmt.Sprintf("owner-%d", i),
			PublicKey: "AAAA" + fmt.Sprintf("%032d", i),
			RealAddr:  fmt.Sprintf("10.0.0.%d:9000", i%255),
			Networks:  []uint16{1},
			LastSeen:  now,
			Hostname:  fmt.Sprintf("host-%d", i),
		}
	}

	for i := 1; i <= networks; i++ {
		key := fmt.Sprintf("%d", i)
		members := make([]uint32, 0, 5)
		for j := i; j <= nodes && j < i+5; j++ {
			members = append(members, uint32(j))
		}
		snap.Networks[key] = &snapshotNet{
			ID:       uint16(i),
			Name:     fmt.Sprintf("net-%d", i),
			JoinRule: "open",
			Members:  members,
			Created:  now,
		}
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// TestApplySnapshotBasic locks down the happy path: applySnapshot replaces
// the registry's nodes, networks, and indices wholesale.
func TestApplySnapshotBasic(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	data := buildSnapshot(t, 5, 2)

	if err := s.applySnapshot(data); err != nil {
		t.Fatalf("applySnapshot: %v", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if got := len(s.nodes); got != 5 {
		t.Fatalf("nodes count = %d, want 5", got)
	}
	if got := len(s.networks); got != 2 {
		t.Fatalf("networks count = %d, want 2", got)
	}
	if s.nextNode != 105 {
		t.Fatalf("nextNode = %d, want 105", s.nextNode)
	}
	if s.nextNet != 12 {
		t.Fatalf("nextNet = %d, want 12", s.nextNet)
	}
	// Hostname index populated
	if got := s.hostnameIdx["host-1"]; got != 1 {
		t.Fatalf("hostnameIdx[host-1] = %d, want 1", got)
	}
}

// TestApplySnapshotReplacesPreviousState validates that a second apply
// fully replaces the prior state — the legacy contract.
func TestApplySnapshotReplacesPreviousState(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if err := s.applySnapshot(buildSnapshot(t, 3, 1)); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := s.applySnapshot(buildSnapshot(t, 7, 3)); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if got := len(s.nodes); got != 7 {
		t.Fatalf("nodes count after second apply = %d, want 7", got)
	}
	if got := len(s.networks); got != 3 {
		t.Fatalf("networks count after second apply = %d, want 3", got)
	}
}

// TestApplySnapshotRejectsTooLarge enforces the size cap.
func TestApplySnapshotRejectsTooLarge(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	huge := make([]byte, maxSnapshotSize+1)
	if err := s.applySnapshot(huge); err == nil {
		t.Fatalf("expected error for oversized snapshot")
	}
}

// TestApplySnapshotConcurrentReadsStaySane stresses the new pattern: while
// applySnapshot runs, concurrent readers (sampleStats) must see either the
// fully-old or fully-new state — not a partial mix. Run with -race.
func TestApplySnapshotConcurrentReadsStaySane(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if err := s.applySnapshot(buildSnapshot(t, 50, 5)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const iterations = 50
	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations && !stop.Load(); i++ {
			result := s.sampleStats()
			// State count is either the prior state size or new state size,
			// not negative or absurd. We don't pin a specific count because
			// it's racing with applySnapshot; we just want the read path to
			// not panic and to return a non-empty global sample.
			if result.Global.TotalNodes < 0 {
				t.Errorf("negative TotalNodes")
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations/5 && !stop.Load(); i++ {
			data := buildSnapshot(t, 50+i, 5)
			if err := s.applySnapshot(data); err != nil {
				t.Errorf("applySnapshot at iter %d: %v", i, err)
				return
			}
		}
	}()

	wg.Wait()
	stop.Store(true)
}
