// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestRekeyBudgetBounded ensures that a flood of unique peer node IDs cannot
// grow lastRekeyReq without bound. The prune step must evict expired entries
// once the map reaches maxRekeyRequesters, capping memory usage.
func TestRekeyBudgetBounded(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()

	// Fill past the cap with entries already older than the rate-limit window,
	// so the prune sweep will successfully evict all of them.
	stale := time.Now().Add(-10 * rekeyRequestInterval)
	for i := uint32(1); i <= maxRekeyRequesters+10; i++ {
		tm.lastRekeyReq[i] = stale
	}

	tm.rekeyMu.Lock()
	ok := tm.pruneRekeyBudgetLocked(time.Now())
	size := len(tm.lastRekeyReq)
	tm.rekeyMu.Unlock()

	if !ok {
		t.Fatalf("prune should free budget when entries are stale; got size=%d", size)
	}
	if size != 0 {
		t.Fatalf("all stale entries should be evicted, got %d remaining", size)
	}
}

// TestRekeyBudgetBlocksFloodOfLiveEntries confirms that when the cap is hit
// by genuinely-recent entries (no stale ones to reap), pruneRekeyBudgetLocked
// refuses to admit a new one. That is the DoS-mitigation path: a flood of
// rotated node IDs within rekeyRequestInterval can't force the map past cap.
func TestRekeyBudgetBlocksFloodOfLiveEntries(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()

	now := time.Now()
	for i := uint32(1); i <= maxRekeyRequesters; i++ {
		tm.lastRekeyReq[i] = now
	}

	tm.rekeyMu.Lock()
	ok := tm.pruneRekeyBudgetLocked(now)
	size := len(tm.lastRekeyReq)
	tm.rekeyMu.Unlock()

	if ok {
		t.Fatalf("prune should refuse new slot when all entries are live; size=%d", size)
	}
	if size != maxRekeyRequesters {
		t.Fatalf("live entries must not be evicted, got size=%d", size)
	}
}
