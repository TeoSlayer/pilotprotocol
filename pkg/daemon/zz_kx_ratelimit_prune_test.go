// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// TestKxRateLimitDoesNotWedgePermanently is the regression guard for a
// self-inflicted denial of service in allowKxFromSource.
//
// kxRateLim had no delete anywhere in the package: entries were inserted
// per source IP and never removed. Once maxPerSrcKxEntries (4096) distinct
// source IPs had EVER sent a PILA/PILK frame, the `len >= max` branch
// returned false for every new IP forever, so key exchange with any new
// peer was permanently dead until the process restarted. An attacker
// spraying spoofed source IPs filled all 4096 slots in a single burst.
//
// Against the unfixed code this test fails: the fresh IP is refused.
func TestKxRateLimitDoesNotWedgePermanently(t *testing.T) {
	tm := &TunnelManager{kxRateLim: make(map[string]*srcKxBucket)}

	// Fill the table to capacity with stale entries, as a burst of spoofed
	// source IPs would. lastFill is backdated past relayKxPruneAge so they
	// are all reclaimable.
	stale := time.Now().Add(-10 * relayKxPruneAge)
	for i := 0; i < maxPerSrcKxEntries; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		tm.kxRateLim[ip] = &srcKxBucket{tokens: perSourceKxLimit, lastFill: stale}
	}
	if len(tm.kxRateLim) != maxPerSrcKxEntries {
		t.Fatalf("setup: got %d entries, want %d", len(tm.kxRateLim), maxPerSrcKxEntries)
	}

	// A brand-new legitimate peer must still be able to key-exchange.
	fresh := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4000}
	if !tm.allowKxFromSource(fresh) {
		t.Fatal("new source IP refused while the table was full of stale entries — " +
			"key exchange is permanently wedged (this is the DoS)")
	}

	if len(tm.kxRateLim) >= maxPerSrcKxEntries {
		t.Fatalf("table did not shrink after prune: %d entries", len(tm.kxRateLim))
	}
}

// TestKxRateLimitStillRefusesWhenAllEntriesAreFresh confirms the prune is a
// reclaim of idle buckets, not a hole in the cap. When every slot is
// genuinely active, the limit must still hold.
func TestKxRateLimitStillRefusesWhenAllEntriesAreFresh(t *testing.T) {
	tm := &TunnelManager{kxRateLim: make(map[string]*srcKxBucket)}

	now := time.Now()
	for i := 0; i < maxPerSrcKxEntries; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		tm.kxRateLim[ip] = &srcKxBucket{tokens: perSourceKxLimit, lastFill: now}
	}

	fresh := &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 4000}
	if tm.allowKxFromSource(fresh) {
		t.Fatal("cap not enforced: a new source was admitted while all 4096 buckets were active")
	}
}

// TestKxRateLimitPerSourceBudgetStillApplies guards the actual rate limit:
// a single source may not exceed perSourceKxLimit frames in one refill
// window.
func TestKxRateLimitPerSourceBudgetStillApplies(t *testing.T) {
	tm := &TunnelManager{kxRateLim: make(map[string]*srcKxBucket)}
	addr := &net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 4000}

	allowed := 0
	for i := 0; i < perSourceKxLimit*3; i++ {
		if tm.allowKxFromSource(addr) {
			allowed++
		}
	}
	if allowed > perSourceKxLimit {
		t.Fatalf("per-source budget exceeded: %d allowed, limit %d", allowed, perSourceKxLimit)
	}
}
