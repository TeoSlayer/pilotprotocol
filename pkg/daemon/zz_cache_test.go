// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- cacheEndpoint + cachedEndpoint + CachedEndpoint ---

func TestCachedEndpointReturnsEmptyWhenAbsent(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	addr, ok := d.cachedEndpoint(42)
	if ok {
		t.Fatalf("expected ok=false for absent nodeID, got addr=%q ok=true", addr)
	}
	if addr != "" {
		t.Fatalf("expected empty addr, got %q", addr)
	}
}

func TestCacheEndpointStoresAndCachedEndpointReads(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.cacheEndpoint(42, "1.2.3.4:4000")
	addr, ok := d.cachedEndpoint(42)
	if !ok {
		t.Fatal("expected ok=true after cacheEndpoint")
	}
	if addr != "1.2.3.4:4000" {
		t.Fatalf("addr = %q, want 1.2.3.4:4000", addr)
	}
}

func TestCacheEndpointOverwritesExistingEntry(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.cacheEndpoint(42, "1.2.3.4:4000")
	d.cacheEndpoint(42, "5.6.7.8:5000")
	addr, ok := d.cachedEndpoint(42)
	if !ok || addr != "5.6.7.8:5000" {
		t.Fatalf("cachedEndpoint after overwrite = (%q, %v), want (5.6.7.8:5000, true)", addr, ok)
	}
}

func TestCachedEndpointExportedWrapperMatches(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.cacheEndpoint(77, "10.0.0.1:4000")
	internalAddr, internalOK := d.cachedEndpoint(77)
	exportedAddr, exportedOK := d.CachedEndpoint(77)
	if internalAddr != exportedAddr || internalOK != exportedOK {
		t.Fatalf("CachedEndpoint(77)=(%q,%v) != cachedEndpoint(77)=(%q,%v)",
			exportedAddr, exportedOK, internalAddr, internalOK)
	}
}

// --- isEndpointStale ---

func TestIsEndpointStaleReturnsTrueWhenAbsent(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if !d.isEndpointStale(999) {
		t.Fatal("isEndpointStale on absent nodeID should return true")
	}
}

func TestIsEndpointStaleReturnsFalseForFreshEntry(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.cacheEndpoint(1, "1.1.1.1:4000")
	if d.isEndpointStale(1) {
		t.Fatal("fresh cache entry should not be stale")
	}
}

func TestIsEndpointStaleReturnsTrueForOldEntry(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.epCacheMu.Lock()
	d.epCache[2] = &endpointEntry{addr: "2.2.2.2:4000", cachedAt: time.Now().Add(-2 * EndpointCacheTTL)}
	d.epCacheMu.Unlock()
	if !d.isEndpointStale(2) {
		t.Fatal("old cache entry should be stale")
	}
}

// --- cachedResolve + cacheResolve ---

func TestCachedResolveReturnsFalseWhenAbsent(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	resp, ok := d.cachedResolve(42)
	if ok {
		t.Fatalf("expected ok=false for absent, got resp=%v ok=true", resp)
	}
}

func TestCacheResolveStoresAndCachedResolveReads(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	want := map[string]interface{}{"real_addr": "1.2.3.4:4000", "node_id": float64(42)}
	d.cacheResolve(42, want)
	got, ok := d.cachedResolve(42)
	if !ok {
		t.Fatal("cachedResolve should return true after cacheResolve")
	}
	if got["real_addr"] != want["real_addr"] || got["node_id"] != want["node_id"] {
		t.Fatalf("cachedResolve mismatch: got %v want %v", got, want)
	}
}

func TestCachedResolveReturnsFalseWhenStale(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.resolveCacheMu.Lock()
	d.resolveCache[42] = &resolveEntry{resp: map[string]interface{}{"x": "y"}, cachedAt: time.Now().Add(-2 * ResolveCacheTTL)}
	d.resolveCacheMu.Unlock()
	_, ok := d.cachedResolve(42)
	if ok {
		t.Fatal("cachedResolve on stale entry should return false")
	}
}

// --- knownNetworkSet ---

func TestKnownNetworkSetEmptyReturnsEmpty(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	set := d.knownNetworkSet()
	if len(set) != 0 {
		t.Fatalf("expected empty set, got %v", set)
	}
}

func TestKnownNetworkSetFiltersZeroFromNetPolicies(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.netPolicyMu.Lock()
	d.netPolicies[0] = []uint16{1, 2}
	d.netPolicies[5] = []uint16{80}
	d.netPolicyMu.Unlock()
	set := d.knownNetworkSet()
	if set[0] {
		t.Fatal("netID=0 should be filtered from knownNetworkSet (via netPolicies path)")
	}
	if !set[5] {
		t.Fatal("netID=5 should be in set")
	}
}

func TestKnownNetworkSetUnionsFromAllFourSources(t *testing.T) {
	t.Parallel()
	d := New(Config{})

	d.netPolicyMu.Lock()
	d.netPolicies[100] = []uint16{80}
	d.netPolicyMu.Unlock()

	// policyRunners moved to plugins/policy. Without a manager wired,
	// the policy-runner contribution to the union is empty. Test now
	// verifies the three remaining sources merge correctly; the
	// manager-contributed networks are covered by integration tests.

	d.managedMu.Lock()
	d.managed[300] = &ManagedEngine{}
	d.managedMu.Unlock()

	d.memberTagsMu.Lock()
	d.memberTags[400] = []string{"admin"}
	d.memberTagsMu.Unlock()

	set := d.knownNetworkSet()
	for _, netID := range []uint16{100, 300, 400} {
		if !set[netID] {
			t.Fatalf("netID=%d missing from union", netID)
		}
	}
	if len(set) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(set), set)
	}
}

func TestKnownNetworkSetDeduplicatesAcrossSources(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.netPolicyMu.Lock()
	d.netPolicies[50] = []uint16{80}
	d.netPolicyMu.Unlock()
	// policy-runner contribution covered indirectly when a manager
	// is wired (integration tests). Skip in this unit-level dedupe test.
	d.memberTagsMu.Lock()
	d.memberTags[50] = []string{"t"}
	d.memberTagsMu.Unlock()

	set := d.knownNetworkSet()
	if len(set) != 1 || !set[50] {
		t.Fatalf("expected single entry {50:true}, got %v", set)
	}
}

// --- clearNetworkState ---

func TestClearNetworkStateRemovesBothPoliciesAndTags(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.netPolicyMu.Lock()
	d.netPolicies[7] = []uint16{80, 443}
	d.netPolicies[8] = []uint16{22}
	d.netPolicyMu.Unlock()
	d.memberTagsMu.Lock()
	d.memberTags[7] = []string{"admin"}
	d.memberTags[8] = []string{"user"}
	d.memberTagsMu.Unlock()

	d.clearNetworkState(7)

	d.netPolicyMu.RLock()
	_, has7 := d.netPolicies[7]
	_, has8 := d.netPolicies[8]
	d.netPolicyMu.RUnlock()
	if has7 {
		t.Fatal("netPolicies[7] should be deleted")
	}
	if !has8 {
		t.Fatal("netPolicies[8] should remain (only 7 was cleared)")
	}

	d.memberTagsMu.RLock()
	_, tag7 := d.memberTags[7]
	_, tag8 := d.memberTags[8]
	d.memberTagsMu.RUnlock()
	if tag7 {
		t.Fatal("memberTags[7] should be deleted")
	}
	if !tag8 {
		t.Fatal("memberTags[8] should remain")
	}
}

func TestClearNetworkStateNonexistentIsNoop(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.clearNetworkState(999)
	set := d.knownNetworkSet()
	if len(set) != 0 {
		t.Fatalf("state should still be empty, got %v", set)
	}
}

// --- saveNetworkSnapshot + loadNetworkSnapshot ---

func TestSaveNetworkSnapshotEmptyIdentityPathIsNoop(t *testing.T) {
	t.Parallel()
	d := New(Config{IdentityPath: ""})
	// Should not panic or create files anywhere.
	d.saveNetworkSnapshot([]uint16{1, 2, 3})
}

func TestSaveNetworkSnapshotWritesJSONFile(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	idPath := filepath.Join(tmp, "identity.json")
	d := New(Config{IdentityPath: idPath})

	d.netPolicyMu.Lock()
	d.netPolicies[10] = []uint16{80, 443}
	d.netPolicyMu.Unlock()
	d.memberTagsMu.Lock()
	d.memberTags[10] = []string{"admin", "user"}
	d.memberTagsMu.Unlock()

	d.saveNetworkSnapshot([]uint16{10})

	snapPath := filepath.Join(tmp, "networks.json")
	data, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("networks.json not written: %v", err)
	}
	var snap networkSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("snap is not valid JSON: %v", err)
	}
	if len(snap.Networks) != 1 || snap.Networks[0] != 10 {
		t.Fatalf("Networks = %v, want [10]", snap.Networks)
	}
	if got := snap.Policies[10]; len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Fatalf("Policies[10] = %v, want [80 443]", got)
	}
	if got := snap.MemberTags[10]; len(got) != 2 || got[0] != "admin" || got[1] != "user" {
		t.Fatalf("MemberTags[10] = %v, want [admin user]", got)
	}
	if snap.SyncedAt == "" {
		t.Fatal("SyncedAt should be populated")
	}
}

func TestLoadNetworkSnapshotEmptyIdentityPathIsNoop(t *testing.T) {
	t.Parallel()
	d := New(Config{IdentityPath: ""})
	d.loadNetworkSnapshot()
	if len(d.netPolicies) != 0 {
		t.Fatal("loadNetworkSnapshot should not touch state when IdentityPath empty")
	}
}

func TestLoadNetworkSnapshotMissingFileIsNoop(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	idPath := filepath.Join(tmp, "identity.json")
	d := New(Config{IdentityPath: idPath})
	d.loadNetworkSnapshot()
	if len(d.netPolicies) != 0 || len(d.memberTags) != 0 {
		t.Fatal("loadNetworkSnapshot with missing file should leave state empty")
	}
}

func TestLoadNetworkSnapshotInvalidJSONIsNoop(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	idPath := filepath.Join(tmp, "identity.json")
	d := New(Config{IdentityPath: idPath})
	if err := os.WriteFile(filepath.Join(tmp, "networks.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	d.loadNetworkSnapshot()
	if len(d.netPolicies) != 0 || len(d.memberTags) != 0 {
		t.Fatal("invalid JSON should not modify state")
	}
}

func TestLoadNetworkSnapshotRoundTripWithSaveOnlyFillsGaps(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	idPath := filepath.Join(tmp, "identity.json")
	d1 := New(Config{IdentityPath: idPath})

	d1.netPolicyMu.Lock()
	d1.netPolicies[5] = []uint16{80}
	d1.netPolicies[6] = []uint16{22}
	d1.netPolicyMu.Unlock()
	d1.memberTagsMu.Lock()
	d1.memberTags[5] = []string{"tag-A"}
	d1.memberTagsMu.Unlock()
	d1.saveNetworkSnapshot([]uint16{5, 6})

	// Second daemon loads the snapshot but ALREADY has its own entry for 5 —
	// loadNetworkSnapshot must only fill the gap (6), not overwrite 5.
	d2 := New(Config{IdentityPath: idPath})
	d2.netPolicyMu.Lock()
	d2.netPolicies[5] = []uint16{443} // pre-existing, different value
	d2.netPolicyMu.Unlock()
	d2.memberTagsMu.Lock()
	d2.memberTags[5] = []string{"live"}
	d2.memberTagsMu.Unlock()

	d2.loadNetworkSnapshot()

	d2.netPolicyMu.RLock()
	p5 := d2.netPolicies[5]
	p6 := d2.netPolicies[6]
	d2.netPolicyMu.RUnlock()
	if len(p5) != 1 || p5[0] != 443 {
		t.Fatalf("netPolicies[5] should be preserved [443], got %v", p5)
	}
	if len(p6) != 1 || p6[0] != 22 {
		t.Fatalf("netPolicies[6] should be filled from snap [22], got %v", p6)
	}

	d2.memberTagsMu.RLock()
	t5 := d2.memberTags[5]
	d2.memberTagsMu.RUnlock()
	if len(t5) != 1 || t5[0] != "live" {
		t.Fatalf("memberTags[5] should be preserved [live], got %v", t5)
	}
}

// --- resolveLocalAddr ---

func TestResolveLocalAddrParseErrorReturnsInput(t *testing.T) {
	t.Parallel()
	if got := resolveLocalAddr("not-a-host-port"); got != "not-a-host-port" {
		t.Fatalf("malformed input should be returned verbatim; got %q", got)
	}
}

func TestResolveLocalAddrWildcardV4ResolvesToLoopback(t *testing.T) {
	t.Parallel()
	if got := resolveLocalAddr("0.0.0.0:4000"); got != "127.0.0.1:4000" {
		t.Fatalf("0.0.0.0:4000 should resolve to 127.0.0.1:4000; got %q", got)
	}
}

func TestResolveLocalAddrEmptyHostResolvesToLoopback(t *testing.T) {
	t.Parallel()
	if got := resolveLocalAddr(":4000"); got != "127.0.0.1:4000" {
		t.Fatalf(":4000 should resolve to 127.0.0.1:4000; got %q", got)
	}
}

func TestResolveLocalAddrWildcardV6ResolvesToLoopback(t *testing.T) {
	t.Parallel()
	if got := resolveLocalAddr("[::]:4000"); got != "[::1]:4000" {
		t.Fatalf("[::]:4000 should resolve to [::1]:4000; got %q", got)
	}
}

func TestResolveLocalAddrSpecificHostIsPassThrough(t *testing.T) {
	t.Parallel()
	if got := resolveLocalAddr("10.0.0.1:4000"); got != "10.0.0.1:4000" {
		t.Fatalf("specific host should pass through; got %q", got)
	}
}

func TestResolveLocalAddrIPv6SpecificHostIsPassThrough(t *testing.T) {
	t.Parallel()
	if got := resolveLocalAddr("[fe80::1]:4000"); got != "[fe80::1]:4000" {
		t.Fatalf("specific IPv6 host should pass through; got %q", got)
	}
}

// --- concurrency smoke (race detector) ---

func TestCachesConcurrentAccessRaceSafe(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(base uint32) {
			defer func() { done <- struct{}{} }()
			for j := uint32(0); j < 100; j++ {
				d.cacheEndpoint(base*1000+j, "1.2.3.4:4000")
				_, _ = d.cachedEndpoint(base*1000 + j)
				_ = d.isEndpointStale(base*1000 + j)
				d.cacheResolve(base*1000+j, map[string]interface{}{"x": j})
				_, _ = d.cachedResolve(base*1000 + j)
			}
		}(uint32(i))
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
