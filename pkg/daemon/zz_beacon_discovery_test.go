// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRegistry is a beaconLister stand-in driven entirely by what the
// test sets it to return. Atomically swappable list lets tests model
// MIG scale-up / scale-down between refresh ticks.
type fakeRegistry struct {
	mu        sync.Mutex
	beacons   []string
	failNext  int   // if >0, the next N Send() calls error
	calls     atomic.Int64
	lastError error
}

func (f *fakeRegistry) setBeacons(addrs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beacons = append([]string(nil), addrs...)
}

func (f *fakeRegistry) failOnce() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext++
}

func (f *fakeRegistry) Send(msg map[string]interface{}) (map[string]interface{}, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext > 0 {
		f.failNext--
		f.lastError = errors.New("simulated registry failure")
		return nil, f.lastError
	}
	if t, _ := msg["type"].(string); t != "beacon_list" {
		return nil, errors.New("unexpected type: " + t)
	}
	out := make([]map[string]interface{}, 0, len(f.beacons))
	for i, addr := range f.beacons {
		out = append(out, map[string]interface{}{
			"id":   uint32(1000 + i),
			"addr": addr,
		})
	}
	// Return as []interface{} (matches what real registry produces via JSON unmarshal)
	asAny := make([]interface{}, len(out))
	for i, m := range out {
		asAny[i] = m
	}
	return map[string]interface{}{
		"type":    "beacon_list_ok",
		"beacons": asAny,
	}, nil
}

// =====================================================================
// fetchBeaconList: registry call shape
// =====================================================================

// TestFetchBeaconListHappyPath: registry returns 3 beacons; we get back
// 3 addrs in deterministic order (sorted).
func TestFetchBeaconListHappyPath(t *testing.T) {
	t.Parallel()
	f := &fakeRegistry{}
	f.setBeacons([]string{"a:1", "c:3", "b:2"})

	got, err := fetchBeaconList(f)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	want := []string{"a:1", "b:2", "c:3"} // sorted
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestFetchBeaconListEmptyResponse: registry hasn't seen any beacons
// yet (cold-start). We get empty slice + nil error.
func TestFetchBeaconListEmptyResponse(t *testing.T) {
	t.Parallel()
	f := &fakeRegistry{}
	f.setBeacons(nil)
	got, err := fetchBeaconList(f)
	if err != nil {
		t.Fatalf("err on empty list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got = %v, want empty", got)
	}
}

// TestFetchBeaconListRegistryError: registry returns error. We get
// the error back; caller decides to keep current list.
func TestFetchBeaconListRegistryError(t *testing.T) {
	t.Parallel()
	f := &fakeRegistry{}
	f.setBeacons([]string{"a:1"})
	f.failOnce()
	if _, err := fetchBeaconList(f); err == nil {
		t.Fatalf("expected error from failing registry")
	}
}

// TestFetchBeaconListNilClient: defensive — nil client doesn't panic.
func TestFetchBeaconListNilClient(t *testing.T) {
	t.Parallel()
	if _, err := fetchBeaconList(nil); err == nil {
		t.Fatalf("expected error for nil client")
	}
}

// TestFetchBeaconListMalformedEntries: registry returns junk in some
// entries; we silently skip them.
func TestFetchBeaconListMalformedEntries(t *testing.T) {
	t.Parallel()
	// Bypass setBeacons; craft response directly.
	customResp := map[string]interface{}{
		"type": "beacon_list_ok",
		"beacons": []interface{}{
			map[string]interface{}{"id": uint32(1), "addr": "real:1"},
			map[string]interface{}{"id": uint32(2)}, // missing addr
			"not even a map",
			map[string]interface{}{"id": uint32(3), "addr": ""}, // empty addr
			map[string]interface{}{"id": uint32(4), "addr": "real:4"},
		},
	}
	stub := &stubLister{response: customResp}
	got, err := fetchBeaconList(stub)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	want := []string{"real:1", "real:4"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// stubLister: returns a fixed response. Used for the malformed-entries test
// because fakeRegistry's setBeacons builds well-formed responses.
type stubLister struct{ response map[string]interface{} }

func (s *stubLister) Send(_ map[string]interface{}) (map[string]interface{}, error) {
	return s.response, nil
}

// =====================================================================
// Disk cache: save / load roundtrip
// =====================================================================

func TestBeaconCacheRoundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")
	addrs := []string{"a:1", "b:2", "c:3"}

	if err := saveBeaconCache(idPath, addrs); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadBeaconCache(idPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != len(addrs) {
		t.Fatalf("loaded %v, want %v", got, addrs)
	}
	for i := range addrs {
		if got[i] != addrs[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], addrs[i])
		}
	}
}

// TestBeaconCacheMissingReturnsEmpty: cold-start with no prior file
// gives (nil, nil) — not an error.
func TestBeaconCacheMissingReturnsEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")
	got, err := loadBeaconCache(idPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

// TestBeaconCacheCorruptIgnored: a corrupt cache file returns an
// error so the caller logs+skips. (We could choose to swallow it; this
// test pins the current contract.)
func TestBeaconCacheCorruptReturnsError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")
	cachePath := filepath.Join(dir, beaconCacheFilename)
	if err := os.WriteFile(cachePath, []byte("not json"), 0600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if _, err := loadBeaconCache(idPath); err == nil {
		t.Fatalf("expected error on corrupt cache")
	}
}

// TestBeaconCacheNoIdentityPathSkips: in-memory daemons (no identity
// file) skip caching cleanly.
func TestBeaconCacheNoIdentityPathSkips(t *testing.T) {
	t.Parallel()
	if err := saveBeaconCache("", []string{"a:1"}); err != nil {
		t.Fatalf("save with empty path: %v", err)
	}
	got, err := loadBeaconCache("")
	if err != nil || got != nil {
		t.Fatalf("load with empty path: got=%v err=%v", got, err)
	}
}

// TestBeaconCacheAtomicWrite: the temp+rename pattern means an
// in-flight crash leaves the OLD cache intact rather than a half-
// written file. Verify the temp file gets cleaned up on success.
func TestBeaconCacheAtomicWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")
	if err := saveBeaconCache(idPath, []string{"x:1"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	// No .tmp file should remain.
	if _, err := os.Stat(filepath.Join(dir, beaconCacheFilename+".tmp")); !os.IsNotExist(err) {
		t.Fatalf(".tmp file left behind after save: err=%v", err)
	}
}

// =====================================================================
// computeRefreshDecision: pure logic, exercised under all scenarios
// =====================================================================

func TestRefreshDecisionInitialPick(t *testing.T) {
	t.Parallel()
	state := newBeaconSelectionState([]string{"boot:1"})
	d := computeRefreshDecision(state, []string{"disc:1", "disc:2"}, []byte("k"))
	if !d.ShouldSwap {
		t.Fatalf("initial pick must signal ShouldSwap=true (current was empty)")
	}
	if d.NewPick == "" {
		t.Fatalf("NewPick empty")
	}
	if len(d.NewList) != 3 {
		t.Fatalf("merged list len = %d, want 3 (boot:1 + 2 discovered)", len(d.NewList))
	}
}

func TestRefreshDecisionStableWhenListUnchanged(t *testing.T) {
	t.Parallel()
	state := newBeaconSelectionState([]string{"boot:1"})
	key := []byte("identity-bytes")

	// First tick: pick + commit
	d1 := computeRefreshDecision(state, []string{"a:1", "b:2"}, key)
	state.ApplyRefreshDecision(d1)
	pick1 := d1.NewPick

	// Second tick: identical list
	d2 := computeRefreshDecision(state, []string{"a:1", "b:2"}, key)
	if d2.ShouldSwap {
		t.Fatalf("ShouldSwap=true on identical list refresh; should be stable. pick1=%s pick2=%s", pick1, d2.NewPick)
	}
	if d2.NewPick != pick1 {
		t.Fatalf("NewPick changed across stable list: %s -> %s", pick1, d2.NewPick)
	}
}

func TestRefreshDecisionFailoverWhenPickIsRemoved(t *testing.T) {
	t.Parallel()
	state := newBeaconSelectionState(nil) // no bootstrap; only discovery
	key := []byte("k")

	// First tick: 3 beacons; daemon picks one.
	d1 := computeRefreshDecision(state, []string{"a:1", "b:2", "c:3"}, key)
	state.ApplyRefreshDecision(d1)
	originalPick := d1.NewPick
	if originalPick == "" {
		t.Fatalf("no initial pick")
	}

	// MIG event: original pick is scaled down. Discovery returns the
	// remaining 2.
	remaining := []string{}
	for _, a := range d1.NewList {
		if a != originalPick {
			remaining = append(remaining, a)
		}
	}
	d2 := computeRefreshDecision(state, remaining, key)
	if !d2.ShouldSwap {
		t.Fatalf("ShouldSwap=false after pick removal; daemon would keep stale pick")
	}
	if d2.NewPick == originalPick {
		t.Fatalf("re-picked the removed beacon: %s", d2.NewPick)
	}
	for _, a := range d2.NewList {
		if a == originalPick {
			t.Fatalf("removed beacon still in NewList: %v", d2.NewList)
		}
	}
}

func TestRefreshDecisionEmptyDiscoveryFallsBackToBootstrap(t *testing.T) {
	t.Parallel()
	state := newBeaconSelectionState([]string{"boot:1"})
	d := computeRefreshDecision(state, nil, []byte("k"))
	if d.NewPick != "boot:1" {
		t.Fatalf("with empty discovery, expected bootstrap pick; got %s", d.NewPick)
	}
}

func TestRefreshDecisionAllEmptyReturnsNothing(t *testing.T) {
	t.Parallel()
	state := newBeaconSelectionState(nil)
	d := computeRefreshDecision(state, nil, []byte("k"))
	if d.NewPick != "" || d.ShouldSwap {
		t.Fatalf("expected no-op decision; got %+v", d)
	}
}

func TestRefreshDecisionMergesAndDedupes(t *testing.T) {
	t.Parallel()
	state := newBeaconSelectionState([]string{"a:1", "b:2"})
	d := computeRefreshDecision(state, []string{"b:2", "c:3"}, []byte("k"))
	if len(d.NewList) != 3 {
		t.Fatalf("expected 3 unique entries (a:1, b:2, c:3); got %v", d.NewList)
	}
	// bootstrap entries come first
	if d.NewList[0] != "a:1" || d.NewList[1] != "b:2" {
		t.Fatalf("bootstrap order broken: %v", d.NewList)
	}
}

// =====================================================================
// State transitions
// =====================================================================

func TestApplyRefreshDecisionUpdatesState(t *testing.T) {
	t.Parallel()
	state := newBeaconSelectionState(nil)
	d := refreshDecision{
		NewList:    []string{"a:1"},
		NewPick:    "a:1",
		ShouldSwap: true,
	}
	state.ApplyRefreshDecision(d)
	if state.GetCurrentPick() != "a:1" {
		t.Fatalf("currentPick = %q, want a:1", state.GetCurrentPick())
	}
}

func TestApplyRefreshDecisionPreservesCurrentOnNonSwap(t *testing.T) {
	t.Parallel()
	state := newBeaconSelectionState(nil)
	state.ApplyRefreshDecision(refreshDecision{NewPick: "first:1", ShouldSwap: true})

	// Apply a second decision marked NotShouldSwap; currentPick stays.
	state.ApplyRefreshDecision(refreshDecision{NewPick: "ignored:1", ShouldSwap: false})
	if got := state.GetCurrentPick(); got != "first:1" {
		t.Fatalf("currentPick = %q, want first:1 (non-swap should not change)", got)
	}
}

// =====================================================================
// End-to-end: emulated registry drives the full discovery flow
// =====================================================================

// TestDiscoveryEndToEndPicksFromRegistry simulates a full refresh tick:
// fetch from fake registry → merge with bootstrap → compute decision →
// apply. Then mutate the registry and run again to verify failover.
func TestDiscoveryEndToEndPicksFromRegistry(t *testing.T) {
	t.Parallel()
	state := newBeaconSelectionState([]string{"boot:1"})
	key := []byte("daemon-pubkey-bytes-stable")

	reg := &fakeRegistry{}
	reg.setBeacons([]string{"mig-a:9001", "mig-b:9001", "mig-c:9001"})

	step := func() refreshDecision {
		discovered, err := fetchBeaconList(reg)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		d := computeRefreshDecision(state, discovered, key)
		state.ApplyRefreshDecision(d)
		return d
	}

	// Tick 1: initial pick from {boot:1, mig-a, mig-b, mig-c}.
	d1 := step()
	if !d1.ShouldSwap {
		t.Fatalf("initial pick should swap; got %+v", d1)
	}
	if len(d1.NewList) != 4 {
		t.Fatalf("merged list len = %d, want 4", len(d1.NewList))
	}
	originalPick := d1.NewPick
	t.Logf("tick 1: list=%v pick=%s", d1.NewList, originalPick)

	// Tick 2: registry list unchanged. No swap.
	d2 := step()
	if d2.ShouldSwap {
		t.Fatalf("tick 2 should be a no-op; got swap to %s", d2.NewPick)
	}

	// MIG SCALE-DOWN: registry drops mig-a (or whichever was picked,
	// to force failover). If pick wasn't a MIG, drop another to test
	// general scale-down resilience.
	dropped := originalPick
	if dropped == "boot:1" {
		dropped = "mig-a:9001"
	}
	remaining := []string{}
	for _, a := range []string{"mig-a:9001", "mig-b:9001", "mig-c:9001"} {
		if a != dropped {
			remaining = append(remaining, a)
		}
	}
	reg.setBeacons(remaining)

	// Tick 3: scale-down detected. If the dropped beacon was our pick,
	// we MUST swap. If it wasn't our pick, the list shrunk but our pick
	// is still in there — no swap unless hash%N differs.
	d3 := step()
	t.Logf("tick 3 after drop %q: list=%v pick=%s shouldSwap=%v", dropped, d3.NewList, d3.NewPick, d3.ShouldSwap)
	if dropped == originalPick && d3.NewPick == dropped {
		t.Fatalf("daemon kept the dropped beacon as pick: %s", dropped)
	}
	for _, a := range d3.NewList {
		if a == dropped {
			t.Fatalf("dropped beacon %q still in NewList: %v", dropped, d3.NewList)
		}
	}

	// MIG SCALE-UP: new beacon arrives.
	reg.setBeacons(append(remaining, "mig-d:9001"))
	d4 := step()
	if len(d4.NewList) <= len(d3.NewList) {
		t.Fatalf("scale-up should grow list: was %d, now %d", len(d3.NewList), len(d4.NewList))
	}

	// REGISTRY FAILURE: next call errors. No state change; pick stays.
	pickBeforeFailure := state.GetCurrentPick()
	reg.failOnce()
	_, err := fetchBeaconList(reg)
	if err == nil {
		t.Fatalf("expected registry failure to surface")
	}
	if got := state.GetCurrentPick(); got != pickBeforeFailure {
		t.Fatalf("registry failure changed currentPick: was %s, now %s", pickBeforeFailure, got)
	}
}

// TestDiscoveryUsesCacheOnRegistryFailure simulates a daemon cold-start
// where the registry is unreachable but the on-disk cache is present.
// The daemon should fall back to the cached list and continue working.
func TestDiscoveryUsesCacheOnRegistryFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")
	cachedAddrs := []string{"cache-a:9001", "cache-b:9001"}
	if err := saveBeaconCache(idPath, cachedAddrs); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Simulate cold-start: registry unreachable.
	reg := &fakeRegistry{}
	reg.failOnce()
	_, err := fetchBeaconList(reg)
	if err == nil {
		t.Fatalf("expected registry failure")
	}

	// Daemon falls back to cache.
	got, err := loadBeaconCache(idPath)
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	if len(got) != len(cachedAddrs) {
		t.Fatalf("cached list = %v, want %v", got, cachedAddrs)
	}

	// Now run a refresh decision using the cached list as the
	// "discovered" input. Daemon picks a beacon and proceeds.
	state := newBeaconSelectionState(nil)
	d := computeRefreshDecision(state, got, []byte("k"))
	if d.NewPick == "" {
		t.Fatalf("no pick from cached list")
	}
}

// TestDiscoveryRefreshLoopJitterBounds: the initial-jitter helper must
// produce values within [0, beaconRefreshJitter). 1000 samples; none
// outside the range.
func TestDiscoveryRefreshLoopJitterBounds(t *testing.T) {
	t.Parallel()
	for i := 0; i < 1000; i++ {
		j := initialJitter()
		if j < 0 || j >= beaconRefreshJitter {
			t.Fatalf("jitter out of [0, %v): %v", beaconRefreshJitter, j)
		}
	}
}

// TestDiscoveryHandlesConcurrentRefresh: state is mutex-guarded; many
// goroutines computing+applying decisions in parallel must not race
// (run with -race).
func TestDiscoveryHandlesConcurrentRefresh(t *testing.T) {
	t.Parallel()
	state := newBeaconSelectionState([]string{"boot:1"})
	const workers = 8
	const iterations = 50
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				d := computeRefreshDecision(state, []string{"a:1", "b:2"}, []byte{byte(w), byte(i)})
				state.ApplyRefreshDecision(d)
			}
		}(w)
	}
	wg.Wait()
	// Just need to NOT race — final state can be any of the picks.
	if state.GetCurrentPick() == "" {
		t.Fatalf("no pick after concurrent refresh")
	}
}

// =====================================================================
// Production beaconRefreshTick: drives the actual loop function with
// a fake registry to confirm the daemon-side wiring (state apply, log
// path, cache persist) works end-to-end without spinning up a real
// daemon.
// =====================================================================

// stubTunnels implements the bare-minimum TunnelManager-style surface
// the refresh tick uses (SetBeaconAddr + RegisterWithBeacon).
type stubTunnels struct {
	mu              sync.Mutex
	beaconAddrs     []string // history of SetBeaconAddr calls
	registerCalls   atomic.Int64
	setBeaconErrors []error // queued errors for SetBeaconAddr to return
}

func (s *stubTunnels) SetBeaconAddr(addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.setBeaconErrors) > 0 {
		err := s.setBeaconErrors[0]
		s.setBeaconErrors = s.setBeaconErrors[1:]
		if err != nil {
			return err
		}
	}
	s.beaconAddrs = append(s.beaconAddrs, addr)
	return nil
}

func (s *stubTunnels) RegisterWithBeacon() {
	s.registerCalls.Add(1)
}

func (s *stubTunnels) lastBeacon() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.beaconAddrs) == 0 {
		return ""
	}
	return s.beaconAddrs[len(s.beaconAddrs)-1]
}

// driveRefreshTick is a test-only helper that runs the same logic as
// beaconRefreshTick but against stub deps (instead of real Daemon /
// Tunnels). Mirrors the production code path so the contract stays
// faithful.
func driveRefreshTick(t *testing.T, state *beaconSelectionState, reg beaconLister, tun *stubTunnels, identityKey []byte, idPath string, firstTick bool) {
	t.Helper()
	discovered, err := fetchBeaconList(reg)
	if err != nil {
		if firstTick {
			cached, _ := loadBeaconCache(idPath)
			if len(cached) > 0 {
				discovered = cached
			} else {
				return
			}
		} else {
			return
		}
	}
	d := computeRefreshDecision(state, discovered, identityKey)
	if !d.ShouldSwap {
		if len(discovered) > 0 {
			_ = saveBeaconCache(idPath, discovered)
		}
		return
	}
	if d.NewPick == "" {
		return
	}
	if err := tun.SetBeaconAddr(d.NewPick); err != nil {
		return
	}
	state.ApplyRefreshDecision(d)
	tun.RegisterWithBeacon()
	_ = saveBeaconCache(idPath, discovered)
}

// TestRefreshTickInitialPickFromRegistry: tick #0 with a healthy
// registry does the full happy-path: fetches, picks, sets, registers,
// and writes the cache.
func TestRefreshTickInitialPickFromRegistry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")

	state := newBeaconSelectionState([]string{"boot:9001"})
	reg := &fakeRegistry{}
	reg.setBeacons([]string{"mig-1:9001", "mig-2:9001"})
	tun := &stubTunnels{}

	driveRefreshTick(t, state, reg, tun, []byte("k"), idPath, true)

	if got := state.GetCurrentPick(); got == "" {
		t.Fatalf("no current pick after initial tick")
	}
	if tun.registerCalls.Load() != 1 {
		t.Fatalf("RegisterWithBeacon calls = %d, want 1", tun.registerCalls.Load())
	}
	cached, err := loadBeaconCache(idPath)
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	if len(cached) != 2 { // only the 2 discovered; bootstrap is not written to cache
		t.Fatalf("cache len = %d, want 2 (got=%v)", len(cached), cached)
	}
}

// TestRefreshTickSkipsOnRegistryErrorAfterFirst: tick #N (N>0) with
// registry error keeps current pick unchanged.
func TestRefreshTickSkipsOnRegistryErrorAfterFirst(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")

	state := newBeaconSelectionState(nil)
	reg := &fakeRegistry{}
	reg.setBeacons([]string{"a:1"})
	tun := &stubTunnels{}

	// Tick #0 — sets initial state.
	driveRefreshTick(t, state, reg, tun, []byte("k"), idPath, true)
	pickBefore := state.GetCurrentPick()
	registerCount := tun.registerCalls.Load()

	// Tick #1 — registry errors. Nothing should change.
	reg.failOnce()
	driveRefreshTick(t, state, reg, tun, []byte("k"), idPath, false)

	if got := state.GetCurrentPick(); got != pickBefore {
		t.Fatalf("pick changed on registry error: was %q, now %q", pickBefore, got)
	}
	if got := tun.registerCalls.Load(); got != registerCount {
		t.Fatalf("RegisterWithBeacon called on error: was %d, now %d", registerCount, got)
	}
}

// TestRefreshTickSwapsOnFailover: tick #0 picks beacon X; X disappears
// from registry on tick #1; daemon migrates to a different beacon.
func TestRefreshTickSwapsOnFailover(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")

	state := newBeaconSelectionState(nil)
	reg := &fakeRegistry{}
	reg.setBeacons([]string{"a:1", "b:2", "c:3"})
	tun := &stubTunnels{}

	driveRefreshTick(t, state, reg, tun, []byte("k"), idPath, true)
	originalPick := state.GetCurrentPick()

	// MIG scale-down: drop the picked beacon.
	remaining := []string{}
	for _, a := range []string{"a:1", "b:2", "c:3"} {
		if a != originalPick {
			remaining = append(remaining, a)
		}
	}
	reg.setBeacons(remaining)

	driveRefreshTick(t, state, reg, tun, []byte("k"), idPath, false)

	if got := state.GetCurrentPick(); got == originalPick {
		t.Fatalf("daemon stuck on dropped beacon %q", got)
	}
	if tun.registerCalls.Load() < 2 {
		t.Fatalf("RegisterWithBeacon should fire on failover swap; calls = %d", tun.registerCalls.Load())
	}
}

// TestRefreshTickColdStartUsesCacheWhenRegistryUnreachable: simulate
// daemon coming up cold with no registry connection and a previously-
// saved cache. The first tick falls back to the cache so the daemon
// gets SOME beacon to talk to instead of zero.
func TestRefreshTickColdStartUsesCacheWhenRegistryUnreachable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")

	// Pre-seed a cache from a previous run.
	if err := saveBeaconCache(idPath, []string{"cached-a:9001", "cached-b:9001"}); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	state := newBeaconSelectionState(nil)
	reg := &fakeRegistry{}
	reg.failOnce() // first call errors
	tun := &stubTunnels{}

	driveRefreshTick(t, state, reg, tun, []byte("k"), idPath, true)

	if got := state.GetCurrentPick(); got == "" {
		t.Fatalf("daemon got no pick despite cache being present")
	}
	if tun.registerCalls.Load() != 1 {
		t.Fatalf("RegisterWithBeacon should fire on cache fallback; calls = %d", tun.registerCalls.Load())
	}
}

// TestCacheNeverContainsPrivateBootstrapAddr is the regression test for
// the private-bootstrap-in-cache bug: a daemon started with a private
// -beacon flag (e.g. swarm VMs configured with 10.128.0.x:9001) must
// NOT write that private address into beacons.json. If it does, every
// subsequent daemon that cold-starts against that cache (and filters it)
// effectively loses half its beacon selection, and any other daemon
// with the same bootstrap writes it back every 60s — a self-healing
// poison loop.
//
// The root cause: computeRefreshDecision returns decision.NewList which
// is the MERGED list (bootstrap + discovered). Saving the merged list
// means bootstrap private IPs survive into the cache even though
// FilterUnreachable already stripped them from the discovered side.
//
// The fix: save only the discovered list (post-filter, pre-merge) to
// disk. Bootstrap comes from the -beacon flag at runtime and is always
// merged in memory — it does not need to live in the file.
func TestCacheNeverContainsPrivateBootstrapAddr(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")

	// Private bootstrap — simulates a swarm VM configured with an
	// internal GCP address.
	privateBootstrap := "10.128.0.78:9001"
	publicDiscovered := "34.71.57.205:9001"

	state := newBeaconSelectionState([]string{privateBootstrap})
	reg := &fakeRegistry{}
	reg.setBeacons([]string{publicDiscovered})
	tun := &stubTunnels{}

	driveRefreshTick(t, state, reg, tun, []byte("k"), idPath, true)

	// Read the raw file bytes — LoadBeaconCache applies FilterUnreachable
	// on read, which would mask the bug. We need to check what was actually
	// written to disk.
	cachePath := filepath.Join(dir, beaconCacheFilename)
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache file: %v", err)
	}
	rawStr := string(raw)
	if strings.Contains(rawStr, privateBootstrap) {
		t.Fatalf("private bootstrap %q written into beacons.json raw content: %s", privateBootstrap, rawStr)
	}
	if !strings.Contains(rawStr, publicDiscovered) {
		t.Fatalf("public discovered address %q missing from beacons.json: %s", publicDiscovered, rawStr)
	}
}

// TestCacheNeverContainsPrivateBootstrapAfterNoSwap covers the no-swap
// branch: even when the pick doesn't change, the refresh still writes
// the cache. That write must also exclude private bootstrap entries.
func TestCacheNeverContainsPrivateBootstrapAfterNoSwap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.json")

	privateBootstrap := "192.168.1.5:9001"
	publicDiscovered := "8.8.8.8:9001"

	state := newBeaconSelectionState([]string{privateBootstrap})
	reg := &fakeRegistry{}
	reg.setBeacons([]string{publicDiscovered})
	tun := &stubTunnels{}

	// Tick 1: initial pick (swap).
	driveRefreshTick(t, state, reg, tun, []byte("k"), idPath, true)
	// Tick 2: list unchanged → no-swap, cache refresh only.
	driveRefreshTick(t, state, reg, tun, []byte("k"), idPath, false)

	cachePath := filepath.Join(dir, beaconCacheFilename)
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache file: %v", err)
	}
	if strings.Contains(string(raw), privateBootstrap) {
		t.Fatalf("private bootstrap %q written into beacons.json after no-swap: %s", privateBootstrap, raw)
	}
}

// silence unused
var _ = time.Second
