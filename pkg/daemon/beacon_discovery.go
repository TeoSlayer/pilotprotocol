// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// beaconRefreshInterval is how often the daemon re-fetches beacon_list
// from the registry. At 100k daemons × 1 call/min = ~1.7k req/sec on
// the registry — bounded, small responses, well within capacity.
const beaconRefreshInterval = 60 * time.Second

// beaconRefreshJitter spreads the initial tick across a window so a
// fleet-wide simultaneous restart doesn't thunder-herd the registry.
// The first refresh fires at t = rand[0..beaconRefreshJitter).
const beaconRefreshJitter = 10 * time.Second

// beaconCacheFilename is the on-disk fallback used when the registry
// is unreachable at cold-start. Lives next to the identity file.
const beaconCacheFilename = "beacons.json"

// beaconLister abstracts the registry call. Production wires this to
// (*registry.Client).Send; tests inject a fake.
type beaconLister interface {
	Send(msg map[string]interface{}) (map[string]interface{}, error)
}

// fetchBeaconList queries the registry's beacon_list endpoint and
// returns just the addresses, in the registry's response order. Empty
// addrs are dropped. Returns an error if the call fails or the response
// shape is wrong; the caller treats that as "keep the current list".
func fetchBeaconList(client beaconLister) ([]string, error) {
	if client == nil {
		return nil, fmt.Errorf("nil registry client")
	}
	resp, err := client.Send(map[string]interface{}{"type": "beacon_list"})
	if err != nil {
		return nil, fmt.Errorf("beacon_list send: %w", err)
	}
	rawList, ok := resp["beacons"].([]interface{})
	if !ok {
		// No "beacons" key OR not an array — treat as empty list, not error.
		return nil, nil
	}
	out := make([]string, 0, len(rawList))
	for _, b := range rawList {
		entry, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		addr, _ := entry["addr"].(string)
		if addr != "" {
			out = append(out, addr)
		}
	}
	// Sort to give a deterministic order even when the registry's map
	// iteration produces a different order each call. mergeBeaconLists
	// dedupes against bootstrap, but stable order keeps the hash-pick
	// stable when the SET is unchanged.
	sort.Strings(out)
	return out, nil
}

// beaconCacheEntry is the on-disk format. We keep "saved_at" so a stale
// cache (older than e.g. an hour) can be sniffed out by an operator.
type beaconCacheEntry struct {
	SavedAt time.Time `json:"saved_at"`
	Addrs   []string  `json:"addrs"`
}

// beaconCachePath returns the path to the on-disk beacon cache derived
// from the identity path. Returns "" if identityPath is empty (in-memory
// daemons skip caching).
func beaconCachePath(identityPath string) string {
	if identityPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(identityPath), beaconCacheFilename)
}

// saveBeaconCache writes the current addr list to disk as a fallback
// for next cold-start. Best-effort: errors are returned but the caller
// typically logs and continues.
func saveBeaconCache(identityPath string, addrs []string) error {
	path := beaconCachePath(identityPath)
	if path == "" {
		return nil
	}
	entry := beaconCacheEntry{SavedAt: time.Now(), Addrs: addrs}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal beacon cache: %w", err)
	}
	// Write atomically: write to temp file, then rename.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write beacon cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename beacon cache: %w", err)
	}
	return nil
}

// loadBeaconCache reads the on-disk cache. Returns (nil, nil) if no
// cache exists or identityPath is empty (not an error). Returns an
// error only on parse failures.
func loadBeaconCache(identityPath string) ([]string, error) {
	path := beaconCachePath(identityPath)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read beacon cache: %w", err)
	}
	var entry beaconCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("parse beacon cache: %w", err)
	}
	return entry.Addrs, nil
}

// beaconSelectionState tracks the daemon's beacon picks across refresh
// ticks. Pure data — the refresh logic mutates it under its mutex,
// and the daemon hot path reads via getCurrentPick().
type beaconSelectionState struct {
	mu          sync.Mutex
	bootstrap   []string // operator-configured -beacon list
	currentList []string // last-known merged list
	currentPick string   // address currently set on the tunnel
}

func newBeaconSelectionState(bootstrap []string) *beaconSelectionState {
	return &beaconSelectionState{
		bootstrap: append([]string(nil), bootstrap...),
	}
}

func (s *beaconSelectionState) getCurrentPick() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentPick
}

// refreshDecision describes the outcome of a discovery tick: should
// the daemon swap its beacon and what's the new picked address?
type refreshDecision struct {
	NewList    []string // merged bootstrap + discovered, deduped
	NewPick    string   // hash-of-pubkey selection from NewList
	ShouldSwap bool     // true if NewPick != previous currentPick
}

// computeRefreshDecision runs the merge-pick-compare logic on a snapshot
// of state. Pure function; tests drive it directly without a registry.
//
// If discovered is nil/empty, the function still merges with bootstrap
// — i.e. if discovery fails / returns nothing, fall back to bootstrap-
// only. NewList is empty only if BOTH inputs are empty.
//
// ShouldSwap is true when:
//   - currentPick is empty (initial pick at startup), OR
//   - currentPick is no longer present in NewList (failover: the picked
//     beacon was scaled down / removed from the registry), OR
//   - hash-pick over NewList disagrees with currentPick (rare; happens
//     when the bootstrap list changes via config reload, not in steady
//     state since pubkey + list both stay constant).
//
// NOTE on stickiness vs failover: a hash-of-pubkey pick is stable as
// long as the list set is stable. When a beacon is REMOVED from the
// list, the modulo result for ~ all daemons hashing past that index
// shifts — so the daemon migrates naturally. When a NEW beacon is added
// at a higher index, only the daemons whose hash%N now points at the
// new entry migrate. This is the standard mod-N failover; consistent
// hashing would minimize migration but mod-N is fine at our scale.
func computeRefreshDecision(state *beaconSelectionState, discovered []string, identityKey []byte) refreshDecision {
	state.mu.Lock()
	bootstrap := state.bootstrap
	previousPick := state.currentPick
	state.mu.Unlock()

	merged := mergeBeaconLists(bootstrap, discovered)
	if len(merged) == 0 {
		return refreshDecision{NewList: nil, NewPick: "", ShouldSwap: false}
	}
	newPick := pickBeacon(merged, identityKey)

	shouldSwap := previousPick == "" || newPick != previousPick
	// Also force a swap if currentPick was REMOVED from the new list
	// (covers the "beacon scaled down" case even if hash happens to
	// produce the same index).
	if !shouldSwap {
		stillPresent := false
		for _, a := range merged {
			if a == previousPick {
				stillPresent = true
				break
			}
		}
		if !stillPresent {
			shouldSwap = true
		}
	}
	return refreshDecision{
		NewList:    merged,
		NewPick:    newPick,
		ShouldSwap: shouldSwap,
	}
}

// applyRefreshDecision commits a refresh outcome to the state struct.
// Called by the production refresh loop after a successful SetBeaconAddr.
func (s *beaconSelectionState) applyRefreshDecision(d refreshDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentList = d.NewList
	if d.ShouldSwap && d.NewPick != "" {
		s.currentPick = d.NewPick
	}
}

// initialJitter returns a duration in [0, beaconRefreshJitter) for
// avoiding thundering-herd on the registry at fleet restart.
func initialJitter() time.Duration {
	return time.Duration(rand.Int63n(int64(beaconRefreshJitter)))
}

// beaconRefreshLoop runs in a background goroutine and refreshes the
// daemon's beacon selection from the registry every beaconRefreshInterval
// (60s) plus initial jitter. Started from Daemon.Start() after
// registration. Exits when d.stopCh closes.
//
// Per-tick work:
//  1. Call regConn.Send({"type":"beacon_list"}). On error: log+skip;
//     keep current pick. (Don't repick on registry blip.)
//  2. Merge with bootstrap; compute decision against current state.
//  3. If ShouldSwap: SetBeaconAddr(newPick), RegisterWithBeacon, log.
//  4. Persist the merged list to disk so a future cold-start with
//     unreachable registry can fall back to a recent list.
//
// Cold-start fallback (registry unreachable on FIRST tick): if the
// daemon's bootstrap list is single-entry AND fetch fails AND a cache
// file exists, the cached list is merged into the bootstrap so the
// daemon at least gets a chance at the previously-known beacons.
// (We don't run this on every tick — only at first-tick to keep the
// hot path simple.)
func (d *Daemon) beaconRefreshLoop() {
	if d.beaconSelection == nil || d.regConn == nil || d.identity == nil {
		// Nothing to refresh — single-beacon static config without
		// identity/registry. Exit cleanly.
		return
	}

	// Initial jitter (0..beaconRefreshJitter) avoids fleet thundering
	// herd when daemons restart simultaneously after a registry restart.
	select {
	case <-time.After(initialJitter()):
	case <-d.stopCh:
		return
	}

	firstTick := true
	ticker := time.NewTicker(beaconRefreshInterval)
	defer ticker.Stop()

	for {
		d.beaconRefreshTick(firstTick)
		firstTick = false

		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
		}
	}
}

// beaconRefreshTick runs one iteration of the discovery loop. Extracted
// from beaconRefreshLoop for testability — production drives this from
// the loop; tests can drive it directly.
func (d *Daemon) beaconRefreshTick(firstTick bool) {
	discovered, err := fetchBeaconList(d.regConn)
	if err != nil {
		// On the FIRST tick, try the on-disk cache as a fallback —
		// the registry may have been briefly unreachable at startup.
		// On subsequent ticks, just keep the current pick.
		if firstTick {
			cached, cacheErr := loadBeaconCache(d.config.IdentityPath)
			if cacheErr == nil && len(cached) > 0 {
				slog.Info("beacon discovery: using on-disk cache (registry unreachable)",
					"err", err, "cached_count", len(cached))
				discovered = cached
			} else {
				slog.Debug("beacon discovery skipped (registry error, no usable cache)",
					"err", err)
				return
			}
		} else {
			slog.Debug("beacon discovery skipped (registry error)", "err", err)
			return
		}
	}

	decision := computeRefreshDecision(d.beaconSelection, discovered, d.identity.PublicKey)
	if !decision.ShouldSwap {
		// Refresh the cache even on no-op so it tracks the latest
		// known list — useful for cold-start fallback.
		if len(decision.NewList) > 0 {
			_ = saveBeaconCache(d.config.IdentityPath, decision.NewList)
		}
		return
	}

	if decision.NewPick == "" {
		// Empty merged list — no beacons known. Keep current.
		return
	}

	if err := d.tunnels.SetBeaconAddr(decision.NewPick); err != nil {
		slog.Warn("beacon refresh: SetBeaconAddr failed", "addr", decision.NewPick, "err", err)
		return
	}
	d.beaconSelection.applyRefreshDecision(decision)
	d.tunnels.RegisterWithBeacon()
	if err := saveBeaconCache(d.config.IdentityPath, decision.NewList); err != nil {
		slog.Debug("beacon cache save failed (non-fatal)", "err", err)
	}
	slog.Info("beacon refresh: pick changed",
		"new", decision.NewPick,
		"available", len(decision.NewList))
}
