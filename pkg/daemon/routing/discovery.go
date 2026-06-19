// SPDX-License-Identifier: AGPL-3.0-or-later

package routing

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// BeaconRefreshInterval is how often the daemon re-fetches beacon_list
// from the registry. At 100k daemons × 1 call/min = ~1.7k req/sec on
// the registry — bounded, small responses, well within capacity.
const BeaconRefreshInterval = 60 * time.Second

// BeaconRefreshJitter spreads the initial tick across a window so a
// fleet-wide simultaneous restart doesn't thunder-herd the registry.
// The first refresh fires at t = rand[0..BeaconRefreshJitter).
const BeaconRefreshJitter = 10 * time.Second

// BeaconCacheMaxAge is the maximum age of an on-disk beacon cache
// before it is considered stale and rejected in favor of the
// operator-configured bootstrap list.
const BeaconCacheMaxAge = 1 * time.Hour

// BeaconCacheFilename is the on-disk fallback used when the registry
// is unreachable at cold-start. Lives next to the identity file.
const BeaconCacheFilename = "beacons.json"

// BeaconLister abstracts the registry call. Production wires this to
// (*registry.Client).Send; tests inject a fake.
type BeaconLister interface {
	Send(msg map[string]interface{}) (map[string]interface{}, error)
}

// FetchBeaconList queries the registry's beacon_list endpoint and
// returns just the addresses, in the registry's response order. Empty
// addrs are dropped. Returns an error if the call fails or the response
// shape is wrong; the caller treats that as "keep the current list".
func FetchBeaconList(client BeaconLister) ([]string, error) {
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
	// Drop addresses that an off-VPC client cannot reach (RFC1918,
	// loopback, link-local). The registry returns whatever beacons have
	// registered, including ones running on a private VPC; if our hash
	// lands on one of those, all relay traffic vanishes (silent black-
	// hole). Bootstrap entries are NOT filtered — operators on the same
	// VPC can still pin a private beacon there.
	out = FilterUnreachable(out)
	// Sort to give a deterministic order even when the registry's map
	// iteration produces a different order each call. MergeBeaconLists
	// dedupes against bootstrap, but stable order keeps the hash-pick
	// stable when the SET is unchanged.
	sort.Strings(out)
	return out, nil
}

// BeaconCacheEntry is the on-disk format. We keep "saved_at" so a stale
// cache (older than e.g. an hour) can be sniffed out by an operator.
type BeaconCacheEntry struct {
	SavedAt time.Time `json:"saved_at"`
	Addrs   []string  `json:"addrs"`
}

// BeaconCachePath returns the path to the on-disk beacon cache derived
// from the identity path. Returns "" if identityPath is empty (in-memory
// daemons skip caching).
func BeaconCachePath(identityPath string) string {
	if identityPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(identityPath), BeaconCacheFilename)
}

// SaveBeaconCache writes the current addr list to disk as a fallback
// for next cold-start. Best-effort: errors are returned but the caller
// typically logs and continues.
func SaveBeaconCache(identityPath string, addrs []string) error {
	path := BeaconCachePath(identityPath)
	if path == "" {
		return nil
	}
	entry := BeaconCacheEntry{SavedAt: time.Now(), Addrs: addrs}
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

// LoadBeaconCache reads the on-disk cache. Returns (nil, nil) if no
// cache exists or identityPath is empty (not an error). Returns an
// error only on parse failures.
func LoadBeaconCache(identityPath string) ([]string, error) {
	path := BeaconCachePath(identityPath)
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
	var entry BeaconCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("parse beacon cache: %w", err)
	}
	// Filter unreachable addresses from disk too — a previous daemon may
	// have persisted a list that included private VPC IPs before this
	// fix was in place.
	return FilterUnreachable(entry.Addrs), nil
}

// BeaconCacheSavedAt reads the SavedAt timestamp from the on-disk cache
// without deserialising the full addr list.  Returns (time.Time{}, nil)
// when the file does not exist.
func BeaconCacheSavedAt(identityPath string) (time.Time, error) {
	path := BeaconCachePath(identityPath)
	if path == "" {
		return time.Time{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("read beacon cache for SavedAt: %w", err)
	}
	var entry BeaconCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return time.Time{}, fmt.Errorf("parse beacon cache for SavedAt: %w", err)
	}
	return entry.SavedAt, nil
}

// BeaconSelectionState tracks the daemon's beacon picks across refresh
// ticks. Pure data — the refresh logic mutates it under its mutex,
// and the daemon hot path reads via GetCurrentPick().
type BeaconSelectionState struct {
	mu          sync.Mutex
	bootstrap   []string // operator-configured -beacon list
	currentList []string // last-known merged list
	currentPick string   // address currently set on the tunnel
}

// NewBeaconSelectionState returns a state seeded with the operator's
// bootstrap list (copied).
func NewBeaconSelectionState(bootstrap []string) *BeaconSelectionState {
	return &BeaconSelectionState{
		bootstrap: append([]string(nil), bootstrap...),
	}
}

// GetCurrentPick returns the currently-selected beacon address (or "").
func (s *BeaconSelectionState) GetCurrentPick() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentPick
}

// RefreshDecision describes the outcome of a discovery tick: should
// the daemon swap its beacon and what's the new picked address?
type RefreshDecision struct {
	NewList    []string // merged bootstrap + discovered, deduped
	NewPick    string   // hash-of-pubkey selection from NewList
	ShouldSwap bool     // true if NewPick != previous currentPick
}

// ComputeRefreshDecision runs the merge-pick-compare logic on a snapshot
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
func ComputeRefreshDecision(state *BeaconSelectionState, discovered []string, identityKey []byte) RefreshDecision {
	state.mu.Lock()
	bootstrap := state.bootstrap
	previousPick := state.currentPick
	state.mu.Unlock()

	merged := MergeBeaconLists(bootstrap, discovered)
	if len(merged) == 0 {
		return RefreshDecision{NewList: nil, NewPick: "", ShouldSwap: false}
	}
	newPick := PickBeacon(merged, identityKey)

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
	return RefreshDecision{
		NewList:    merged,
		NewPick:    newPick,
		ShouldSwap: shouldSwap,
	}
}

// ApplyRefreshDecision commits a refresh outcome to the state struct.
// Called by the production refresh loop after a successful SetBeaconAddr.
func (s *BeaconSelectionState) ApplyRefreshDecision(d RefreshDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentList = d.NewList
	if d.ShouldSwap && d.NewPick != "" {
		s.currentPick = d.NewPick
	}
}

// InitialJitter returns a duration in [0, BeaconRefreshJitter) for
// avoiding thundering-herd on the registry at fleet restart.
func InitialJitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(BeaconRefreshJitter)))
	if err != nil {
		// Fallback: return 0 jitter on crypto failure (safe, just bad for thundering herd)
		return 0
	}
	return time.Duration(n.Int64())
}
