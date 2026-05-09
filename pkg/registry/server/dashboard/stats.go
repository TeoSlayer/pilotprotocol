// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dashboard — stats types and stats-collector loop (R5.2).
//
// This file holds the time-series types (StatsSample, NetHistoryRing,
// NetworkSampleEntry, NetworkStats, DashboardStats, BeaconStatsProvider,
// ReleaseBanner, StatsSampleResult) that were extracted from
// pkg/registry/server/server.go as part of the R5.2 decomposition.

package dashboard

import (
	"log/slog"
	"time"
)

// --------------------------------------------------------------------------
// Release banner
// --------------------------------------------------------------------------

// ReleaseBanner is the public-safe snapshot of the latest GitHub release.
// Surfaced on the dashboard so users see why peers may be briefly unreachable
// while the fleet upgrades.
type ReleaseBanner struct {
	Version     string `json:"version"`
	PublishedAt int64  `json:"published_at"`
}

// --------------------------------------------------------------------------
// StatsSample — global time-series data point
// --------------------------------------------------------------------------

// StatsSample is a single time-series data point for dashboard history charts.
type StatsSample struct {
	Timestamp     int64 `json:"ts"`
	TotalNodes    int   `json:"total_nodes"`
	OnlineNodes   int   `json:"online_nodes"`
	TrustLinks    int   `json:"trust_links,omitempty"`
	TotalRequests int64 `json:"total_requests"`
}

// --------------------------------------------------------------------------
// NetHistoryRing — per-network ring buffer
// --------------------------------------------------------------------------

// NetHistoryRing is a fixed-size ring buffer for per-network history samples.
type NetHistoryRing struct {
	Samples []NetworkSampleEntry // length == Size; heap-allocated per ring
	Size    int                  // ring capacity (24 for hourly, 30 for daily)
	Idx     int                  // next write index
}

// NewNetHistoryRing allocates a new ring of the given capacity.
func NewNetHistoryRing(size int) *NetHistoryRing {
	return &NetHistoryRing{Samples: make([]NetworkSampleEntry, size), Size: size}
}

// Write appends a new entry, overwriting the oldest on wraparound.
func (r *NetHistoryRing) Write(e NetworkSampleEntry) {
	r.Samples[r.Idx%r.Size] = e
	r.Idx++
}

// WriteBucketed overwrites the most recent entry if its timestamp falls in
// the same time bucket (e.g. 86400s for per-day dedup); otherwise behaves
// like Write. Guarantees at most one entry per bucket across restarts.
func (r *NetHistoryRing) WriteBucketed(e NetworkSampleEntry, bucketSecs int64) {
	if bucketSecs > 0 && r.Idx > 0 {
		lastIdx := (r.Idx - 1) % r.Size
		if lastIdx < 0 {
			lastIdx += r.Size
		}
		last := r.Samples[lastIdx]
		if last.Timestamp > 0 && last.Timestamp/bucketSecs == e.Timestamp/bucketSecs {
			r.Samples[lastIdx] = e
			return
		}
	}
	r.Samples[r.Idx%r.Size] = e
	r.Idx++
}

// Read returns all non-zero entries in chronological order.
func (r *NetHistoryRing) Read() []NetworkSampleEntry {
	var out []NetworkSampleEntry
	for i := 0; i < r.Size; i++ {
		idx := (r.Idx + i) % r.Size
		if r.Samples[idx].Timestamp != 0 {
			out = append(out, r.Samples[idx])
		}
	}
	return out
}

// --------------------------------------------------------------------------
// NetworkSampleEntry — per-network stats in a time-series sample
// --------------------------------------------------------------------------

// NetworkSampleEntry holds per-network stats within a time-series sample.
type NetworkSampleEntry struct {
	Timestamp int64  `json:"ts"`
	ID        uint16 `json:"id"`
	Name      string `json:"name"`
	Members   int    `json:"members"`
	Online    int    `json:"online"`
	Requests  int64  `json:"requests"`
}

// --------------------------------------------------------------------------
// NetworkStats — per-network aggregate for authenticated dashboard view
// --------------------------------------------------------------------------

// NetworkStats holds per-network statistics for the authenticated dashboard view.
type NetworkStats struct {
	ID         uint16               `json:"id"`
	Name       string               `json:"name"`
	Members    int                  `json:"members"`
	Online     int                  `json:"online"`
	Requests   int64                `json:"requests"`
	TrustLinks int                  `json:"-"`
	Hourly     []NetworkSampleEntry `json:"hourly,omitempty"`
	Daily      []NetworkSampleEntry `json:"daily,omitempty"`
}

// --------------------------------------------------------------------------
// BeaconStatsProvider
// --------------------------------------------------------------------------

// BeaconStatsProvider exposes relay counters the dashboard surfaces in
// /api/stats. Implemented by pkg/beacon.Server.
type BeaconStatsProvider interface {
	RelayForwarded() uint64
	RelayDropped() uint64
	RelayNotFound() uint64
}

// --------------------------------------------------------------------------
// DashboardStats — public-safe data returned by the dashboard API
// --------------------------------------------------------------------------

// DashboardStats is the public-safe data returned by the dashboard API.
type DashboardStats struct {
	TotalNodes        int                    `json:"total_nodes"`
	ActiveNodes       int                    `json:"active_nodes"`
	TotalTrustLinks   int                    `json:"-"`
	TotalRequests     int64                  `json:"total_requests"`
	RelayForwarded    uint64                 `json:"relay_forwarded,omitempty"`
	RelayDropped      uint64                 `json:"relay_dropped,omitempty"`
	RelayNotFound     uint64                 `json:"relay_not_found,omitempty"`
	ReqPerDay         int64                  `json:"req_per_day"`
	UptimeSecs        int64                  `json:"uptime_secs"`
	Versions          map[string]int         `json:"versions,omitempty"`
	Networks          []NetworkStats         `json:"networks,omitempty"` // only populated with dashboard token
	Hourly            []StatsSample          `json:"hourly,omitempty"`
	Daily             []StatsSample          `json:"daily,omitempty"`
	RestartEvents     []int64                `json:"restart_events,omitempty"`
	DowntimeIntervals [][2]int64             `json:"downtime_intervals,omitempty"`
	Probes            map[string]*ProbeState `json:"probes,omitempty"`
	ReleaseBanner     *ReleaseBanner         `json:"release_banner,omitempty"`
}

// --------------------------------------------------------------------------
// StatsSampleResult — snapshot of stats at one instant
// --------------------------------------------------------------------------

// StatsSampleResult holds both global and per-network samples from a single
// snapshot. It is produced by the server's sampleStats callback and consumed
// by recordSample.
type StatsSampleResult struct {
	Global   StatsSample
	Networks map[uint16]NetworkSampleEntry
}

// --------------------------------------------------------------------------
// WriteBucketedStats — ring-buffer helper
// --------------------------------------------------------------------------

// WriteBucketedStats writes a sample into a fixed ring buffer with time-bucket
// dedup: if the most recently written slot holds a sample in the same bucket,
// it is overwritten in place instead of advancing the index. This prevents
// duplicate entries (e.g. two samples on the same UTC day after a restart).
func WriteBucketedStats(ring []StatsSample, idxPtr *int, sample StatsSample, bucketSecs int64) {
	size := len(ring)
	if bucketSecs > 0 && *idxPtr > 0 {
		lastIdx := (*idxPtr - 1) % size
		if lastIdx < 0 {
			lastIdx += size
		}
		last := ring[lastIdx]
		if last.Timestamp > 0 && last.Timestamp/bucketSecs == sample.Timestamp/bucketSecs {
			ring[lastIdx] = sample
			return
		}
	}
	ring[*idxPtr%size] = sample
	*idxPtr++
}

// --------------------------------------------------------------------------
// StatsCollectorLoop — background stats sampling loop (R5.2)
// --------------------------------------------------------------------------

// StatsCollectorLoop runs in the background and samples stats for history
// charts. Hourly samples are taken every hour; daily samples every 24 hours.
//
// readyCh is closed when the parent server is ready to serve (load complete).
// done is closed on server shutdown.
// sampleFn returns a fresh StatsSampleResult under whatever locking the
// caller requires.
// recordFn persists the sample into the parent server's ring buffers; it
// must acquire any required server locks internally.
func (h *Handler) StatsCollectorLoop(
	readyCh <-chan struct{},
	done <-chan struct{},
	sampleFn func() StatsSampleResult,
	recordFn func(StatsSampleResult, bool),
) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("statsCollectorLoop panic", "recover", r)
		}
	}()
	// Wait for server to be ready (load complete) before first sample.
	<-readyCh
	// Sample immediately so there is at least one data point.
	result := sampleFn()
	recordFn(result, true)

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	hourCounter := 0
	for {
		select {
		case <-ticker.C:
			hourCounter++
			result := sampleFn()
			recordFn(result, hourCounter%24 == 0)
		case <-done:
			return
		}
	}
}
