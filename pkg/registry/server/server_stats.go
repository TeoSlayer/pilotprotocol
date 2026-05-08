// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"fmt"
	"sort"
	"strings"
	"time"

	dashpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/dashboard"
)

// sampleStats snapshots current stats into a StatsSampleResult and per-network
// entries under RLock. Passed as the sampleFn callback to
// dashboard.Handler.StatsCollectorLoop (R5.2).
func (s *Server) sampleStats() dashpkg.StatsSampleResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.now()
	onlineThreshold := now.Add(-s.StaleNodeThreshold())
	online := 0
	for _, node := range s.nodes {
		if node.GetLastSeen().After(onlineThreshold) {
			online++
		}
	}

	// Per-network samples
	netSamples := make(map[uint16]NetworkSampleEntry, len(s.networks))
	for _, net := range s.networks {
		netOnline := 0
		for _, memberID := range net.Members {
			if node, exists := s.nodes[memberID]; exists {
				if node.GetLastSeen().After(onlineThreshold) {
					netOnline++
				}
			}
		}
		netSamples[net.ID] = NetworkSampleEntry{
			Timestamp: now.Unix(),
			ID:        net.ID,
			Name:      net.Name,
			Members:   len(net.Members),
			Online:    netOnline,
			Requests:  net.RequestCount.Load(),
		}
	}

	return dashpkg.StatsSampleResult{
		Global: StatsSample{
			Timestamp:     now.Unix(),
			TotalNodes:    int(s.nextNode - 1),
			OnlineNodes:   online,
			TrustLinks:    s.trust.Count(),
			TotalRequests: s.requestCount.Load(),
		},
		Networks: netSamples,
	}
}

// recordSample writes a sample into the global and per-network ring buffers.
// Passed as the recordFn callback to dashboard.Handler.StatsCollectorLoop (R5.2).
//
// Samples are bucketed by time (hourly = 3600s, daily = 86400s) so that
// multiple samples falling within the same bucket (e.g. two startups on
// the same UTC day) collapse to a single entry per bucket instead of
// producing duplicate labels on the dashboard charts.
func (s *Server) recordSample(r dashpkg.StatsSampleResult, daily bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dashpkg.WriteBucketedStats(s.hourlyHistory[:], &s.hourlyIdx, r.Global, 3600)
	for netID, entry := range r.Networks {
		ring := s.netHourly[netID]
		if ring == nil {
			ring = dashpkg.NewNetHistoryRing(24)
			s.netHourly[netID] = ring
		}
		ring.WriteBucketed(entry, 3600)
	}
	if daily {
		dashpkg.WriteBucketedStats(s.dailyHistory[:], &s.dailyIdx, r.Global, 86400)
		for netID, entry := range r.Networks {
			ring := s.netDaily[netID]
			if ring == nil {
				ring = dashpkg.NewNetHistoryRing(30)
				s.netDaily[netID] = ring
			}
			ring.WriteBucketed(entry, 86400)
		}
	}
}



// --- Dashboard type aliases (R5.2) ---
//
// The following types have been moved to pkg/registry/server/dashboard.
// Type aliases keep all existing code in package server and in external tests
// compiling without changes.

// StatsSample is an alias for dashpkg.StatsSample (moved in R5.2).
type StatsSample = dashpkg.StatsSample

// netHistoryRing is a package-internal alias for dashpkg.NetHistoryRing.
// The exported form lives in the dashboard sub-package; the unexported alias
// lets existing field names and helper calls in server.go remain unchanged.
type netHistoryRing = dashpkg.NetHistoryRing

// NetworkSampleEntry is an alias for dashpkg.NetworkSampleEntry (moved in R5.2).
type NetworkSampleEntry = dashpkg.NetworkSampleEntry

// NetworkStats is an alias for dashpkg.NetworkStats (moved in R5.2).
type NetworkStats = dashpkg.NetworkStats

// BeaconStatsProvider is an alias for dashpkg.BeaconStatsProvider (moved in R5.2).
type BeaconStatsProvider = dashpkg.BeaconStatsProvider

// DashboardStats is an alias for dashpkg.DashboardStats (moved in R5.2).
type DashboardStats = dashpkg.DashboardStats

// SetBeaconStats wires a BeaconStatsProvider into the registry so
// /api/stats can return relay-forward counts.
func (s *Server) SetBeaconStats(b BeaconStatsProvider) {
	s.mu.Lock()
	s.beaconStats = b
	s.mu.Unlock()
}

// GetDashboardStats returns aggregate statistics for the dashboard.
func (s *Server) GetDashboardStats() DashboardStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	onlineThreshold := now.Add(-s.StaleNodeThreshold())

	activeCount := 0
	versions := make(map[string]int)
	for _, node := range s.nodes {
		if node.GetLastSeen().After(onlineThreshold) {
			activeCount++
		}
		v := node.Version
		if v == "" {
			v = "<1.7.0"
		} else if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		versions[v]++
	}

	reqPerDay := s.computeDeltas()

	var banner *ReleaseBanner
	if s.releasePoller != nil {
		banner = s.releasePoller.current()
	}

	stats := DashboardStats{
		TotalNodes:      int(s.nextNode - 1),
		ActiveNodes:     activeCount,
		TotalTrustLinks: s.trust.Count(),
		TotalRequests:   s.requestCount.Load(),
		ReqPerDay:       reqPerDay,
		UptimeSecs:      int64(now.Sub(s.startTime).Seconds()),
		Versions:        versions,
		ReleaseBanner:   banner,
	}
	if s.beaconStats != nil {
		stats.RelayForwarded = s.beaconStats.RelayForwarded()
		stats.RelayDropped = s.beaconStats.RelayDropped()
		stats.RelayNotFound = s.beaconStats.RelayNotFound()
	}
	return stats
}

// deduplicateSamples keeps only the latest sample per time bucket.
// bucketSecs is 3600 for hourly or 86400 for daily. maxOut caps the result.
func deduplicateSamples(samples []StatsSample, bucketSecs int64, maxOut int) []StatsSample {
	type entry struct {
		bucket int64
		sample StatsSample
	}
	seen := make(map[int64]int) // bucket -> index in result
	var result []entry
	for _, s := range samples {
		if s.Timestamp == 0 {
			continue
		}
		b := s.Timestamp / bucketSecs
		if idx, ok := seen[b]; ok {
			// Keep the later sample in the same bucket
			if s.Timestamp > result[idx].sample.Timestamp {
				result[idx].sample = s
			}
		} else {
			seen[b] = len(result)
			result = append(result, entry{bucket: b, sample: s})
		}
	}
	// Sort chronologically
	sort.Slice(result, func(i, j int) bool { return result[i].bucket < result[j].bucket })
	out := make([]StatsSample, 0, len(result))
	for _, e := range result {
		out = append(out, e.sample)
	}
	if len(out) > maxOut {
		out = out[len(out)-maxOut:]
	}
	return out
}

// deduplicateNetSamples keeps only the latest NetworkSampleEntry per time bucket.
func deduplicateNetSamples(samples []NetworkSampleEntry, bucketSecs int64, maxOut int) []NetworkSampleEntry {
	type entry struct {
		bucket int64
		sample NetworkSampleEntry
	}
	seen := make(map[int64]int)
	var result []entry
	for _, s := range samples {
		if s.Timestamp == 0 {
			continue
		}
		b := s.Timestamp / bucketSecs
		if idx, ok := seen[b]; ok {
			if s.Timestamp > result[idx].sample.Timestamp {
				result[idx].sample = s
			}
		} else {
			seen[b] = len(result)
			result = append(result, entry{bucket: b, sample: s})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].bucket < result[j].bucket })
	out := make([]NetworkSampleEntry, 0, len(result))
	for _, e := range result {
		out = append(out, e.sample)
	}
	if len(out) > maxOut {
		out = out[len(out)-maxOut:]
	}
	return out
}

// readHistory returns chronologically-ordered hourly and daily samples.
// Caller must hold s.mu (at least RLock).
func (s *Server) readHistory() (hourly, daily []StatsSample) {
	// Hourly: read from oldest to newest in ring buffer order
	for i := 0; i < 24; i++ {
		idx := (s.hourlyIdx + i) % 24
		if s.hourlyHistory[idx].Timestamp != 0 {
			hourly = append(hourly, s.hourlyHistory[idx])
		}
	}
	// Daily: same for 30-day ring
	for i := 0; i < len(s.dailyHistory); i++ {
		idx := (s.dailyIdx + i) % len(s.dailyHistory)
		if s.dailyHistory[idx].Timestamp != 0 {
			daily = append(daily, s.dailyHistory[idx])
		}
	}
	return
}

// computeDeltas returns req/day and node growth from daily (or hourly) ring buffers.
// Caller must hold s.mu (at least RLock).
func (s *Server) computeDeltas() (reqPerDay int64) {
	// Try daily samples first (preferred — exact 24h delta)
	var daily []StatsSample
	for i := 0; i < len(s.dailyHistory); i++ {
		idx := (s.dailyIdx + i) % len(s.dailyHistory)
		if s.dailyHistory[idx].Timestamp != 0 {
			daily = append(daily, s.dailyHistory[idx])
		}
	}
	if len(daily) >= 2 {
		prev := daily[len(daily)-2]
		newest := daily[len(daily)-1]
		return newest.TotalRequests - prev.TotalRequests
	}
	// Fall back to last 2 hourly samples, extrapolate ×24
	var hourly []StatsSample
	for i := 0; i < 24; i++ {
		idx := (s.hourlyIdx + i) % 24
		if s.hourlyHistory[idx].Timestamp != 0 {
			hourly = append(hourly, s.hourlyHistory[idx])
		}
	}
	if len(hourly) >= 2 {
		prev := hourly[len(hourly)-2]
		newest := hourly[len(hourly)-1]
		return (newest.TotalRequests - prev.TotalRequests) * 24
	}
	return 0
}

// GetDashboardStatsWithHistory returns aggregate statistics plus history charts.
// Used on the unauthenticated public endpoint — version distribution is omitted
// to avoid advertising what clients run.
func (s *Server) GetDashboardStatsWithHistory() DashboardStats {
	stats := s.GetDashboardStats()
	stats.Versions = nil
	stats.TotalTrustLinks = 0
	s.mu.RLock()
	stats.Hourly, stats.Daily = s.readHistory()
	s.mu.RUnlock()
	if len(stats.Daily) > 7 {
		stats.Daily = stats.Daily[len(stats.Daily)-7:]
	}
	for i := range stats.Hourly {
		stats.Hourly[i].TrustLinks = 0
	}
	for i := range stats.Daily {
		stats.Daily[i].TrustLinks = 0
	}
	s.restartMu.Lock()
	if len(s.restartEvents) > 0 {
		stats.RestartEvents = append([]int64(nil), s.restartEvents...)
	}
	if len(s.downtimeIntervals) > 0 {
		stats.DowntimeIntervals = append([][2]int64(nil), s.downtimeIntervals...)
	}
	s.restartMu.Unlock()
	// Probe states are owned by the dashboard Handler (R5.1).
	stats.Probes = s.dashboard.GetProbeStates()
	return stats
}

// GetDashboardStatsExtended returns dashboard stats including per-network breakdowns.
// Requires the dashboard token — only called from the token-gated API path.
func (s *Server) GetDashboardStatsExtended() DashboardStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	onlineThreshold := now.Add(-s.StaleNodeThreshold())

	activeCount := 0
	versions := make(map[string]int)
	for _, node := range s.nodes {
		if node.GetLastSeen().After(onlineThreshold) {
			activeCount++
		}
		v := node.Version
		if v == "" {
			v = "<1.7.0"
		} else if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		versions[v]++
	}

	// Build per-network member sets for trust link counting
	netMembers := make(map[uint16]map[uint32]bool, len(s.networks))
	for _, net := range s.networks {
		m := make(map[uint32]bool, len(net.Members))
		for _, id := range net.Members {
			m[id] = true
		}
		netMembers[net.ID] = m
	}

	// Count per-network trust links: both nodes must be members of the network
	netTrust := make(map[uint16]int, len(s.networks))
	for _, key := range s.trust.Pairs() {
		// Trust pair format: "nodeA:nodeB"
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		var nodeA, nodeB uint32
		if _, err := fmt.Sscanf(parts[0], "%d", &nodeA); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(parts[1], "%d", &nodeB); err != nil {
			continue
		}
		for netID, members := range netMembers {
			if members[nodeA] && members[nodeB] {
				netTrust[netID]++
			}
		}
	}

	// Build network stats
	networks := make([]NetworkStats, 0, len(s.networks))
	for _, net := range s.networks {
		online := 0
		for _, memberID := range net.Members {
			if node, exists := s.nodes[memberID]; exists {
				if node.GetLastSeen().After(onlineThreshold) {
					online++
				}
			}
		}
		ns := NetworkStats{
			ID:         net.ID,
			Name:       net.Name,
			Members:    len(net.Members),
			Online:     online,
			Requests:   net.RequestCount.Load(),
			TrustLinks: netTrust[net.ID],
		}
		if ring := s.netHourly[net.ID]; ring != nil {
			ns.Hourly = ring.Read()
		}
		if ring := s.netDaily[net.ID]; ring != nil {
			ns.Daily = ring.Read()
		}
		networks = append(networks, ns)
	}

	// Sort by ID for stable output
	sort.Slice(networks, func(i, j int) bool { return networks[i].ID < networks[j].ID })

	hourly, daily := s.readHistory()
	reqPerDay := s.computeDeltas()
	s.restartMu.Lock()
	var restartEvents []int64
	if len(s.restartEvents) > 0 {
		restartEvents = append([]int64(nil), s.restartEvents...)
	}
	var downtimeIntervals [][2]int64
	if len(s.downtimeIntervals) > 0 {
		downtimeIntervals = append([][2]int64(nil), s.downtimeIntervals...)
	}
	s.restartMu.Unlock()

	// Probe states are owned by the dashboard Handler (R5.1).
	probes := s.dashboard.GetProbeStates()

	return DashboardStats{
		TotalNodes:      int(s.nextNode - 1),
		ActiveNodes:     activeCount,
		TotalTrustLinks: s.trust.Count(),
		TotalRequests:   s.requestCount.Load(),
		ReqPerDay:       reqPerDay,
		UptimeSecs:      int64(now.Sub(s.startTime).Seconds()),
		Versions:        versions,
		Networks:        networks,
		Hourly:          hourly,
		Daily:             daily,
		RestartEvents:     restartEvents,
		DowntimeIntervals: downtimeIntervals,
		Probes:            probes,
	}
}
