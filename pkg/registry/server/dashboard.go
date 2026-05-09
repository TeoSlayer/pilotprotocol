// SPDX-License-Identifier: AGPL-3.0-or-later

package server

// dashboard.go — thin shim that wires Server to the dashboard sub-package (R5.1).
//
// All HTTP serving, probe-loop, pulse-ring, and banner state have been extracted
// to pkg/registry/server/dashboard. This file keeps the public methods on Server
// that callers (cmd/rendezvous, tests) already depend on.

import (
	"strings"
	"time"
)

// buildDashboardStatsPayload is the BuildStatsPayload callback wired into the
// dashboard Handler. It assembles the core /api/stats map from the server's
// aggregated statistics without probe states or maintenance banner (which the
// dashboard Handler overlays from its own state).
func (s *Server) buildDashboardStatsPayload(authenticated bool) map[string]interface{} {
	var src DashboardStats
	if authenticated {
		src = s.GetDashboardStatsExtended()
	} else {
		src = s.GetDashboardStatsWithHistory()
	}

	payload := map[string]interface{}{
		"total_requests": src.TotalRequests,
		"total_nodes":    src.TotalNodes,
		"active_nodes":   src.ActiveNodes,
		"uptime_secs":    src.UptimeSecs,
	}
	if len(src.RestartEvents) > 0 {
		payload["restart_events"] = src.RestartEvents
	}
	if src.ReleaseBanner != nil {
		payload["release_banner"] = src.ReleaseBanner
	}

	// Hourly/Daily: convert to dashboard-compatible sample shape.
	if len(src.Hourly) > 0 {
		samples := make([]map[string]interface{}, len(src.Hourly))
		for i, h := range src.Hourly {
			samples[i] = map[string]interface{}{
				"ts":           h.Timestamp,
				"online_nodes": h.OnlineNodes,
			}
		}
		payload["hourly"] = samples
	}
	if len(src.Daily) > 0 {
		daily := src.Daily
		if len(daily) > 7 {
			daily = daily[len(daily)-7:]
		}
		samples := make([]map[string]interface{}, len(daily))
		for i, d := range daily {
			samples[i] = map[string]interface{}{
				"ts":           d.Timestamp,
				"online_nodes": d.OnlineNodes,
			}
		}
		payload["daily"] = samples
	}

	// Per-network table (only for authenticated/extended view).
	if authenticated && len(src.Networks) > 0 {
		nets := make([]map[string]interface{}, len(src.Networks))
		for i, n := range src.Networks {
			nets[i] = map[string]interface{}{
				"id":       n.ID,
				"name":     n.Name,
				"members":  n.Members,
				"online":   n.Online,
				"requests": n.Requests,
			}
		}
		payload["networks"] = nets
	}

	return payload
}

// onlineCount returns the number of nodes whose last-seen is after threshold.
// Called by the dashboard Handler's OnlineCount callback.
func (s *Server) onlineCount(threshold time.Time) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, node := range s.nodes {
		if node.GetLastSeen().After(threshold) {
			count++
		}
	}
	return count
}

// heartbeatLoop persists a "last alive" timestamp at a steady cadence so that,
// after a crash or restart, the gap between the last persisted heartbeat and
// the new process start can be recorded as a real downtime interval.
func (s *Server) heartbeatLoop() {
	defer recoverHandler("heartbeatLoop", nil)
	<-s.readyCh
	// Initial tick so a fresh process immediately has a baseline.
	s.lastHeartbeatMs.Store(time.Now().UnixMilli())
	s.save()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.lastHeartbeatMs.Store(time.Now().UnixMilli())
			s.save()
		case <-s.done:
			s.lastHeartbeatMs.Store(time.Now().UnixMilli())
			return
		}
	}
}

// GetPulseSamples returns the ordered pulse samples from the dashboard Handler's ring.
func (s *Server) GetPulseSamples() []interface{} {
	return nil // legacy stub — dashboard Handler serves /api/pulse directly
}

// dedupStrTrimRight trims trailing whitespace; kept for test compatibility.
func dedupStrTrimRight(s string) string {
	return strings.TrimRight(s, "\r\n\t ")
}
