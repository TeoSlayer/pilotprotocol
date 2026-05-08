// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"runtime"
	"time"

	metrpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/metrics"
)

// updateGauges reads current server state and sets gauge values on the metrics Store.
// It must be called with no locks held; it acquires s.mu.RLock internally.
func (s *Server) updateGauges(m *metrpkg.Store) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	onlineThreshold := now.Add(-s.StaleNodeThreshold())

	total := len(s.nodes)
	online := 0
	taskExec := 0
	for _, node := range s.nodes {
		// Use the atomic-aware getter: heartbeat hot path updates only
		// lastSeenNano (under shard.RLock), not the legacy LastSeen field.
		// Reading LastSeen directly here under-counted "online" for any
		// node that had heartbeated since registration but never gone
		// through a slow-path operation.
		if node.GetLastSeen().After(onlineThreshold) {
			online++
		}
		if node.TaskExec {
			taskExec++
		}
	}

	m.NodesTotal.Set(float64(total))
	m.NodesOnline.Set(float64(online))
	m.TrustLinks.Set(float64(s.trust.Count()))
	m.TaskExecutors.Set(float64(taskExec))
	m.UptimeSeconds.Set(now.Sub(s.startTime).Seconds())

	// Enterprise gauges
	netTotal := 0
	netEnterprise := 0
	var netSnaps []metrpkg.NetworkMetricSnapshot
	for _, n := range s.networks {
		if n.ID == 0 {
			continue // skip backbone
		}
		netTotal++
		if n.Enterprise {
			netEnterprise++
		}

		snap := metrpkg.NetworkMetricSnapshot{
			Name:       n.Name,
			Members:    len(n.Members),
			Enterprise: n.Enterprise,
			PolicySet:  n.Policy.MaxMembers > 0 || len(n.Policy.AllowedPorts) > 0,
		}
		for _, role := range n.MemberRoles {
			switch role {
			case RoleOwner:
				snap.Owners++
			case RoleAdmin:
				snap.Admins++
			}
		}
		netSnaps = append(netSnaps, snap)
	}
	m.NetworksTotal.Set(float64(netTotal))
	m.NetworksEnterprise.Set(float64(netEnterprise))

	m.SetNetworkMetrics(netSnaps)

	pendingInvites := 0
	for _, invites := range s.inviteInbox {
		pendingInvites += len(invites)
	}
	m.InvitesPending.Set(float64(pendingInvites))

	// Enterprise status
	if s.identity.GetIDPConfig() != nil {
		m.IdpConfigured.Set(1)
	} else {
		m.IdpConfigured.Set(0)
	}
	if s.webhook != nil {
		m.WebhookConfigured.Set(1)
	} else {
		m.WebhookConfigured.Set(0)
	}
	if s.auditStore.ExporterConfig() != nil {
		m.AuditExportActive.Set(1)
	} else {
		m.AuditExportActive.Set(0)
	}
	dirSynced := 0
	for range s.rbacPreAssign {
		dirSynced++
	}
	m.DirectorySynced.Set(float64(dirSynced))

	// Saturation observability — capture via trust.InboxSize (separate from s.mu).
	// runtime.NumGoroutine is lock-free.
	m.RuntimeGoroutines.Set(float64(runtime.NumGoroutine()))
	m.RuntimeConnectionsTCP.Set(float64(s.ConnCount()))
	hi, hr := s.trust.InboxSize()
	m.HandshakeInboxSize.Set(float64(hi))
	m.HandshakeRespSize.Set(float64(hr))

	// list_nodes cache counters — sum legacy backbone-admin cache + all
	// per-network caches so the gauge reflects real activity.
	var totalHits, totalWaits, totalRebuilds uint64
	s.listNodesCache.Mu.Lock()
	totalHits += s.listNodesCache.CacheHits
	totalWaits += s.listNodesCache.CacheWaits
	totalRebuilds += s.listNodesCache.CacheRebuilds
	s.listNodesCache.Mu.Unlock()
	s.listNodesPerNetMu.Lock()
	for _, c := range s.listNodesPerNet {
		c.Mu.Lock()
		totalHits += c.CacheHits
		totalWaits += c.CacheWaits
		totalRebuilds += c.CacheRebuilds
		c.Mu.Unlock()
	}
	s.listNodesPerNetMu.Unlock()
	m.ListNodesCacheHits.Set(float64(totalHits))
	m.ListNodesCacheWaits.Set(float64(totalWaits))
	m.ListNodesCacheRebuilds.Set(float64(totalRebuilds))
}
