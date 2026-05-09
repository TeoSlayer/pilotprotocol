// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	acceptpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/accept"
	auditpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/audit"
	authzpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/authz"
	dashpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/dashboard"
	dirpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/directory"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/events"
	identpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/identity"
	membpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/membership"
	metrpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/metrics"
	policypkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/policy"
	replpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/replication"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/routing"
	trustpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/trust"
	walpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/wal"
	webhookpkg "github.com/TeoSlayer/pilotprotocol/pkg/registry/server/webhook"
)

// SetStandby puts the server into standby mode: write operations are rejected
// and state is received from the given primary.
func (s *Server) SetStandby(primary string) {
	s.walStore.SetStandby(true)
	go s.RunStandby(primary)
}

func (s *Server) IsStandby() bool {
	return s.walStore.IsStandby()
}

// SetAdminToken sets the token required for network creation.
// Empty string disables network creation entirely.
func (s *Server) SetAdminToken(token string) {
	s.mu.Lock()
	s.authz.SetAdminToken(token)
	s.mu.Unlock()
}

// SetMaxNodes caps the number of registered nodes. Zero means unlimited.
func (s *Server) SetMaxNodes(n int) {
	s.mu.Lock()
	s.maxNodes = n
	s.mu.Unlock()
}

// SetDashboardToken gates per-network stats on the dashboard.
// Empty string restricts the dashboard to global aggregates only.
func (s *Server) SetDashboardToken(token string) {
	s.mu.Lock()
	s.authz.SetDashboardToken(token)
	s.mu.Unlock()
}

// SetMaintenanceBanner sets a notice rendered on the dashboard. Empty string clears it.
// If SetBannerPath was called, the value is atomically written to disk so it survives restart.
func (s *Server) SetMaintenanceBanner(msg string) { s.dashboard.SetMaintenanceBanner(msg) }

func (s *Server) MaintenanceBanner() string { return s.dashboard.MaintenanceBanner() }

// SetBannerPath enables disk persistence for the maintenance banner.
// If the file exists when called, its content becomes the initial banner value.
func (s *Server) SetBannerPath(path string) { s.dashboard.SetBannerPath(path) }

func (s *Server) SetDashboardHTTPAddr(addr string) { s.dashboard.SetHTTPProbeAddr(addr) }

func (s *Server) ServeDashboard(addr string) error { return s.dashboard.Serve(addr) }

// SetClock replaces the time source. Used in tests for deterministic time.
func (s *Server) SetClock(fn func() time.Time) {
	s.mu.Lock()
	s.now = fn
	s.mu.Unlock()
	s.routing.SetClock(fn)
}

// SetMaxConnections overrides the default connection limit. Used in tests to prevent port exhaustion.
func (s *Server) SetMaxConnections(max int64) {
	s.accept.SetMaxConnections(max)
}

// SetReplicationToken sets the bearer token required for subscribe_replication.
// Empty string disables replication subscription entirely.
func (s *Server) SetReplicationToken(token string) {
	s.walStore.SetReplicationToken(token)
}

// SetWebhookURL sets the endpoint for audit event POSTs. Empty string disables dispatching.
func (s *Server) SetWebhookURL(url string) {
	s.webhook.SetURL(url)
}

// SetWebhookRetryBackoff sets the initial backoff for webhook retries.
// Tests set a short value to avoid waiting on retry exhaustion.
func (s *Server) SetWebhookRetryBackoff(d time.Duration) {
	s.webhook.SetInitialBackoff(d)
}

// SetTLS enables TLS. Empty certFile triggers automatic self-signed certificate generation.
func (s *Server) SetTLS(certFile, keyFile string) error {
	return s.accept.SetTLS(certFile, keyFile)
}

func (s *Server) ListenAndServe(addr string) error {
	if err := s.accept.Listen(addr); err != nil {
		return err
	}

	ln := s.accept.Listener()
	tlsStr := "plaintext"
	if s.accept.TLSConfig() != nil {
		tlsStr = "TLS"
	}
	slog.Info("registry listening", "addr", ln.Addr(), "transport", tlsStr)
	close(s.readyCh)

	go s.reapLoop()
	go s.replMgr.StartHeartbeat(s.done)

	return s.accept.Accept(s.done)
}

// reapLoop removes nodes that have not sent a heartbeat recently.
// Runs every 10s instead of 60s, processing 10K nodes per tick (chunked reap).
// Full sweep completes in ~100s at 100K nodes, within 3-min stale threshold.
func (s *Server) reapLoop() {
	defer recoverHandler("reapLoop", nil)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reapStaleNodes()
			s.reapStaleBeacons()
			s.accept.LogSamplerCleanup()
		case <-s.done:
			return
		}
	}
}

// reapChunkSize is how many nodes to process per reap tick.
const reapChunkSize = 10000

func (s *Server) reapStaleNodes() {
	threshold := s.now().Add(-s.StaleNodeThreshold())
	s.mu.Lock()
	defer s.mu.Unlock()

	nodeIDs := make([]uint32, 0, len(s.nodes))
	for id := range s.nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Slice(nodeIDs, func(i, j int) bool { return nodeIDs[i] < nodeIDs[j] })

	startIdx := 0
	for startIdx < len(nodeIDs) && nodeIDs[startIdx] < s.reapCursor {
		startIdx++
	}

	processed := 0
	reaped := false
	for i := 0; i < len(nodeIDs) && processed < reapChunkSize; i++ {
		idx := (startIdx + i) % len(nodeIDs)
		id := nodeIDs[idx]
		processed++

		node := s.nodes[id]
		lastSeen := node.GetLastSeen()
		if lastSeen.Before(threshold) {
			staleDuration := time.Since(lastSeen).Round(time.Second)
			slog.Info("registry reaping stale node", "node_id", id, "last_seen_ago", staleDuration)
			s.audit("node.reaped", "node_id", id, "reason", "stale_heartbeat",
				"last_seen_ago", staleDuration.String(), "networks", len(node.Networks))
			// Backbone membership is removed. Non-backbone memberships are kept
			// so re-registration can restore the node to its prior networks.
			if net, ok := s.networks[0]; ok {
				for j, m := range net.Members {
					if m == id {
						net.Members = append(net.Members[:j], net.Members[j+1:]...)
						break
					}
				}
			}
			// pubKeyIdx and ownerIdx are intentionally preserved so re-registration
			// reclaims the same node_id rather than allocating a new one.
			if node.Hostname != "" {
				delete(s.hostnameIdx, node.Hostname)
			}
			s.cleanupNode(id)
			delete(s.nodes, id)
			s.invalidateAdminListNodesCache()
			reaped = true
		}

		s.reapCursor = id + 1
	}

	if processed >= len(nodeIDs) {
		s.reapCursor = 0
	}

	if reaped {
		s.save()
	}
}

func (s *Server) reapStaleBeacons() {
	s.routing.ReapStale()
}

func (s *Server) Ready() <-chan struct{} {
	return s.readyCh
}

// Addr returns the bound address. Valid only after Ready() fires.
func (s *Server) Addr() net.Addr {
	ln := s.accept.Listener()
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

func (s *Server) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	// Bound the wait on background loops. If a flushSave or replica push
	// is stuck (slow disk, peer stuck on write), we'd otherwise hang the
	// process indefinitely on shutdown. shutdownDrainTimeout is generous
	// enough for a normal final flush (synchronous disk write of the full
	// snapshot) but bounded so a misbehaving environment cannot wedge us.
	waitOrTimeout := func(name string, ch <-chan struct{}) {
		select {
		case <-ch:
		case <-time.After(shutdownDrainTimeout):
			slog.Warn("registry shutdown: background loop did not finish in time", "loop", name, "timeout", shutdownDrainTimeout)
		}
	}
	waitOrTimeout("saveLoop", s.walStore.SaveDone())
	waitOrTimeout("replicaPushLoop", s.walStore.ReplicaPushDone())
	s.walStore.Close()
	s.webhook.Close()
	s.auditStore.Close()
	if ln := s.accept.Listener(); ln != nil {
		return ln.Close()
	}
	return nil
}

func New(beaconAddr string) *Server {
	return NewWithStore(beaconAddr, "")
}

func NewWithStore(beaconAddr, storePath string) *Server {
	s := &Server{
		nodes:           make(map[uint32]*NodeInfo),
		networks:        make(map[uint16]*NetworkInfo),
		pubKeyIdx:       make(map[string]uint32),
		ownerIdx:        make(map[string]uint32),
		hostnameIdx:     make(map[string]uint32),
		maxNodes:        1_000_000,
		nextNode:        1, // 0 is reserved
		nextNet:         1, // 0 is backbone
		beaconAddr:      beaconAddr,
		storePath:       storePath,
		startTime:       time.Now(),
		inviteInbox:     make(map[uint32][]*NetworkInvite),
		beacons:         make(map[uint32]*beaconEntry),
		replMgr:         replpkg.NewManager(),
		deltaLog:        newDeltaLog(),
		metrics:         metrpkg.NewStore(RecoveredPanicCount),
		readyCh:         make(chan struct{}),
		done:            make(chan struct{}),
		now:             time.Now,
		netHourly:       make(map[uint16]*netHistoryRing),
		netDaily:        make(map[uint16]*netHistoryRing),
		listNodesPerNet: make(map[uint16]*listNodesCacheState),
		bus:             events.NewInProcessBus(0),
	}
	s.staleNodeThresholdNs.Store(int64(defaultStaleNodeThreshold))
	s.accept = acceptpkg.NewAcceptor(defaultMaxConnections, s) // R3.2: accept/TLS/rate-limit layer
	s.authz = authzpkg.NewChecker("", "")                      // tokens set later via SetAdminToken / SetDashboardToken
	s.listNodesCache.Cond = sync.NewCond(&s.listNodesCache.Mu)
	s.routing = routing.NewStore(s)                    // R1.4: beacon/punch routing sub-package
	s.webhook = webhookpkg.NewStore()                  // R1.3: webhook sub-package
	s.webhook.Subscribe(s.bus)                         // fan-out audit.entry events → webhook HTTP POST
	s.auditStore = auditpkg.NewStore()                 // R1.2: audit sub-package
	s.auditStore.Subscribe(s.bus)                      // async ring-buffer + exporter fan-out
	s.trust = trustpkg.NewStore(s, trustpkg.Callbacks{ // R2.1: trust sub-package
		Save:                 s.save,
		Audit:                s.audit,
		IncTrustReports:      s.metrics.TrustReports.Inc,
		IncTrustRevocations:  s.metrics.TrustRevocations.Inc,
		IncHandshakeRequests: s.metrics.HandshakeRequests.Inc,
	})
	s.identity = identpkg.NewStore(s, identpkg.Callbacks{ // R2.3: identity sub-package
		Save:                s.save,
		Audit:               s.audit,
		IncKeyRotations:     s.metrics.KeyRotations.Inc,
		IncIDPVerifications: s.metrics.IdpVerifications.Inc,
		RecordWAL: func(nodeID uint32, newPubKeyB64, rotatedAt string) {
			s.recordWAL(DeltaKeyRotation, nodeID, keyRotationDelta{
				NodeID:       nodeID,
				NewPublicKey: newPubKeyB64,
				RotatedAt:    rotatedAt,
			})
		},
		OnKeyRotated: func(nodeID uint32, oldPubKeyB64, newPubKeyB64 string) {
			s.mu.Lock()
			delete(s.pubKeyIdx, oldPubKeyB64)
			s.pubKeyIdx[newPubKeyB64] = nodeID
			s.mu.Unlock()
		},
		Bus: s.bus,
	})
	s.policy = policypkg.NewStore( // R2.4: policy sub-package
		func(netID uint16) (policypkg.NetworkState, error) {
			s.mu.RLock()
			network, ok := s.networks[netID]
			if !ok {
				s.mu.RUnlock()
				return policypkg.NetworkState{}, fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
			}
			state := policypkg.NetworkState{
				Policy: policypkg.NetworkPolicy{
					MaxMembers:   network.Policy.MaxMembers,
					AllowedPorts: append([]uint16(nil), network.Policy.AllowedPorts...),
					Description:  network.Policy.Description,
				},
				Expr:        append([]byte(nil), network.ExprPolicy...),
				MemberCount: len(network.Members),
			}
			s.mu.RUnlock()
			return state, nil
		},
		func(netID uint16, p policypkg.NetworkPolicy, expr policypkg.ExprPolicy) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			network, ok := s.networks[netID]
			if !ok {
				return fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
			}
			network.Policy = NetworkPolicy{
				MaxMembers:   p.MaxMembers,
				AllowedPorts: p.AllowedPorts,
				Description:  p.Description,
			}
			network.ExprPolicy = expr
			return nil
		},
		func(msg map[string]interface{}, netID uint16) error {
			return s.requireNetworkRole(msg, netID, RoleOwner, RoleAdmin)
		},
		s.requireEnterprise,
		policypkg.Callbacks{
			Save:             s.save,
			Audit:            s.audit,
			IncPolicyChanges: s.metrics.PolicyChanges.Inc,
		},
	)

	s.membership = membpkg.NewStore( // R4.1: membership sub-package
		&s.mu,
		s.networks,
		s.inviteInbox,
		&s.nextNet,
		membpkg.Callbacks{
			Save:  s.save,
			Audit: s.audit,
			RecordWALNetworkCreate: func(netID uint16, name, joinRule, token, adminToken string, enterprise bool, creatorNodeID uint32, createdAt string) {
				s.recordWAL(DeltaNetworkCreate, 0, networkCreateDelta{
					NetworkID:     netID,
					Name:          name,
					JoinRule:      joinRule,
					Token:         token,
					AdminToken:    adminToken,
					Enterprise:    enterprise,
					CreatorNodeID: creatorNodeID,
					CreatedAt:     createdAt,
				})
			},
			RecordWALNetworkJoin: func(nodeID uint32, netID uint16) {
				s.recordWAL(DeltaNetworkJoin, nodeID, networkMembershipDelta{
					NodeID:    nodeID,
					NetworkID: netID,
				})
			},
			RecordWALNetworkLeave: func(nodeID uint32, netID uint16) {
				s.recordWAL(DeltaNetworkLeave, nodeID, networkMembershipDelta{
					NodeID:    nodeID,
					NetworkID: netID,
				})
			},
			RecordWALNetworkDelete: func(netID uint16) {
				s.recordWAL(DeltaNetworkDelete, 0, networkDeleteDelta{NetworkID: netID})
			},
			InvalidateListNodesCache: s.invalidateListNodesCacheForNetwork,
			PublishMembershipChanged: s.publishMembershipChanged,
			ApplyRBACPreAssignment:   s.applyRBACPreAssignmentLocked,
			RequireAdminToken:        s.requireAdminToken,
			RequireNetworkRole: func(msg map[string]interface{}, netID uint16, roles ...membpkg.Role) error {
				srv := make([]Role, len(roles))
				for i, r := range roles {
					srv[i] = Role(r)
				}
				return s.requireNetworkRole(msg, netID, srv...)
			},
			RequireEnterprise: s.requireEnterprise,
			VerifyNodeSignature: func(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
				return authzpkg.VerifyNodeSignature(pubKey, adminToken, msg, challenge)
			},
			AdminToken: func() string {
				return s.authz.AdminToken()
			},
			NodeExists: func(nodeID uint32) bool {
				_, ok := s.nodes[nodeID]
				return ok
			},
			GetNode: func(nodeID uint32) (pubKey []byte, networks []uint16, externalID string, ok bool) {
				node, ok := s.nodes[nodeID]
				if !ok {
					return nil, nil, "", false
				}
				return node.PublicKey, node.Networks, node.ExternalID, true
			},
			NodeNetworks: func(nodeID uint32) ([]uint16, bool) {
				node, ok := s.nodes[nodeID]
				if !ok {
					return nil, false
				}
				return node.Networks, true
			},
			AppendNodeNetwork: func(nodeID uint32, netID uint16) {
				node, ok := s.nodes[nodeID]
				if !ok {
					return
				}
				sh := s.nodeShard(nodeID)
				sh.Lock()
				node.Networks = append(node.Networks, netID)
				sh.Unlock()
			},
			RemoveNodeNetwork: func(nodeID uint32, netID uint16) bool {
				node, ok := s.nodes[nodeID]
				if !ok {
					return false
				}
				sh := s.nodeShard(nodeID)
				sh.Lock()
				found := false
				for i, n := range node.Networks {
					if n == netID {
						node.Networks = append(node.Networks[:i], node.Networks[i+1:]...)
						found = true
						break
					}
				}
				sh.Unlock()
				return found
			},
			IncInvitesSent:     s.metrics.InvitesSent.Inc,
			IncInvitesAccepted: s.metrics.InvitesAccepted.Inc,
			IncInvitesRejected: s.metrics.InvitesRejected.Inc,
			IncRbacOps:         func(op string) { s.metrics.RbacOps.WithLabel(op).Inc() },
		},
		func() time.Time { return s.now() },
	)

	s.directory = dirpkg.NewStore( // R4.2: directory sub-package
		&s.mu,
		(*dirpkg.NodeShards)(&s.nodeShards),
		s.nodes,
		s.pubKeyIdx,
		s.ownerIdx,
		s.hostnameIdx,
		&s.nextNode,
		&s.maxNodes,
		&s.reapCursor,
		&s.listNodesCache,
		&s.listNodesPerNetMu,
		&s.listNodesPerNet,
		func(netID uint16) (dirpkg.NetworkMemberView, bool) {
			// Caller holds mu.RLock.
			network, ok := s.networks[netID]
			if !ok {
				return dirpkg.NetworkMemberView{}, false
			}
			members := make([]uint32, len(network.Members))
			copy(members, network.Members)
			roles := make(map[uint32]string, len(network.MemberRoles))
			for k, v := range network.MemberRoles {
				roles[k] = string(v)
			}
			tags := make(map[uint32][]string, len(network.MemberTags))
			for k, v := range network.MemberTags {
				tags[k] = append([]string(nil), v...)
			}
			return dirpkg.NetworkMemberView{Members: members, MemberRoles: roles, MemberTags: tags}, true
		},
		dirpkg.Callbacks{
			Save:  s.save,
			Audit: s.audit,
			RecordWALRegister: func(nodeID uint32, owner, pubKeyB64, realAddr, hostname string, lanAddrs []string, version, createdAt string) {
				s.recordWAL(DeltaRegister, nodeID, registerDelta{
					NodeID:    nodeID,
					Owner:     owner,
					PublicKey: pubKeyB64,
					RealAddr:  realAddr,
					Hostname:  hostname,
					LANAddrs:  lanAddrs,
					Version:   version,
					CreatedAt: createdAt,
				})
			},
			RecordWALDeregister: func(nodeID uint32) {
				s.recordWAL(DeltaDeregister, nodeID, deregisterDelta{NodeID: nodeID})
			},
			InvalidateListNodesCache:      s.invalidateListNodesCacheForNetwork,
			InvalidateAdminListNodesCache: s.invalidateAdminListNodesCache,
			PublishMembershipChanged:      s.publishMembershipChanged,
			RemoveFromNetworks: func(nodeID uint32, networks []uint16) []uint16 {
				var lostOwnerNets []uint16
				for _, netID := range networks {
					if net, ok := s.networks[netID]; ok {
						if net.MemberRoles[nodeID] == RoleOwner && len(net.Members) > 1 {
							lostOwnerNets = append(lostOwnerNets, netID)
						}
						for i, m := range net.Members {
							if m == nodeID {
								net.Members = append(net.Members[:i], net.Members[i+1:]...)
								break
							}
						}
						delete(net.MemberRoles, nodeID)
					}
				}
				return lostOwnerNets
			},
			ClearInviteInbox: func(nodeID uint32) {
				delete(s.inviteInbox, nodeID)
				for targetID, invites := range s.inviteInbox {
					remaining := make([]*NetworkInvite, 0, len(invites))
					for _, inv := range invites {
						if inv.InviterID != nodeID {
							remaining = append(remaining, inv)
						}
					}
					if len(remaining) == 0 {
						delete(s.inviteInbox, targetID)
					} else if len(remaining) < len(invites) {
						s.inviteInbox[targetID] = remaining
					}
				}
			},
			RequireAdminToken:       s.requireAdminToken,
			RequireAdminTokenLocked: s.requireAdminTokenLocked,
			AdminToken:              func() string { return s.authz.AdminToken() },
			VerifyNodeSignature:     s.verifyHeartbeatSignature,
			IsTrusted:               s.trust.IsTrusted,
			BeaconAddr:              func() string { return s.beaconAddr },
			IncRegistrations:        s.metrics.Registrations.Inc,
			IncDeregistrations:      s.metrics.Deregistrations.Inc,
			IncRequestsTotal:        func(label string) { s.metrics.RequestsTotal.WithLabel(label).Inc() },
			IncErrorsTotal:          func(label string) { s.metrics.ErrorsTotal.WithLabel(label).Inc() },
			ObserveRequestDuration:  func(label string, sec float64) { s.metrics.RequestDuration.WithLabel(label).Observe(sec) },
			Now:                     func() time.Time { return s.now() },
			AddNodeToBackbone: func(nodeID uint32) {
				// Caller holds mu.Lock. Only add if not already a member.
				backbone := s.networks[0]
				for _, m := range backbone.Members {
					if m == nodeID {
						return
					}
				}
				backbone.Members = append(backbone.Members, nodeID)
			},
			ScanNetworkMemberships: func(nodeID uint32) []uint16 {
				// Caller holds mu.Lock. Returns non-backbone networks that list nodeID.
				var nets []uint16
				for netID, net := range s.networks {
					if netID == 0 {
						continue
					}
					for _, m := range net.Members {
						if m == nodeID {
							nets = append(nets, netID)
							break
						}
					}
				}
				return nets
			},
		},
	)

	// Wire the event bus subscriber that invalidates the list_nodes cache
	// whenever any handler publishes "membership.changed". This is the
	// authoritative invalidation path for handlers that call s.publishMembershipChanged;
	// direct calls to invalidateListNodesCacheForNetwork in handlers ensure
	// synchronous correctness for existing code paths as well.
	{
		ch, unsubscribe := s.bus.Subscribe("membership.changed")
		go func() {
			defer unsubscribe()
			for {
				select {
				case evt, ok := <-ch:
					if !ok {
						return
					}
					if netID, ok := evt.Payload["net_id"].(uint16); ok {
						s.invalidateListNodesCacheForNetwork(netID)
					}
				case <-s.done:
					return
				}
			}
		}()
	}

	// Initialize WAL Store (R6.1): owns WAL file, save/replica-push goroutines,
	// standby flag, and replication token. The walPath is empty when no
	// persistence is configured, which causes NewStore to return a Store with
	// a nil WAL (all WAL operations become no-ops).
	{
		walPath := ""
		if storePath != "" {
			walPath = storePath + ".wal"
		}
		walCbs := walpkg.StoreCallbacks{
			FlushSave:       s.flushSave,
			SnapshotJSON:    s.snapshotJSON,
			Push:            s.replMgr.Push,
			IncSaveFailures: s.metrics.SaveFailures.Inc,
		}
		ws, err := walpkg.NewStore(walPath, s.done, walCbs)
		if err != nil {
			slog.Error("failed to initialize WAL store; falling back to no persistence", "err", err)
			var fbErr error
			ws, fbErr = walpkg.NewStore("", s.done, walCbs)
			if fbErr != nil {
				// NewStore("") only fails if its own goroutine startup fails,
				// which should never happen. Treat it as unrecoverable.
				panic(fmt.Sprintf("failed to initialize in-memory WAL store: %v", fbErr))
			}
		}
		s.walStore = ws
		ws.Start()
	}

	// Initialize dashboard Handler (R5.1): owns probe state, pulse ring,
	// maintenance banner, and the HTTP mux. Wired via Callbacks to avoid
	// circular imports between the server and dashboard packages.
	s.dashboard = dashpkg.NewHandler(dashpkg.Callbacks{
		GetDashboardToken: func() string { return s.authz.DashboardToken() },
		GetAdminToken:     func() string { return s.authz.AdminToken() },
		BuildStatsPayload: s.buildDashboardStatsPayload,
		GetNodes: func() []dashpkg.NodeSnapshot {
			s.mu.RLock()
			out := make([]dashpkg.NodeSnapshot, 0, len(s.nodes))
			for _, node := range s.nodes {
				out = append(out, dashpkg.NodeSnapshot{
					ID:       node.ID,
					Hostname: node.Hostname,
					LastSeen: node.GetLastSeen(),
				})
			}
			s.mu.RUnlock()
			return out
		},
		RequestCount:    s.requestCount.Load,
		StartTime:       func() time.Time { return s.startTime },
		NodeCount:       func() int { s.mu.RLock(); n := len(s.nodes); s.mu.RUnlock(); return n },
		OnlineCount:     s.onlineCount,
		StaleThreshold:  s.StaleNodeThreshold,
		TriggerSnapshot: s.TriggerSnapshot,
		UpdateGauges:    func() { s.updateGauges(s.metrics) },
		WriteMetrics:    func(w io.Writer) { s.metrics.WriteTo(w) }, //nolint:errcheck
		ListenerAddr: func() string {
			if ln := s.accept.Listener(); ln != nil {
				return ln.Addr().String()
			}
			return ""
		},
		BeaconAddr: func() string { return s.beaconAddr },
		ReadyCh:    func() <-chan struct{} { return s.readyCh },
		Done:       func() <-chan struct{} { return s.done },
		Save:       s.save,
	})

	s.releasePoller = newReleasePoller("TeoSlayer/pilotprotocol")
	go s.dashboard.StatsCollectorLoop(s.readyCh, s.done, s.sampleStats, s.recordSample)
	go s.dashboard.PulseLoop()
	go s.heartbeatLoop()
	go s.dashboard.ProbeLoop()
	go s.releasePoller.run(s.done)

	// Try loading from disk
	if storePath != "" {
		loaded := false
		if err := s.load(); err != nil {
			slog.Info("registry starting fresh", "reason", err)
		} else {
			slog.Info("registry loaded state from disk",
				"nodes", len(s.nodes),
				"networks", len(s.networks),
				"next_node", s.nextNode,
				"next_net", s.nextNet,
			)
			loaded = true
		}
		// Replay WAL in both cases: entries after the last snapshot when one
		// exists, and entries written before the first-ever snapshot when the
		// server crashed before the first flush. Without this, a node registered
		// then lost before the first flush is silently dropped on restart.
		s.replayWAL()
		if loaded {
			return s
		}
		// Fall through to backbone creation for the fresh-start case.
	}

	// Create the backbone network (ID 0)
	s.networks[0] = &NetworkInfo{
		ID:       0,
		Name:     "backbone",
		JoinRule: "open",
		Members:  []uint32{},
		Created:  time.Now(),
	}

	return s
}
