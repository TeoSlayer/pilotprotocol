// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"context"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// Service is the L11 plugin adapter for the manual trust-handshake
// runtime (port 444). Wraps a Manager and bridges between the
// coreapi.Service lifecycle (Start/Stop with deps) and the daemon-
// facing HandshakeService interface that ipc.go + the trust-gate
// callsites rely on.
type Service struct {
	mgr *Manager
}

// NewService constructs a handshake plugin Service over the given
// Runtime. cmd/daemon (composition root) builds the Runtime via
// NewDaemonRuntime(d) and registers the resulting Service.
func NewService(rt Runtime) *Service {
	return &Service{mgr: NewManager(rt)}
}

// --- coreapi.Service ---

func (s *Service) Name() string  { return "handshake" }
func (s *Service) Order() int    { return 60 } // identity-adjacent; before app services
func (s *Service) Start(_ context.Context, _ coreapi.Deps) error {
	// The plugin's Runtime already wraps *daemon.Daemon, so we don't
	// use the coreapi.Deps Streams surface — port 444 binds via the
	// runtime's PortListener (which goes through daemon.Ports().Bind).
	// This keeps the Manager's Start path identical pre/post extraction.
	return s.mgr.Start()
}

func (s *Service) Stop(_ context.Context) error {
	// Best-effort: release the listener so the accept-loop exits, then
	// drain background RPCs.
	if r, ok := s.mgr.rt.(interface{ PortUnbind(uint16) }); ok {
		r.PortUnbind(protocol.PortHandshake)
	}
	s.mgr.Stop()
	return nil
}

// Manager returns the underlying Manager (test helper + composition glue).
func (s *Service) Manager() *Manager { return s.mgr }

// AsHandshakeService returns a daemon.HandshakeService view of this
// plugin, suitable for d.RegisterHandshakeService(svc.AsHandshakeService()).
// The returned wrapper converts plugin-internal TrustRecord /
// PendingHandshake values into the daemon-local mirror types so daemon
// can hold the interface without an upward import.
func (s *Service) AsHandshakeService() daemon.HandshakeService {
	return handshakeServiceAdapter{m: s.mgr}
}

type handshakeServiceAdapter struct{ m *Manager }

func (a handshakeServiceAdapter) IsTrusted(nodeID uint32) bool { return a.m.IsTrusted(nodeID) }

func (a handshakeServiceAdapter) TrustedPeers() []daemon.HandshakeTrustRecord {
	src := a.m.TrustedPeers()
	out := make([]daemon.HandshakeTrustRecord, len(src))
	for i, r := range src {
		out[i] = daemon.HandshakeTrustRecord{
			NodeID:     r.NodeID,
			PublicKey:  r.PublicKey,
			ApprovedAt: r.ApprovedAt,
			Mutual:     r.Mutual,
			Network:    r.Network,
		}
	}
	return out
}

func (a handshakeServiceAdapter) PendingRequests() []daemon.HandshakePendingRecord {
	src := a.m.PendingRequests()
	out := make([]daemon.HandshakePendingRecord, len(src))
	for i, p := range src {
		out[i] = daemon.HandshakePendingRecord{
			NodeID:        p.NodeID,
			PublicKey:     p.PublicKey,
			Justification: p.Justification,
			ReceivedAt:    p.ReceivedAt,
		}
	}
	return out
}

func (a handshakeServiceAdapter) PendingCount() int { return a.m.PendingCount() }

func (a handshakeServiceAdapter) SendRequest(peerNodeID uint32, justification string) error {
	return a.m.SendRequest(peerNodeID, justification)
}

func (a handshakeServiceAdapter) ApproveHandshake(peerNodeID uint32) error {
	return a.m.ApproveHandshake(peerNodeID)
}

func (a handshakeServiceAdapter) RejectHandshake(peerNodeID uint32, reason string) error {
	return a.m.RejectHandshake(peerNodeID, reason)
}

func (a handshakeServiceAdapter) RevokeTrust(peerNodeID uint32) error {
	return a.m.RevokeTrust(peerNodeID)
}

func (a handshakeServiceAdapter) WaitForTrust(peerNodeID uint32, timeout time.Duration) bool {
	return a.m.WaitForTrust(peerNodeID, timeout)
}

func (a handshakeServiceAdapter) ProcessRelayedRequest(fromNodeID uint32, justification string) {
	a.m.ProcessRelayedRequest(fromNodeID, justification)
}

func (a handshakeServiceAdapter) ProcessRelayedApproval(fromNodeID uint32) {
	a.m.ProcessRelayedApproval(fromNodeID)
}

func (a handshakeServiceAdapter) ProcessRelayedRejection(fromNodeID uint32) {
	a.m.ProcessRelayedRejection(fromNodeID)
}

func (a handshakeServiceAdapter) Stop() { a.m.Stop() }

// Compile-time guards.
var (
	_ coreapi.Service         = (*Service)(nil)
	_ daemon.HandshakeService = handshakeServiceAdapter{}
)
