// SPDX-License-Identifier: AGPL-3.0-or-later

package runtime

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	registryclient "github.com/TeoSlayer/pilotprotocol/pkg/registry/client"
	"github.com/pilot-protocol/handshake"
)

// handshakeCloseDelay matches plugins/handshake.HandshakeCloseDelay.
const handshakeCloseDelay = 500 * time.Millisecond

// HandshakeRuntime adapts *daemon.Daemon to the handshake.Runtime
// interface. Lives here (L12 composition root) so plugins/handshake
// stays free of pkg/daemon.
type HandshakeRuntime struct{ d *daemon.Daemon }

// NewHandshakeRuntime returns a handshake.Runtime backed by d.
func NewHandshakeRuntime(d *daemon.Daemon) handshake.Runtime {
	return HandshakeRuntime{d: d}
}

func (r HandshakeRuntime) NodeID() uint32    { return r.d.NodeID() }
func (r HandshakeRuntime) HasIdentity() bool { return r.d.Identity() != nil }

func (r HandshakeRuntime) PublicKey() ed25519.PublicKey {
	id := r.d.Identity()
	if id == nil {
		return nil
	}
	return id.PublicKey
}

func (r HandshakeRuntime) Sign(msg []byte) []byte {
	id := r.d.Identity()
	if id == nil {
		return nil
	}
	return id.Sign(msg)
}

func (r HandshakeRuntime) IdentityPath() string   { return r.d.IdentityPath() }
func (r HandshakeRuntime) TrustAutoApprove() bool { return r.d.TrustAutoApprove() }

func (r HandshakeRuntime) IsTrusted(nodeID uint32) (string, bool) {
	tc := r.d.GetTrustChecker()
	if tc == nil {
		return "", false
	}
	return tc.IsTrusted(nodeID)
}

func (r HandshakeRuntime) PublishEvent(topic string, payload map[string]any) {
	r.d.PublishEvent(topic, payload)
}

func (r HandshakeRuntime) PortListener(port uint16) (coreapi.Listener, error) {
	return daemonStreams{d: r.d}.Listen(port)
}

func (r HandshakeRuntime) DialAndSend(peerNodeID uint32, port uint16, data []byte) error {
	peerAddr := protocol.Addr{Network: 0, Node: peerNodeID}
	conn, err := r.d.DialConnection(peerAddr, port)
	if err != nil {
		return err
	}
	if err := r.d.SendData(conn, data); err != nil {
		r.d.CloseConnection(conn)
		return fmt.Errorf("send handshake data: %w", err)
	}
	go func() {
		time.Sleep(handshakeCloseDelay)
		r.d.CloseConnection(conn)
	}()
	return nil
}

func (r HandshakeRuntime) RemoveTunnelPeer(nodeID uint32) {
	r.d.Tunnels().RemovePeer(nodeID)
}

func (r HandshakeRuntime) Registry() handshake.RegistryClient {
	c := r.d.RegistryClient()
	if c == nil {
		return nil
	}
	return c
}

// handshakeServiceAdapter converts between plugins/handshake types and
// the daemon-local daemon.HandshakeService mirror types.
type handshakeServiceAdapter struct{ m *handshake.Manager }

// NewHandshakeServiceAdapter wraps a *handshake.Service so it satisfies
// daemon.HandshakeService.
func NewHandshakeServiceAdapter(svc *handshake.Service) daemon.HandshakeService {
	return handshakeServiceAdapter{m: svc.Manager()}
}

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
	_ handshake.Runtime        = HandshakeRuntime{}
	_ daemon.HandshakeService  = handshakeServiceAdapter{}
	_ handshake.RegistryClient = (*registryclient.Client)(nil)
)
