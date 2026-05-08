// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	registryclient "github.com/TeoSlayer/pilotprotocol/pkg/registry/client"
)

// DaemonRuntime adapts a *daemon.Daemon to the handshake plugin's
// Runtime interface. cmd/daemon (the composition root) constructs one
// and passes it to NewService.
//
// Lives in plugins/handshake (L11) because it imports pkg/daemon (L7) —
// a downward edge that's allowed. The reverse (pkg/daemon importing
// plugins/handshake) would be the layer violation T3.3 explicitly
// extracts away.
type DaemonRuntime struct{ d *daemon.Daemon }

// NewDaemonRuntime returns a Runtime implementation that delegates to
// the given daemon.
func NewDaemonRuntime(d *daemon.Daemon) DaemonRuntime { return DaemonRuntime{d: d} }

func (r DaemonRuntime) NodeID() uint32 { return r.d.NodeID() }

func (r DaemonRuntime) HasIdentity() bool { return r.d.Identity() != nil }

func (r DaemonRuntime) PublicKey() ed25519.PublicKey {
	id := r.d.Identity()
	if id == nil {
		return nil
	}
	return id.PublicKey
}

func (r DaemonRuntime) Sign(msg []byte) []byte {
	id := r.d.Identity()
	if id == nil {
		return nil
	}
	return id.Sign(msg)
}

func (r DaemonRuntime) IdentityPath() string {
	return r.d.IdentityPath()
}

func (r DaemonRuntime) TrustAutoApprove() bool { return r.d.TrustAutoApprove() }

func (r DaemonRuntime) IsTrusted(nodeID uint32) (string, bool) {
	tc := r.d.GetTrustChecker()
	if tc == nil {
		return "", false
	}
	return tc.IsTrusted(nodeID)
}

func (r DaemonRuntime) PublishEvent(topic string, payload map[string]any) {
	r.d.PublishEvent(topic, payload)
}

func (r DaemonRuntime) PortListener(port uint16) (*daemon.Listener, error) {
	return r.d.Ports().Bind(port)
}

func (r DaemonRuntime) PortUnbind(port uint16) {
	r.d.Ports().Unbind(port)
}

func (r DaemonRuntime) DialAndSend(peerNodeID uint32, port uint16, data []byte) error {
	peerAddr := protocol.Addr{Network: 0, Node: peerNodeID}
	conn, err := r.d.DialConnection(peerAddr, port)
	if err != nil {
		return err
	}
	if err := r.d.SendData(conn, data); err != nil {
		r.d.CloseConnection(conn)
		return fmt.Errorf("send handshake data: %w", err)
	}
	// Close after a brief delay so the data flushes.
	go func() {
		time.Sleep(handshakeCloseDelay)
		r.d.CloseConnection(conn)
	}()
	return nil
}

func (r DaemonRuntime) RemoveTunnelPeer(nodeID uint32) {
	r.d.Tunnels().RemovePeer(nodeID)
}

func (r DaemonRuntime) Registry() RegistryClient {
	c := r.d.RegistryClient()
	if c == nil {
		return nil
	}
	return c
}

// Compile-time guards.
var (
	_ Runtime        = DaemonRuntime{}
	_ RegistryClient = (*registryclient.Client)(nil)
)
