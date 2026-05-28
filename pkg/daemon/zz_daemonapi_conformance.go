// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"fmt"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/daemonapi"
	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
)

// daemonAPIAdapter wraps a *Daemon to satisfy daemonapi.Daemon.
//
// Why an adapter instead of changing *Daemon's method signatures:
//
//   - The daemon engine's internal call sites pass *Connection, get
//     back *Connection, and want strong typing. Forcing them onto
//     daemonapi.Connection (which is interface{}) would mean
//     type-assertions at hundreds of internal call sites.
//
//   - daemonapi.Daemon, on the other hand, must return opaque types
//     plugins treat as tokens. The adapter translates: it presents
//     the daemonapi-shaped signatures externally and dispatches to
//     the typed methods internally.
//
// Plugins receive a daemonapi.Daemon via daemonapi.LoadAll; cmd/daemon
// passes d.DaemonAPI() at startup.
type daemonAPIAdapter struct{ d *Daemon }

// Compile-time assertion that the adapter implements every method on
// daemonapi.Daemon. When this assertion fails, the compiler reports
// the offending method below — fix the adapter, not the daemon engine.
var _ daemonapi.Daemon = daemonAPIAdapter{}

// DaemonAPI returns a daemonapi.Daemon-shaped view of this daemon for
// plugin LoadAll. Stateless wrapper; cheap to call.
func (d *Daemon) DaemonAPI() daemonapi.Daemon { return daemonAPIAdapter{d: d} }

// --- Lifecycle -------------------------------------------------------

func (a daemonAPIAdapter) Start() error { return a.d.Start() }
func (a daemonAPIAdapter) Stop() error  { return a.d.Stop() }

// --- Identity --------------------------------------------------------

func (a daemonAPIAdapter) NodeID() uint32             { return a.d.NodeID() }
func (a daemonAPIAdapter) Identity() *crypto.Identity { return a.d.Identity() }
func (a daemonAPIAdapter) IdentityPath() string       { return a.d.IdentityPath() }

// --- Configuration ---------------------------------------------------

func (a daemonAPIAdapter) AdminToken() string     { return a.d.AdminToken() }
func (a daemonAPIAdapter) TrustAutoApprove() bool { return a.d.TrustAutoApprove() }

// --- Network plumbing ------------------------------------------------

func (a daemonAPIAdapter) Addr() protocol.Addr { return a.d.Addr() }

func (a daemonAPIAdapter) DialConnection(dstAddr protocol.Addr, dstPort uint16) (daemonapi.Connection, error) {
	return a.d.DialConnection(dstAddr, dstPort)
}

func (a daemonAPIAdapter) DialConnectionContext(ctx context.Context, dstAddr protocol.Addr, dstPort uint16) (daemonapi.Connection, error) {
	return a.d.DialConnectionContext(ctx, dstAddr, dstPort)
}

func (a daemonAPIAdapter) SendData(c daemonapi.Connection, data []byte) error {
	conn, ok := c.(*Connection)
	if !ok {
		return fmt.Errorf("daemonapi: SendData expected *Connection, got %T", c)
	}
	return a.d.SendData(conn, data)
}

func (a daemonAPIAdapter) SendDatagram(dstAddr protocol.Addr, dstPort uint16, data []byte) error {
	return a.d.SendDatagram(dstAddr, dstPort, data)
}

func (a daemonAPIAdapter) CloseConnection(c daemonapi.Connection) {
	conn, ok := c.(*Connection)
	if !ok {
		return // wrong type — silently drop, same shape as a no-op close
	}
	a.d.CloseConnection(conn)
}

func (a daemonAPIAdapter) NewConnReadWriter(c daemonapi.Connection) daemonapi.ConnReadWriter {
	conn, ok := c.(*Connection)
	if !ok {
		return nil
	}
	return a.d.NewConnReadWriter(conn)
}

func (a daemonAPIAdapter) Ports() daemonapi.PortAllocator    { return a.d.Ports() }
func (a daemonAPIAdapter) Tunnels() daemonapi.TunnelRegistry { return a.d.Tunnels() }

// --- Registry --------------------------------------------------------

func (a daemonAPIAdapter) RegistryClient() *registry.Client { return a.d.RegistryClient() }

func (a daemonAPIAdapter) RegConnListNodes(netID uint16, token string) (map[string]any, error) {
	return a.d.RegConnListNodes(netID, token)
}

func (a daemonAPIAdapter) SetMemberTags(netID uint16, tags []string) {
	a.d.SetMemberTags(netID, tags)
}

// --- Events ----------------------------------------------------------

func (a daemonAPIAdapter) PublishEvent(topic string, payload map[string]any) {
	a.d.PublishEvent(topic, payload)
}

func (a daemonAPIAdapter) Bus() daemonapi.EventBus { return a.d.Bus() }

// --- Trust + handshake plugin coordination ---------------------------

func (a daemonAPIAdapter) GetTrustChecker() daemonapi.TrustChecker {
	return a.d.GetTrustChecker()
}

func (a daemonAPIAdapter) RegisterTrustChecker(tc daemonapi.TrustChecker) {
	a.d.RegisterTrustChecker(tc)
}

func (a daemonAPIAdapter) HandshakeService() daemonapi.HandshakeService {
	return a.d.HandshakeService()
}

func (a daemonAPIAdapter) RegisterHandshakeService(svc daemonapi.HandshakeService) {
	a.d.RegisterHandshakeService(svc)
}

func (a daemonAPIAdapter) TrustedPeers() []daemonapi.HandshakeTrustRecord {
	return a.d.TrustedPeers()
}

func (a daemonAPIAdapter) HandshakeRevokeTrust(nodeID uint32) error {
	return a.d.HandshakeRevokeTrust(nodeID)
}

func (a daemonAPIAdapter) HandshakeSendRequest(nodeID uint32, reason string) error {
	return a.d.HandshakeSendRequest(nodeID, reason)
}

// --- Policy + webhook plugin coordination ----------------------------

func (a daemonAPIAdapter) RegisterPolicyManager(pm daemonapi.PolicyManager) {
	a.d.RegisterPolicyManager(pm)
}

func (a daemonAPIAdapter) SetWebhookURL(url string) {
	a.d.SetWebhookURL(url)
}

func (a daemonAPIAdapter) RegisterWebhookManager(wm daemonapi.WebhookManager) {
	a.d.RegisterWebhookManager(wm)
}
