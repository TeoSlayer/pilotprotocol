// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// DaemonRuntime adapts a daemon's internals to the plugin's Runtime
// interface. Used by cmd/daemon and cmd/pilotctl _daemon-run as the
// composition glue: both binaries register the policy plugin with
// `policy.NewService(policy.NewDaemonRuntime(d))`.
//
// Lives in plugins/policy (L11) because it imports pkg/daemon (L7) —
// a downward edge that's allowed. The reverse (pkg/daemon importing
// plugins/policy) is the layer violation T2.3 explicitly forbids;
// putting the adapter here keeps daemon free of plugin imports.
type DaemonRuntime struct{ d *daemon.Daemon }

// NewDaemonRuntime returns a Runtime implementation that delegates to
// the given daemon. cmd/daemon (composition root) constructs one and
// passes it to NewService.
func NewDaemonRuntime(d *daemon.Daemon) DaemonRuntime { return DaemonRuntime{d: d} }

func (r DaemonRuntime) NodeID() uint32 { return r.d.NodeID() }

func (r DaemonRuntime) PublishEvent(topic string, payload map[string]any) {
	r.d.PublishEvent(topic, payload)
}

func (r DaemonRuntime) AdminToken() string { return r.d.AdminToken() }

func (r DaemonRuntime) ListNodes(netID uint16, token string) (map[string]any, error) {
	return r.d.RegConnListNodes(netID, token)
}

func (r DaemonRuntime) SetMemberTags(netID uint16, tags []string) {
	r.d.SetMemberTags(netID, tags)
}

func (r DaemonRuntime) TrustedPeers() []TrustRecord {
	src := r.d.TrustedPeers()
	out := make([]TrustRecord, 0, len(src))
	for _, t := range src {
		out = append(out, TrustRecord{
			NodeID:     t.NodeID,
			PublicKey:  t.PublicKey,
			ApprovedAt: t.ApprovedAt,
			Mutual:     t.Mutual,
			Network:    t.Network,
		})
	}
	return out
}

func (r DaemonRuntime) RevokeTrust(nodeID uint32) error {
	return r.d.HandshakeRevokeTrust(nodeID)
}

func (r DaemonRuntime) SendHandshakeRequest(nodeID uint32, reason string) error {
	return r.d.HandshakeSendRequest(nodeID, reason)
}

// Compile-time guard.
var _ Runtime = DaemonRuntime{}
