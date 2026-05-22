// SPDX-License-Identifier: AGPL-3.0-or-later

package runtime

import (
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/pilot-protocol/policy"
)

// PolicyRuntime adapts *daemon.Daemon to the policy.Runtime interface.
// Lives here (L12 composition root) so plugins/policy stays free of
// pkg/daemon.
type PolicyRuntime struct{ d *daemon.Daemon }

// NewPolicyRuntime returns a policy.Runtime backed by d.
func NewPolicyRuntime(d *daemon.Daemon) policy.Runtime {
	return PolicyRuntime{d: d}
}

func (r PolicyRuntime) NodeID() uint32 { return r.d.NodeID() }

func (r PolicyRuntime) PublishEvent(topic string, payload map[string]any) {
	r.d.PublishEvent(topic, payload)
}

func (r PolicyRuntime) AdminToken() string { return r.d.AdminToken() }

func (r PolicyRuntime) ListNodes(netID uint16, token string) (map[string]any, error) {
	return r.d.RegConnListNodes(netID, token)
}

func (r PolicyRuntime) SetMemberTags(netID uint16, tags []string) {
	r.d.SetMemberTags(netID, tags)
}

func (r PolicyRuntime) TrustedPeers() []policy.TrustRecord {
	src := r.d.TrustedPeers()
	out := make([]policy.TrustRecord, 0, len(src))
	for _, t := range src {
		out = append(out, policy.TrustRecord{
			NodeID:     t.NodeID,
			PublicKey:  t.PublicKey,
			ApprovedAt: t.ApprovedAt,
			Mutual:     t.Mutual,
			Network:    t.Network,
		})
	}
	return out
}

func (r PolicyRuntime) RevokeTrust(nodeID uint32) error {
	return r.d.HandshakeRevokeTrust(nodeID)
}

func (r PolicyRuntime) SendHandshakeRequest(nodeID uint32, reason string) error {
	return r.d.HandshakeSendRequest(nodeID, reason)
}

// Compile-time guard.
var _ policy.Runtime = PolicyRuntime{}
