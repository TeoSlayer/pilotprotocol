// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"log/slog"
	"net"
)

// SendKeyExchangeToNode sends an authenticated key exchange if identity
// is available, otherwise falls back to unauthenticated.
//
// This function carries the single annotated bootstrap-exception site
// (see the marker comment inside the body). After Stage 2 sub-pass 2,
// the canonical home for the marker is here in keyexchange/bootstrap.go;
// layers.yaml's bootstrap_exception.allowed_call_sites tracks this path.
func (m *Manager) SendKeyExchangeToNode(peerNodeID uint32) {
	// BOOTSTRAP-EXCEPTION: bypasses L6 envelope
	// The peer key is not yet established, so the L6 AEAD wrap is
	// impossible here. This is the single annotated bootstrap site
	// whitelisted by layers.yaml's bootstrap_exception block and
	// enforced by tools/check-bootstrap (P8). Do not duplicate this
	// marker elsewhere — the checker fails if more than one site
	// carries it. See docs/architecture/05-VERIFICATION.md §3 P8.
	if m.sender == nil {
		return
	}

	var addr *net.UDPAddr
	if m.addrLookup != nil {
		addr = m.addrLookup(peerNodeID)
	}

	hasIdentity := m.HasIdentity()
	frame := m.BuildUnauthFrame()
	if frame == nil {
		return
	}

	if hasIdentity {
		authFrame := m.BuildAuthFrame()
		if authFrame != nil {
			frame = authFrame
		}
	}

	if err := m.sender(peerNodeID, addr, frame); err != nil {
		slog.Error("send key exchange failed", "peer_node_id", peerNodeID, "error", err)
		return
	}

	// P1-010 tunnel-state half: register that we're waiting on a reply,
	// so rekeyRetransmitLoop can retransmit if the peer's response (or
	// our request) was dropped under loss.
	m.MarkPendingRekey(peerNodeID)
}
