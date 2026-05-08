// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"context"
	"log/slog"
	"time"
)

// Loop runs the rekey retransmit loop. It scans pendingRekey every
// RekeyRetransmitInterval, retransmits stale entries via
// SendKeyExchangeToNode, and gives up after MaxRekeyAttempts.
//
// Cancel via ctx — typical wiring uses tunnel.done as the cancellation
// source through a tiny adapter goroutine.
func (m *Manager) Loop(ctx context.Context) {
	t := time.NewTicker(RekeyRetransmitInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.RekeyRetransmitTick()
		}
	}
}

// RekeyRetransmitTick is the per-tick body of Loop, split out for direct
// testing without a real ticker. Iterates pendingRekey under
// rkPendingMu, releases it before invoking SendKeyExchangeToNode (which
// re-takes rkPendingMu via MarkPendingRekey — splitting the lock keeps
// rkPendingMu a true leaf).
func (m *Manager) RekeyRetransmitTick() {
	now := time.Now()
	type retry struct {
		peerNodeID uint32
		attempts   int
	}
	var toRetry []retry
	var toGiveUp []uint32

	m.rkPendingMu.Lock()
	for peerNodeID, st := range m.pendingRekey {
		if st.Attempts >= MaxRekeyAttempts+1 {
			toGiveUp = append(toGiveUp, peerNodeID)
			continue
		}
		if now.Sub(st.LastSentAt) < RekeyRetransmitInterval {
			continue
		}
		toRetry = append(toRetry, retry{peerNodeID: peerNodeID, attempts: st.Attempts})
	}
	for _, id := range toGiveUp {
		delete(m.pendingRekey, id)
	}
	m.rkPendingMu.Unlock()

	for _, r := range toRetry {
		slog.Info("rekey retransmit",
			"peer_node_id", r.peerNodeID,
			"attempt", r.attempts+1,
			"max", MaxRekeyAttempts+1)
		// SendKeyExchangeToNode calls MarkPendingRekey, which bumps the
		// counter and lastSentAt — we don't need to do that ourselves.
		m.SendKeyExchangeToNode(r.peerNodeID)
	}
	for _, id := range toGiveUp {
		slog.Warn("rekey retransmit gave up after maxRekeyAttempts",
			"peer_node_id", id, "max", MaxRekeyAttempts+1)
		m.publish("tunnel.rekey_gave_up", map[string]any{
			"peer_node_id": id,
		})
	}
}
