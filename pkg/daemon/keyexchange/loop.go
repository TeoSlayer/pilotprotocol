// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"context"
	"log/slog"
	"time"
)

// maxRetransmitsPerTick caps how many pending key exchanges are
// retransmitted in a single tick. Without this, sending to hundreds of
// peers simultaneously causes all their retransmits to fire in one tight
// loop every RekeyRetransmitInterval, flooding the UDP socket. Uncapped
// peers are simply skipped this tick and picked up in the next one; with
// MaxRekeyAttempts=5 and RekeyRetransmitInterval=4s we have 20s of
// budget — enough for thousands of peers at 64/tick.
const maxRetransmitsPerTick = 64

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
		m.rekeyGaveUp[id] = now // cooldown: block immediate restart
	}
	// Prune expired gave-up entries to prevent unbounded map growth.
	for id, t := range m.rekeyGaveUp {
		if now.Sub(t) >= rekeyGaveUpCooldown {
			delete(m.rekeyGaveUp, id)
		}
	}
	m.rkPendingMu.Unlock()

	// Fire the gave-up hook for each peer we just abandoned — OUTSIDE the
	// lock (the daemon's handler does registry I/O). This is the only
	// recovery signal for a desynced peer: it is no longer Ready, so the
	// inbound-silence path watchdog can't see it; the hook triggers a full
	// path reset (fresh resolve + hole-punch).
	if m.onGaveUp != nil {
		for _, id := range toGiveUp {
			m.onGaveUp(id)
		}
	}

	// Cap retransmits per tick to prevent UDP flooding when many peers
	// are pending simultaneously. Remaining entries are retried next tick.
	if len(toRetry) > maxRetransmitsPerTick {
		toRetry = toRetry[:maxRetransmitsPerTick]
	}

	for _, r := range toRetry {
		slog.Debug("rekey retransmit",
			"peer_node_id", r.peerNodeID,
			"attempt", r.attempts+1,
			"max", MaxRekeyAttempts+1)
		// Cross-layer policy hook: lets tunnel.go flip the peer's
		// routing path (e.g. to relay) before this attempt goes out.
		// Receives the upcoming attempt count (r.attempts is the
		// count BEFORE this send; the +1 reflects what we're about
		// to do). Nil-safe.
		if m.preRetx != nil {
			m.preRetx(r.peerNodeID, r.attempts+1)
		}
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
