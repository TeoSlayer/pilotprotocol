// SPDX-License-Identifier: AGPL-3.0-or-later

package routing

import (
	"errors"
	"syscall"
	"time"
)

// RecordDirectRecv stamps the lastDirectRecv timestamp for a peer. Called
// from the L7 handleEncrypted path after a successful direct (non-beacon)
// decrypt. Also clears firstOutboundSend since the direct path is confirmed.
func (m *Manager) RecordDirectRecv(nodeID uint32, t time.Time) {
	m.mu.Lock()
	m.lastDirectRecv[nodeID] = t
	delete(m.firstOutboundSend, nodeID)
	m.mu.Unlock()
}

// HasDirectRecv reports whether we've ever recorded a direct receipt for
// the peer. Used by tests asserting RemovePeer cleanup.
func (m *Manager) HasDirectRecv(nodeID uint32) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.lastDirectRecv[nodeID]
	return ok
}

// LastDirectRecv returns the recorded timestamp (zero value if none).
func (m *Manager) LastDirectRecv(nodeID uint32) time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastDirectRecv[nodeID]
}

// RecordOutboundSend stamps the lastOutboundSend timestamp for a peer.
// Also sets firstOutboundSend on the very first write (never updated
// after that), which gives MaybeFlipBlackhole a baseline for peers
// that have never been heard from on the direct path.
// Used by NAT-keepalive logic and blackhole detection.
func (m *Manager) RecordOutboundSend(nodeID uint32, t time.Time) {
	m.mu.Lock()
	m.lastOutboundSend[nodeID] = t
	if _, ok := m.firstOutboundSend[nodeID]; !ok {
		m.firstOutboundSend[nodeID] = t
	}
	m.mu.Unlock()
}

// LastOutboundSend returns the last recorded outbound timestamp.
func (m *Manager) LastOutboundSend(nodeID uint32) (time.Time, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.lastOutboundSend[nodeID]
	return t, ok
}

// ClearSendErrCount drops accumulated ICMP-unreachable errors for a peer.
// Called after a successful inbound decrypt — proof the peer is alive.
func (m *Manager) ClearSendErrCount(nodeID uint32) {
	m.mu.Lock()
	delete(m.sendErrCount, nodeID)
	m.mu.Unlock()
}

// SendErrCount returns the current consecutive-error count.
func (m *Manager) SendErrCount(nodeID uint32) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sendErrCount[nodeID]
}

// BlackholeMissCount returns the current consecutive-miss count.
func (m *Manager) BlackholeMissCount(nodeID uint32) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.blackholeMissCount[nodeID]
}

// HandleSendError records an ICMP-unreachable error and may flip the
// peer to relay mode if the threshold is reached. Returns true if the
// peer was newly flipped to relay (caller logs/publishes).
//
// Non-ICMP errors (generic write failure, EAGAIN, etc.) are ignored.
func (m *Manager) HandleSendError(nodeID uint32, err error) (flipped bool, count int) {
	if !isICMPUnreachable(err) {
		return false, 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendErrCount[nodeID]++
	count = m.sendErrCount[nodeID]
	if count >= SendErrThreshold && !m.relayPeers[nodeID] {
		if len(m.relayPeers) < MaxRelayPeers {
			m.relayPeers[nodeID] = true
			m.relayPinned[nodeID] = true
			m.sendErrCount[nodeID] = 0
			flipped = true
		}
	}
	return flipped, count
}

// MaybeFlipBlackhole evaluates the blackhole heuristic. Caller invokes
// before sending a frame. Returns shouldRelay=true if the peer is now
// in relay mode (either because it already was, or because the
// heuristic just tripped). flipped=true means this call did the flip.
func (m *Manager) MaybeFlipBlackhole(nodeID uint32) (shouldRelay, flipped bool, silentFor time.Duration, misses int) {
	m.mu.RLock()
	relay := m.relayPeers[nodeID]
	bAddr := m.beaconAddr
	lastRecv, hasRecv := m.lastDirectRecv[nodeID]
	firstSend, hasSent := m.firstOutboundSend[nodeID]
	m.mu.RUnlock()

	if relay {
		return true, false, 0, 0
	}
	if bAddr == nil {
		return false, false, 0, 0
	}
	if hasRecv {
		// Established peer: measure silence since last direct receipt.
		silentFor = time.Since(lastRecv)
	} else if hasSent {
		// Brand-new peer (no direct recv yet): measure silence since
		// we first sent to them. This lets the blackhole heuristic fire
		// for new peers on symmetric-NAT paths where the direct reply
		// can never reach us — without this, !hasRecv would suppress
		// blackhole detection forever and the peer would never flip to relay.
		silentFor = time.Since(firstSend)
	} else {
		return false, false, 0, 0
	}
	if silentFor <= DirectBlackholeThreshold {
		return false, false, 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Re-check under write lock to avoid racing with ClearRelayOnDirect
	if m.relayPeers[nodeID] {
		return true, false, 0, 0
	}
	m.blackholeMissCount[nodeID]++
	misses = m.blackholeMissCount[nodeID]
	if misses >= BlackholeMissesRequired {
		m.relayPeers[nodeID] = true
		m.relayPinned[nodeID] = true
		m.blackholeMissCount[nodeID] = 0
		return true, true, silentFor, misses
	}
	return false, false, silentFor, misses
}

// isICMPUnreachable returns true if err is one of the syscall errors
// the Linux kernel surfaces on a subsequent UDP send after receiving
// an ICMP unreachable from the peer's stack.
func isICMPUnreachable(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}
