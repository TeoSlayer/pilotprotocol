// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestRTTMeasurementNotCorruptedByTimerRestart verifies that the RFC 6298
// §5.3 timer restart does not corrupt RTT measurements.
//
// RFC 6298 §5.3 requires the retransmission timer to be restarted for the
// oldest remaining unacked segment when SND.UNA advances (a new ACK arrives).
// The current implementation restarts the timer by resetting sentAt:
//
//	e.sentAt = ackNow    // RFC 6298 §5.3 restart (iter-70 fix)
//
// However, sentAt is ALSO used by ProcessAck as the RTT anchor:
//
//	rtt := time.Since(e.sentAt)   // RTT measurement
//	c.updateRTT(rtt)
//
// After the timer restart, e.sentAt = time of the prior ACK, not the
// original send time.  When the segment is later acknowledged, the measured
// RTT is the inter-ACK interval (time between adjacent ACKs), not the actual
// path round-trip time (time from segment transmission to its ACK).
//
// Concrete scenario:
//
//	T_sent     = now - 500ms   (seqB sent 500ms ago)
//	T_ack_A    ≈ now           (ACK for seqA arrives → §5.3 restarts timer: seqB.sentAt = T_ack_A)
//	T_ack_B    ≈ now + 1ms     (ACK for seqB arrives)
//
//	Correct RTT sample: T_ack_B - T_sent ≈ 500ms
//	Bug RTT sample:     T_ack_B - T_ack_A ≈ 1ms  (inter-ACK interval)
//
// Consequence: SRTT collapses to ~1ms; RTO clamps to RTOMin (200ms) but
// SRTT is wrong for every subsequent ACK until the path is re-probed.
//
// Fix: separate the "timer anchor" from the "RTT anchor" in retxEntry.
// Add origSentAt time.Time (set once at TrackSend, never reset); use it
// for RTT measurement.  The timer restart and fastRetransmit continue to
// update sentAt (the timer anchor), leaving origSentAt intact.
//
//	// ProcessAck RTT measurement:
//	rttAnchor := e.origSentAt
//	if rttAnchor.IsZero() {
//	    rttAnchor = e.sentAt // fallback for entries without origSentAt
//	}
//	rtt := time.Since(rttAnchor)
//
// GREEN assertion: after ACKing seqB (which had its sentAt reset by the
// timer restart while origSentAt still points to the 500ms-ago send time),
// SRTT is at least 100ms — demonstrably larger than the 1ms inter-ACK
// interval that would result from the corrupted sentAt.
func TestRTTMeasurementNotCorruptedByTimerRestart(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)

	const (
		seqA = uint32(1000)
		seqB = seqA + MaxSegmentSize // 5096
		seqC = seqB + MaxSegmentSize // 9192
	)

	// seqB was sent 500ms ago; origSentAt tracks this while sentAt will be
	// overwritten by the §5.3 timer restart.
	origSend := time.Now().Add(-500 * time.Millisecond)

	c.LastAck = seqA
	c.Unacked = []*retxEntry{
		// seqA: retransmitted (attempts=2) → Karn's algorithm skips RTT measurement,
		// so seqA's ACK does not pollute SRTT.
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 2,
			sentAt: origSend, origSentAt: origSend},
		// seqB: sent 500ms ago; timer restart will reset sentAt to ~now,
		// but origSentAt must remain at origSend.
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1,
			sentAt: origSend, origSentAt: origSend},
		// seqC: oldest remaining after seqB acked; stays in Unacked throughout.
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1,
			sentAt: origSend, origSentAt: origSend},
	}

	// Step 1: ACK for seqA → seqA removed, RFC 6298 §5.3 restarts timer for seqB
	//         (resets seqB.sentAt to ~now).  seqA has attempts=2 so no RTT sample.
	c.ProcessAck(seqB, true)

	// Step 2: a tiny interval passes — simulates inter-ACK gap on the wire.
	time.Sleep(2 * time.Millisecond)

	// Step 3: ACK for seqB → seqB acked, RTT measured from seqB.
	//   With bug:  RTT = time.Since(seqB.sentAt=~now) ≈ 2ms → SRTT ≈ 2ms
	//   With fix:  RTT = time.Since(seqB.origSentAt=origSend) ≈ 500ms → SRTT ≈ 500ms
	c.ProcessAck(seqC, true)

	// SRTT must reflect the actual path RTT (≥ 100ms), not the inter-ACK gap (≈ 2ms).
	if c.SRTT < 100*time.Millisecond {
		t.Errorf("RTT corrupted by §5.3 timer restart: SRTT=%v, want ≥100ms "+
			"(actual path RTT ≈ 500ms from origSentAt); "+
			"bug: timer restart overwrites sentAt→RTT sample is inter-ACK gap ≈ 2ms; "+
			"fix: add origSentAt to retxEntry, use it in ProcessAck RTT measurement "+
			"instead of sentAt",
			c.SRTT)
	}
}
