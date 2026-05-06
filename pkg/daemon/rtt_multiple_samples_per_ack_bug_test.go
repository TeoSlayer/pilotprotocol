// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestProcessAckTakesOnlyOneRTTSamplePerACK verifies that a single cumulative
// ACK event produces exactly one RTT measurement, not one per acked segment.
//
// Bug (current): ProcessAck iterates over all acked entries and calls
// updateRTT for every entry with attempts==1:
//
//	for _, e := range c.Unacked {
//	    if seqAfterOrEqual(ack, endSeq) {
//	        if e.attempts == 1 {
//	            rtt := time.Since(e.sentAt)
//	            c.updateRTT(rtt)   // ← called N times for N acked segments
//	        }
//	    }
//	}
//
// The comment above the loop says "update RTT from the first one" — the
// intended behaviour — but the implementation is missing a guard that stops
// after the first call.
//
// RFC 6298 §2 specifies that RTT is updated using ONE measurement per ACK.
// Taking N samples per ACK event biases SRTT toward the most-recently-sent
// acked segment (which has the smallest RTT in the batch) and inflates
// RTTVAR with within-batch variance that should not count as path-level
// variation.
//
// Concrete harm: suppose two segments are sent 990 ms apart (seg1 at T=0,
// seg2 at T=990 ms) and a single cumulative ACK arrives at T=1000 ms:
//   - seg1 RTT = 1000 ms
//   - seg2 RTT =   10 ms
//
// With the bug (two updateRTT calls starting from SRTT=0):
//   - Call 1: SRTT = 1000 ms, RTTVAR = 500 ms
//   - Call 2: diff = |1000-10| = 990 ms
//     RTTVAR = 500*3/4 + 990/4 = 375+247.5 = 622.5 ms
//     SRTT   = 1000*7/8 + 10/8 = 875+1.25  = 876.25 ms
//     → SRTT ≈ 876 ms, pulled down by the short-RTT segment
//
// With the fix (one updateRTT call using the first/oldest acked segment):
//   - SRTT = 1000 ms (first measurement, set directly per RFC 6298 §2.2)
//
// GREEN assertion: after a cumulative ACK covering two segments whose RTTs
// differ by 990 ms, SRTT is close to the oldest segment's RTT (≥ 950 ms).
// Against unpatched code SRTT ≈ 876 ms — pulled below 950 ms by the second
// call — and the assertion fails.
func TestProcessAckTakesOnlyOneRTTSamplePerACK(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7360, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const seg1RTT = 1000 * time.Millisecond
	const seg2RTT = 10 * time.Millisecond
	const segLen = 100

	conn.RetxMu.Lock()
	conn.SRTT = 0 // first measurement path: sets SRTT = R directly (RFC 6298 §2.2)
	conn.RTTVAR = 0
	conn.RTO = InitialRTO
	conn.LastAck = 5000
	conn.Unacked = []*retxEntry{
		// Oldest segment — large RTT.  Should be the sole RTT sample.
		{seq: 5000, data: make([]byte, segLen), attempts: 1, sentAt: time.Now().Add(-seg1RTT)},
		// Recent segment — small RTT.  Must NOT contribute an extra updateRTT call.
		{seq: 5100, data: make([]byte, segLen), attempts: 1, sentAt: time.Now().Add(-seg2RTT)},
	}
	conn.RetxMu.Unlock()

	// Single cumulative ACK covering both segments.
	conn.ProcessAck(5000+2*segLen, true)

	conn.RetxMu.Lock()
	srtt := conn.SRTT
	conn.RetxMu.Unlock()

	// FIXED: one RTT sample → SRTT ≈ seg1RTT = 1000 ms.
	// BUG:   two RTT samples → SRTT ≈ 876 ms (pulled down toward seg2's 10 ms RTT).
	// Threshold 950 ms gives ≥74 ms gap against the buggy value; timing jitter
	// on seg1RTT is ≤5 ms in practice, keeping the fix well above the threshold.
	const minExpectedSRTT = 950 * time.Millisecond
	if srtt < minExpectedSRTT {
		t.Errorf("ProcessAck took multiple RTT samples from one ACK event: SRTT=%v, want >= %v; "+
			"the cumulative ACK acked 2 segments (RTTs ~%v and ~%v); "+
			"updateRTT was called %d time(s) — once per acked segment instead of once per ACK; "+
			"RFC 6298 §2 requires at most one RTT measurement per ACK to avoid "+
			"biasing SRTT toward short-RTT late-in-batch segments; "+
			"fix: set a rttUpdated bool and only call updateRTT once per ProcessAck call",
			srtt, minExpectedSRTT, seg1RTT, seg2RTT, 2)
	}
}
