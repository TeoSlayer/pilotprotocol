// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRetransmitSSThreshUsesFlightSizeNotCongWin verifies that when 3 dup
// ACKs trigger fast retransmit, SSThresh is set to max(FlightSize/2, 2*SMSS)
// using the actual FlightSize (RFC 5681 §3.2 step 2), not CongWin.
//
// RFC 5681 §2 definition:
//
//	FlightSize = "the amount of data that has been sent but not yet
//	cumulatively acknowledged."
//
// FlightSize = SND.NXT − SND.UNA = sum of ALL bytes in conn.Unacked (whether
// SACK'd or not), because SACK confirmation does not advance SND.UNA.
//
// The current code uses CongWin/2 instead:
//
//	c.SSThresh = c.CongWin / 2   // ← wrong: CongWin is window capacity
//
// CongWin reflects the maximum allowed bytes in flight, not the actual bytes
// outstanding.  When the sender is not filling its window — for example after
// SACK marks several segments as received, reducing BytesInFlight far below
// CongWin — CongWin/2 overestimates SSThresh by the unused window fraction.
//
// Concrete scenario (3 segments in Unacked, 2 SACK'd):
//
//	CongWin = 10*MSS = 40960   (large window, sender not filling it)
//	Unacked: A(4096, not sacked), B(4096, sacked), C(4096, sacked)
//	FlightSize = 3*MSS = 12288 (A + B + C; none are cumulatively ACK'd yet)
//
//	fast retransmit fires (DupAckCount == 3)
//	  bug:  SSThresh = CongWin/2 = 40960/2 = 20480 (5*MSS — uses window capacity)
//	  fix:  SSThresh = max(12288/2, 2*MSS) = max(6144, 8192) = 8192 (2*MSS — uses actual flight)
//
// After fast-recovery exit, CongWin is deflated to SSThresh.  With the bug,
// CongWin resumes from 20480 (5*MSS) — 2.5× larger than the 8192 (2*MSS) that
// RFC 5681 mandates.  The sender re-enters the congestion zone immediately
// instead of recovering conservatively from the measured in-flight data.
//
// Fix: in ProcessAck's fast-retransmit SSThresh halving block, replace
//
//	c.SSThresh = c.CongWin / 2
//
// with a FlightSize loop over all Unacked entries (including SACK'd):
//
//	var flightSize int
//	for _, e := range c.Unacked { flightSize += len(e.data) }
//	c.SSThresh = flightSize / 2
//
// then apply the existing 2*SMSS floor.
//
// GREEN assertion: after fast retransmit with CongWin=10*MSS and FlightSize=3*MSS,
// SSThresh == max(FlightSize/2, 2*SMSS) == 2*SMSS == 8192, NOT CongWin/2 == 20480.
func TestFastRetransmitSSThreshUsesFlightSizeNotCongWin(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7603, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	conn.RetxSend = func(*protocol.Packet) {}
	conn.RetxStop = make(chan struct{})

	const (
		seqA           = uint32(1000)
		seqB           = seqA + MaxSegmentSize
		seqC           = seqB + MaxSegmentSize
		initialCongWin = 10 * MaxSegmentSize // 40960 — window capacity >> FlightSize
		highSSThresh   = 40 * MaxSegmentSize // >> CongWin, not the binding constraint
	)

	// SND.NXT = seqC + MSS so FlightSize = SND.NXT - SND.UNA = 3*MSS = 12288.
	conn.Mu.Lock()
	conn.SendSeq = seqC + MaxSegmentSize
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = initialCongWin
	conn.SSThresh = highSSThresh
	conn.InRecovery = false
	conn.DupAckCount = 2 // one more dup ACK → 3 → fast retransmit fires
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now(), sacked: false},
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now(), sacked: true},
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: time.Now(), sacked: true},
	}
	conn.RetxMu.Unlock()

	// 3rd dup ACK: triggers fast retransmit.
	// RFC 5681 §3.2 step 2: ssthresh = max(FlightSize/2, 2*SMSS).
	// FlightSize = 3*MSS = 12288; FlightSize/2 = 6144 < 2*MSS = 8192 → floor applies.
	// SSThresh must be 8192, NOT CongWin/2 = 20480.
	conn.ProcessAck(seqA, true) // DupAckCount 2→3 → fast retransmit fires

	conn.RetxMu.Lock()
	ssthresh := conn.SSThresh
	conn.RetxMu.Unlock()

	// RFC 5681 §3.2 step 2: ssthresh = max(FlightSize/2, 2*SMSS) = max(6144, 8192) = 8192.
	// Bug: ssthresh = CongWin/2 = 40960/2 = 20480 — 2.5× larger than the RFC value.
	// The in-flight data is 3*MSS (12288 bytes), not 10*MSS (40960); CongWin is the
	// window capacity, not the measured flight size; using it overestimates SSThresh
	// and causes the connection to resume from a rate higher than what caused the loss.
	const (
		flightSize   = 3 * MaxSegmentSize // 12288 — sum of all Unacked
		wantSSThresh = 2 * MaxSegmentSize // max(flightSize/2=6144, 2*MSS=8192)
		badSSThresh  = initialCongWin / 2 // 20480 — what CongWin/2 produces
	)
	if ssthresh != wantSSThresh {
		t.Errorf("fast retransmit with CongWin=%d, FlightSize=%d: SSThresh=%d, want %d "+
			"(max(FlightSize/2=%d, 2*SMSS=%d)); "+
			"bug: SSThresh = CongWin/2 = %d uses window capacity not actual bytes in "+
			"flight; RFC 5681 §3.2 step 2 defines ssthresh in terms of FlightSize "+
			"(SND.NXT − SND.UNA = sum of all Unacked, including SACK'd entries that "+
			"have not been cumulatively acknowledged); when CongWin >> FlightSize "+
			"(sender not filling its window), CongWin/2 overestimates SSThresh by the "+
			"unused window fraction; fix: replace 'c.SSThresh = c.CongWin/2' with a "+
			"loop over all c.Unacked entries to compute FlightSize, then halve that",
			initialCongWin, flightSize, ssthresh, wantSSThresh,
			flightSize/2, 2*MaxSegmentSize, badSSThresh)
	}
}
