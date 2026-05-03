// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRetransmitSSThreshFloorTwoSMSS verifies that when 3 dup ACKs trigger
// fast retransmit and CongWin / 2 is below 2*MaxSegmentSize, SSThresh is
// raised to 2*MaxSegmentSize (RFC 5681 §3.2 step 2).
//
// RFC 5681 §3.2 step 2:
//
//	ssthresh = max(FlightSize / 2, 2 * SMSS)
//
// The current code applies a floor of 1*MaxSegmentSize (not 2*MaxSegmentSize):
//
//	c.SSThresh = c.CongWin / 2           // = 1*MSS when CongWin = 2*MSS
//	if c.SSThresh < MaxSegmentSize {      // 4096 < 4096 → false → no floor
//	    c.SSThresh = MaxSegmentSize
//	}
//
// When CongWin = 2*MaxSegmentSize (the smallest window that can hold two in-
// flight segments), CongWin/2 = 1*MaxSegmentSize.  The RFC requires
// SSThresh >= 2*MaxSegmentSize, but the floor check uses MaxSegmentSize as
// the bound and fires only when SSThresh < MaxSegmentSize — it never corrects
// the case where SSThresh == MaxSegmentSize.
//
// Consequence: with the floor at 1*SMSS, a connection that has experienced
// repeated congestion on a very small window converges to SSThresh =
// MaxSegmentSize.  When fast-recovery exits (CongWin = SSThresh = 4096), the
// sender can never grow past 1 segment before entering CA.  The RFC requires
// that a connection can always sustain at least a 2-segment window post-
// recovery, so the minimum SSThresh after a multiplicative decrease must be
// 2*SMSS.
//
// Concrete scenario:
//
//	CongWin = 2*MaxSegmentSize = 8192
//	fast retransmit fires (DupAckCount == 3)
//	  bug:  SSThresh = 8192/2 = 4096; floor = MaxSegmentSize; 4096 < 4096 = false
//	        SSThresh = 4096  (1*MSS — below RFC minimum)
//	  fix:  SSThresh = 8192/2 = 4096; floor = 2*MaxSegmentSize; 4096 < 8192 = true
//	        SSThresh = 8192  (2*MSS — RFC minimum satisfied)
//
// Fix: in ProcessAck's fast-retransmit SSThresh halving block (and the
// parallel block in retransmitUnacked), replace:
//
//	if c.SSThresh < MaxSegmentSize { c.SSThresh = MaxSegmentSize }
//
// with:
//
//	if c.SSThresh < 2*MaxSegmentSize { c.SSThresh = 2 * MaxSegmentSize }
//
// GREEN assertion: after fast retransmit with CongWin = 2*MaxSegmentSize,
// SSThresh >= 2*MaxSegmentSize.
func TestFastRetransmitSSThreshFloorTwoSMSS(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7602, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	// Wire a no-op send function so fastRetransmit returns true (otherwise
	// RetxSend==nil causes it to return false and SSThresh halving is skipped).
	conn.RetxSend = func(*protocol.Packet) {}
	conn.RetxStop = make(chan struct{})

	const (
		lastAck      = uint32(1000)
		initialCongWin = 2 * MaxSegmentSize // 8192 — floor scenario
		highSSThresh = 40 * MaxSegmentSize  // >> CongWin, not the binding constraint
	)

	conn.Mu.Lock()
	conn.SendSeq = lastAck + MaxSegmentSize
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = lastAck
	conn.CongWin = initialCongWin
	conn.SSThresh = highSSThresh
	conn.InRecovery = false
	conn.DupAckCount = 2 // one more dup ACK will bring it to 3 → fast retransmit
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{
		{
			seq:      lastAck,
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now(),
			sacked:   false,
		},
	}
	conn.RetxMu.Unlock()

	// 3rd dup ACK: triggers fast retransmit.
	// RFC 5681 §3.2 step 2: ssthresh = max(FlightSize/2, 2*SMSS).
	// With CongWin = 2*MSS, CongWin/2 = 1*MSS < 2*SMSS → floor must apply.
	conn.ProcessAck(lastAck, true) // DupAckCount 2 → 3 → fast retransmit fires

	conn.RetxMu.Lock()
	ssthresh := conn.SSThresh
	conn.RetxMu.Unlock()

	// RFC 5681 §3.2 step 2: ssthresh must be at least 2*SMSS = 2*MaxSegmentSize.
	// Bug: ssthresh = CongWin/2 = MaxSegmentSize; floor check (< MaxSegmentSize)
	// is false; ssthresh stays at MaxSegmentSize — one SMSS below the RFC minimum.
	// Fix: raise floor to 2*MaxSegmentSize so the minimum is satisfied.
	const minSSThresh = 2 * MaxSegmentSize
	if ssthresh < minSSThresh {
		t.Errorf("fast retransmit with CongWin=%d: SSThresh=%d, want >= %d (2*SMSS per RFC 5681 §3.2); "+
			"SSThresh = CongWin/2 = %d; the floor check 'SSThresh < MaxSegmentSize' uses "+
			"1*SMSS (%d) but RFC 5681 §3.2 step 2 requires the minimum to be "+
			"2*SMSS (%d); the floor condition 'SSThresh < MaxSegmentSize' is "+
			"false when SSThresh == MaxSegmentSize, so the RFC minimum is never "+
			"applied when CongWin/2 equals exactly one SMSS; "+
			"fix: change 'if c.SSThresh < MaxSegmentSize' to "+
			"'if c.SSThresh < 2*MaxSegmentSize' in both ProcessAck and retransmitUnacked",
			initialCongWin, ssthresh, minSSThresh,
			initialCongWin/2, MaxSegmentSize, minSSThresh)
	}
}
