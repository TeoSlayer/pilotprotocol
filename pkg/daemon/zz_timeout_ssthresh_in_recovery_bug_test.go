// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestTimeoutDuringFastRecoveryRecomputesSSThresh verifies that when the
// retransmission timer fires while the connection is already in fast
// recovery (InRecovery == true), ssthresh is re-set to
// max(FlightSize/2, 2*SMSS) per RFC 5681 §3.1, rather than left at its
// fast-retransmit value.
//
// RFC 5681 §3.1 (timeout):
//
//	"When the retransmission timer expires, do the following:
//	  (1) Set ssthresh to no more than the value given in equation (4):
//	      ssthresh = max(FlightSize / 2, 2*SMSS)"
//
// "When the retransmission timer expires" is unconditional — no exception
// for connections already in fast recovery.  The current code guards the
// entire ssthresh+InRecovery+RecoveryPoint block with:
//
//	if !conn.InRecovery { … }
//
// so when a timeout fires during an active fast-recovery episode, ssthresh
// is not recomputed.  The connection re-enters slow start with the old
// (larger) ssthresh and overshoots, violating the TCP spec.
//
// Concrete scenario:
//
//	InRecovery  = true
//	SSThresh    = 5*MSS = 20480  (set by fast retransmit from a larger window)
//	CongWin     = SSThresh + 3*MSS = 32768
//	Unacked     = [seqA: 1*MSS, timed out]
//	FlightSize  = 1*MSS = 4096
//
//	Timeout fires →
//	  RFC 5681 §3.1: SSThresh = max(4096/2, 2*4096) = max(2048, 8192) = 8192
//	  bug: SSThresh unchanged = 20480 (5*MSS)
//
// Fix: in retransmitUnacked, move the ssthresh computation out of the
// !InRecovery guard so it runs unconditionally on every timeout expiry:
//
//	var flightSize int
//	for _, e := range conn.Unacked {
//	    flightSize += len(e.data)
//	}
//	conn.SSThresh = flightSize / 2
//	if conn.SSThresh < 2*MaxSegmentSize {
//	    conn.SSThresh = 2 * MaxSegmentSize
//	}
//	conn.InRecovery = true
//	conn.RecoveryPoint = sendSeq
//
// GREEN assertion: after an RTO expiry with InRecovery=true and FlightSize=1*MSS,
// SSThresh == 2*MaxSegmentSize (8192), not the stale 5*MSS = 20480.
func TestTimeoutDuringFastRecoveryRecomputesSSThresh(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	conn := d.ports.NewConnection(7607, protocol.Addr{}, 80)
	t.Cleanup(func() {
		conn.Mu.Lock()
		conn.State = StateClosed
		conn.Mu.Unlock()
		d.ports.RemoveConnection(conn.ID)
	})

	var retxSent int
	conn.RetxSend = func(*protocol.Packet) { retxSent++ }
	conn.RetxStop = make(chan struct{})

	const (
		seqA                 = uint32(1000)
		fastRecoverySSThresh = 5 * MaxSegmentSize // 20480 — from a larger flightSize
		fastRecoveryCongWin  = fastRecoverySSThresh + 3*MaxSegmentSize
	)

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = seqA + MaxSegmentSize
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.SSThresh = fastRecoverySSThresh
	conn.CongWin = fastRecoveryCongWin
	conn.InRecovery = true // already in fast recovery
	conn.DupAckCount = 3
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize), // FlightSize = 1*MSS
		attempts: 1,
		sentAt:   time.Now().Add(-2 * InitialRTO), // timed out
		sacked:   false,
	}}
	conn.RetxMu.Unlock()

	d.retransmitUnacked(conn)

	if retxSent == 0 {
		t.Fatal("test setup error: retransmitUnacked did not fire; check sentAt and RTO")
	}

	conn.RetxMu.Lock()
	ssthresh := conn.SSThresh
	conn.RetxMu.Unlock()

	// RFC 5681 §3.1: ssthresh = max(FlightSize/2, 2*SMSS)
	//              = max(4096/2, 8192) = max(2048, 8192) = 8192 = 2*MaxSegmentSize
	// Bug: ssthresh = 20480 (5*MSS) — the stale fast-recovery value.
	wantSSThresh := 2 * MaxSegmentSize // 8192
	if ssthresh != wantSSThresh {
		t.Errorf("timeout during fast recovery: SSThresh=%d, want %d "+
			"(RFC 5681 §3.1: ssthresh=max(FlightSize/2,2*SMSS)=max(%d,%d)=%d); "+
			"bug: ssthresh left at fast-recovery value %d; "+
			"fix: remove !InRecovery guard around ssthresh computation in retransmitUnacked",
			ssthresh, wantSSThresh,
			MaxSegmentSize/2, 2*MaxSegmentSize, wantSSThresh,
			fastRecoverySSThresh)
	}
}
