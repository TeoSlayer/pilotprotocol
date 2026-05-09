// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRetransmitNoopDoesNotAdjustCongestionState verifies that when
// fastRetransmit returns without sending (because the first non-SACKed entry
// has attempts == MaxRetxAttempts), ProcessAck does NOT:
//   - increment Stats.FastRetx
//   - halve SSThresh
//   - set InRecovery
//   - inflate CongWin
//
// Background: iter-56 added a guard in fastRetransmit that returns early when
// e.attempts >= MaxRetxAttempts. However fastRetransmit returns void, so the
// caller (ProcessAck's DupAckCount==3 branch) cannot tell whether a packet was
// actually sent. It unconditionally executes the three side-effects:
//
//	fastRetx++                                 // over-counted
//	if !c.InRecovery { c.SSThresh = c.CongWin/2; ... }  // phantom halving
//	c.CongWin = c.SSThresh + 3*MaxSegmentSize  // phantom inflation
//
// The phantom adjustments are harmless when the connection is about to be
// killed by the next timeout-RST, but they are still incorrect:
//   - Stats.FastRetx mis-reports a retransmission that never happened.
//   - SSThresh is halved unnecessarily; if a late ACK saves the connection,
//     it starts congestion avoidance from a halved window.
//   - InRecovery blocks a further SSThresh halving for the same episode even
//     though no recovery was actually entered.
//
// Fix: change fastRetransmit to return bool (true = packet sent). In the
// DupAckCount==3 branch, gate fastRetx++ and the three congestion-state
// mutations on the returned bool.
//
// GREEN assertions:
//   - Stats.FastRetx == 0 (no actual fast retransmit happened)
//   - CongWin unchanged from initial value
//   - SSThresh unchanged from initial value
//   - InRecovery still false
func TestFastRetransmitNoopDoesNotAdjustCongestionState(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7550, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	var capturedPkts []*protocol.Packet
	conn.RetxSend = func(pkt *protocol.Packet) {
		p := *pkt
		capturedPkts = append(capturedPkts, &p)
	}
	conn.RetxStop = make(chan struct{})

	const seqA = uint32(1000)
	const initialSSThresh = 20 * MaxSegmentSize

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = seqA + MaxSegmentSize
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = InitialCongWin
	conn.SSThresh = initialSSThresh
	conn.InRecovery = false
	conn.DupAckCount = 0
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize),
		attempts: MaxRetxAttempts, // already at the limit — fastRetransmit must skip
		sentAt:   time.Now().Add(-100 * time.Millisecond),
		sacked:   false,
	}}
	conn.RetxMu.Unlock()

	// 3 dup ACKs trigger ProcessAck's DupAckCount==3 branch → calls fastRetransmit.
	// fastRetransmit returns without sending (MaxRetxAttempts guard from iter-56).
	// The caller must detect the no-op and skip all congestion-state adjustments.
	conn.ProcessAck(seqA, true) // DupAckCount = 1
	conn.ProcessAck(seqA, true) // DupAckCount = 2
	conn.ProcessAck(seqA, true) // DupAckCount = 3 → DupAckCount==3 branch fires

	// Sanity check: iter-56 guard works (no packet sent)
	if len(capturedPkts) != 0 {
		t.Fatalf("fastRetransmit sent %d packet(s); iter-56 guard should prevent any send "+
			"when attempts==MaxRetxAttempts; this test depends on iter-56 being fixed",
			len(capturedPkts))
	}

	conn.RetxMu.Lock()
	congWin := conn.CongWin
	ssthresh := conn.SSThresh
	inRecovery := conn.InRecovery
	conn.RetxMu.Unlock()

	conn.Mu.Lock()
	fastRetxStat := conn.Stats.FastRetx
	conn.Mu.Unlock()

	// Stats.FastRetx must be 0: no packet was sent, so no fast retransmit occurred.
	// Bug: fastRetx++ fires unconditionally → Stats.FastRetx == 1.
	if fastRetxStat != 0 {
		t.Errorf("Stats.FastRetx=%d, want 0; fastRetransmit sent no packet "+
			"(MaxRetxAttempts guard) but fastRetx++ is unconditional in "+
			"ProcessAck's DupAckCount==3 branch; "+
			"fix: make fastRetransmit return bool and gate fastRetx++ on it",
			fastRetxStat)
	}

	// CongWin must be unchanged: no phantom inflation.
	// Bug: c.CongWin = c.SSThresh + 3*MaxSegmentSize fires unconditionally.
	if congWin != InitialCongWin {
		t.Errorf("CongWin=%d after no-op fastRetransmit, want InitialCongWin=%d; "+
			"phantom fast-recovery inflation fired even though no packet was sent; "+
			"fix: gate 'c.CongWin = c.SSThresh + 3*MSS' on fastRetransmit returning true",
			congWin, InitialCongWin)
	}

	// SSThresh must be unchanged: no phantom halving.
	// Bug: 'c.SSThresh = c.CongWin / 2' fires unconditionally when !c.InRecovery.
	if ssthresh != initialSSThresh {
		t.Errorf("SSThresh=%d after no-op fastRetransmit, want %d (initial); "+
			"phantom SSThresh halving fired even though no packet was sent; "+
			"fix: gate the 'c.SSThresh = c.CongWin / 2' halving on fastRetransmit returning true",
			ssthresh, initialSSThresh)
	}

	// InRecovery must remain false: no phantom recovery entry.
	// Bug: 'c.InRecovery = true' fires unconditionally when !c.InRecovery.
	if inRecovery {
		t.Errorf("InRecovery=true after no-op fastRetransmit, want false; " +
			"phantom InRecovery was set even though no packet was sent; " +
			"fix: gate 'c.InRecovery = true' on fastRetransmit returning true",
		)
	}
}
