// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRetransmitStopsAtMaxAttempts verifies that fastRetransmit does NOT
// send a packet when the first non-SACKed Unacked entry has already reached
// MaxRetxAttempts.
//
// Bug: fastRetransmit unconditionally increments e.attempts and sends the
// packet without checking whether e.attempts >= MaxRetxAttempts first.
// retransmitUnacked guards its send with:
//
//	if e.attempts >= MaxRetxAttempts { // → send RST, close conn }
//
// fastRetransmit has no symmetric guard.  This produces two problems:
//
//  1. A fast retransmit fires for an entry at attempts == MaxRetxAttempts-1,
//     bumping it to MaxRetxAttempts.  The very next RTO fires RST even though
//     the connection was live enough to receive ACKs — it dies one RTO early.
//
//  2. A fast retransmit fires for an entry already at MaxRetxAttempts (set by
//     a prior timeout that then immediately fired RST — which closed the
//     connection — but the scenario is also reachable if the state is reached
//     via a combination of fast-retransmit + timeout increments without an
//     intervening RST): the entry is re-sent as a "zombie" packet after the
//     connection has conceptually exhausted its retry budget.
//
// GREEN assertion: when the entry has attempts == MaxRetxAttempts, fast
// retransmit (triggered by 3 dup ACKs) sends NO packet.
func TestFastRetransmitStopsAtMaxAttempts(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7540, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	var capturedPkts []*protocol.Packet
	conn.RetxSend = func(pkt *protocol.Packet) {
		p := *pkt
		capturedPkts = append(capturedPkts, &p)
	}
	conn.RetxStop = make(chan struct{})

	const seqA = uint32(1000)

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = seqA + MaxSegmentSize
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	// Segment A has been attempted MaxRetxAttempts times — it has hit the
	// ceiling.  retransmitUnacked would send RST on its next call; fastRetransmit
	// must also refuse to resend it.
	conn.LastAck = seqA
	conn.CongWin = InitialCongWin
	conn.SSThresh = InitialCongWin / 2
	conn.InRecovery = false
	conn.DupAckCount = 0
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize),
		attempts: MaxRetxAttempts,                         // already at the limit
		sentAt:   time.Now().Add(-100 * time.Millisecond), // not past RTO
		sacked:   false,
	}}
	conn.RetxMu.Unlock()

	// 3 dup ACKs with ack == LastAck; BytesInFlight() > 0 so the dup-ACK
	// counter increments and fast retransmit fires on the 3rd.
	conn.ProcessAck(seqA, true) // DupAckCount = 1
	conn.ProcessAck(seqA, true) // DupAckCount = 2
	conn.ProcessAck(seqA, true) // DupAckCount = 3 → fast retransmit fires

	// fastRetransmit must NOT send a packet when attempts == MaxRetxAttempts.
	// Current bug: no guard → packet IS sent (test is RED until fixed).
	// Fix: in fastRetransmit, add:
	//   if e.attempts >= MaxRetxAttempts { return }
	// before e.attempts++ and the packet build.
	if len(capturedPkts) != 0 {
		t.Errorf("fastRetransmit sent %d packet(s) for an entry at MaxRetxAttempts=%d; "+
			"expected 0 — fastRetransmit must not resend when the retry budget is "+
			"exhausted (same guard as retransmitUnacked's 'e.attempts >= MaxRetxAttempts')",
			len(capturedPkts), MaxRetxAttempts)
	}
}
