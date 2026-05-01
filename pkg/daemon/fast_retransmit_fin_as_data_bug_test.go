// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRetransmitFINEntryAsFlagACK verifies that when 3 dup ACKs fire fast
// retransmit and the first non-sacked Unacked entry is a FIN (isFIN=true),
// fastRetransmit sends a FlagFIN packet — not a FlagACK data packet.
//
// Bug: fastRetransmit always builds the packet with Flags: protocol.FlagACK
// and Payload: e.data, regardless of e.isFIN.  When only the FIN entry
// remains in Unacked (all data was acked, FIN is lost), 3 dup ACKs trigger
// fast retransmit and the FIN is sent as:
//
//	Flags:   FlagACK       (WRONG — should be FlagFIN)
//	Payload: []byte{0}     (WRONG — FIN carries no payload)
//
// The peer receives a 1-byte data packet, not a FIN. Its ACK of that 1-byte
// sequence does not satisfy the FIN handshake (seqAfterOrEqual(ack, seqFIN+1)
// never fires), so the connection stays in FinWait indefinitely.
//
// iter-53 (fix: retransmitUnacked uses e.isFIN) and iter-54 did not update
// fastRetransmit, which has the symmetric responsibility.
//
// GREEN assertion: the fast-retransmitted packet has FlagFIN (not FlagACK)
// and carries no payload.
func TestFastRetransmitFINEntryAsFlagACK(t *testing.T) {
	pm := NewPortManager()
	conn := pm.NewConnection(7530, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	var capturedPkts []*protocol.Packet
	conn.RetxSend = func(pkt *protocol.Packet) {
		p := *pkt
		capturedPkts = append(capturedPkts, &p)
	}
	conn.RetxStop = make(chan struct{})

	// seqFIN: the FIN's sequence number. All data before this was already acked.
	const seqFIN = uint32(5096)

	conn.Mu.Lock()
	conn.State = StateFinWait
	conn.SendSeq = seqFIN + 1 // FIN reserves 1 seq slot
	conn.RecvAck = 0
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	// Simulate: all data was acked (LastAck == seqFIN), only the FIN remains
	// unacked. The peer keeps sending dup ACKs with ack=seqFIN (it never
	// received the FIN but has all data), triggering fast retransmit.
	conn.LastAck = seqFIN
	conn.CongWin = InitialCongWin
	conn.SSThresh = InitialCongWin
	conn.InRecovery = false
	conn.DupAckCount = 0
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{{
		seq:      seqFIN,
		data:     []byte{0}, // FIN sentinel — same as CloseConnection uses
		attempts: 1,
		sentAt:   time.Now().Add(-100 * time.Millisecond), // not past RTO
		sacked:   false,
		isFIN:    true,
	}}
	conn.RetxMu.Unlock()

	// 3 dup ACKs with ack == LastAck (peer acked all data, FIN not yet received).
	conn.ProcessAck(seqFIN, true) // DupAckCount = 1
	conn.ProcessAck(seqFIN, true) // DupAckCount = 2
	conn.ProcessAck(seqFIN, true) // DupAckCount = 3 → fast retransmit fires

	if len(capturedPkts) == 0 {
		t.Fatal("test setup error: fast retransmit did not fire; " +
			"check that BytesInFlight > 0 and RetxSend is wired")
	}

	pkt := capturedPkts[0]

	// The fast-retransmitted packet must carry FlagFIN, not FlagACK.
	// fastRetransmit unconditionally uses FlagACK; it must check e.isFIN.
	if pkt.Flags&protocol.FlagFIN == 0 {
		t.Errorf("fastRetransmit FIN entry: packet Flags=0x%02x does not have FlagFIN; "+
			"fastRetransmit sent the FIN entry as a data packet (FlagACK) "+
			"because it does not check e.isFIN; "+
			"fix: in fastRetransmit, when e.isFIN is true set Flags=FlagFIN and Payload=nil",
			pkt.Flags)
	}

	// Payload must be nil/empty — FIN packets carry no data.
	if len(pkt.Payload) != 0 {
		t.Errorf("fastRetransmit FIN entry: packet Payload len=%d, want 0; "+
			"FIN sentinel data []byte{0} must not be sent as payload",
			len(pkt.Payload))
	}

	// Seq must be the FIN entry's sequence number.
	if pkt.Seq != seqFIN {
		t.Errorf("fastRetransmit FIN entry: packet Seq=%d, want %d", pkt.Seq, seqFIN)
	}
}
