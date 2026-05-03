// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestRetransmitUnackedFinWaitDataSentAsFIN verifies that when a data segment
// times out while the connection is in FIN_WAIT, retransmitUnacked retransmits
// it as a DATA packet (FlagACK), not as a FIN packet.
//
// Bug: retransmitUnacked uses `st == StateFinWait` as a proxy to detect FIN
// entries in Unacked. When multiple entries exist and a DATA entry times out
// before the FIN entry, retransmitUnacked hits the data entry first and sends
// it as FIN — using the data entry's sequence number:
//
//	Unacked = [data(seq=1000, sentAt=old), FIN(seq=5096, sentAt=recent)]
//	state = FinWait
//
//	retransmitUnacked finds data entry (timed out, first in list):
//	  bug:  state==FinWait → sends FIN pkt with Seq=1000  (WRONG seq, wrong type)
//	  fix:  e.isFIN==false  → sends data pkt with Seq=1000 (correct)
//
// The FIN with the wrong seq corrupts the FIN handshake: the peer's ACK of
// seq=1000 does not cover the real FIN (at seq=5096), so the connection
// never fully closes.
//
// GREEN assertion: the retransmitted packet has FlagACK (not FlagFIN) and
// carries the data segment's sequence number.
func TestRetransmitUnackedFinWaitDataSentAsFIN(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	conn := d.ports.NewConnection(7510, protocol.Addr{}, 80)
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })

	var capturedPkts []*protocol.Packet
	conn.RetxSend = func(pkt *protocol.Packet) {
		p := *pkt
		capturedPkts = append(capturedPkts, &p)
	}
	conn.RetxStop = make(chan struct{})

	const (
		seqData = uint32(1000)
		seqFIN  = uint32(1000 + MaxSegmentSize) // FIN sent after the data segment
	)

	// Set state to FinWait — simulates CloseConnection having been called.
	conn.Mu.Lock()
	conn.State = StateFinWait
	conn.SendSeq = seqFIN + 1 // FIN reserves 1 seq slot
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqData
	conn.CongWin = InitialCongWin
	conn.SSThresh = InitialCongWin
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{
		{
			seq:      seqData,
			data:     make([]byte, MaxSegmentSize),
			attempts: 1,
			sentAt:   time.Now().Add(-2 * InitialRTO), // past RTO — will time out
			sacked:   false,
			// isFIN: false (data segment, not FIN)
		},
		{
			seq:      seqFIN,
			data:     []byte{0}, // FIN sentinel (1-byte, as CloseConnection uses)
			attempts: 1,
			sentAt:   time.Now().Add(-100 * time.Millisecond), // NOT past RTO yet
			sacked:   false,
			// isFIN: true after fix
		},
	}
	conn.RetxMu.Unlock()

	// Trigger retransmit — data entry is first and past RTO, FIN is not.
	d.retransmitUnacked(conn)

	if len(capturedPkts) == 0 {
		t.Fatal("test setup error: retransmitUnacked did not send any packet; " +
			"check that the data entry sentAt is older than RTO and RetxSend is wired")
	}

	pkt := capturedPkts[0]

	// The retransmitted packet must be a DATA packet (FlagACK), not FlagFIN.
	// The state==FinWait check in retransmitUnacked incorrectly uses the connection
	// state to identify the FIN entry; after the fix, e.isFIN is the correct check.
	if pkt.Flags&protocol.FlagFIN != 0 {
		t.Errorf("retransmitUnacked FinWait: retransmitted packet has FlagFIN set "+
			"(Flags=0x%02x, Seq=%d); data entry (seq=%d) was sent as FIN because "+
			"retransmitUnacked uses state==FinWait instead of e.isFIN to detect "+
			"FIN entries; fix: add isFIN bool to retxEntry and check e.isFIN",
			pkt.Flags, pkt.Seq, seqData)
	}

	// Additionally: the seq must be the DATA entry's seq, not the FIN seq.
	if pkt.Seq != seqData {
		t.Errorf("retransmitUnacked FinWait: retransmitted packet Seq=%d, want %d "+
			"(data entry seq); FIN entry seq=%d should not have been used",
			pkt.Seq, seqData, seqFIN)
	}
}
