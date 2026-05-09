// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestTimeoutSSThreshUsesFlightSizeNotCongWin verifies that when the RTO
// timer fires in retransmitUnacked, SSThresh is set to max(FlightSize/2,
// 2*SMSS) using the actual bytes outstanding (RFC 5681 §3.1 equation 4),
// not CongWin.
//
// RFC 5681 §3.1 equation 4 (same formula as for fast retransmit):
//
//	ssthresh = max(FlightSize / 2, 2 * SMSS)
//	where FlightSize = bytes sent but not yet cumulatively acknowledged.
//
// The current code uses CongWin/2:
//
//	conn.SSThresh = conn.CongWin / 2   // ← wrong: CongWin is window capacity
//
// When the sender is not filling its congestion window (e.g., the application
// is bursty, or the pipe is only partially loaded), CongWin/2 overestimates
// SSThresh by the unused window fraction — exactly the same bug as in the
// fast-retransmit path fixed in iter-64.
//
// Concrete scenario:
//
//	CongWin = 10*MSS = 40960   (large window, only 1 segment outstanding)
//	Unacked: [A: 4096 bytes, timed out, not sacked]
//	FlightSize = 4096 = 1*MSS  (all Unacked, one non-sacked segment)
//
//	RTO fires
//	  bug:  SSThresh = CongWin/2 = 40960/2 = 20480  (5*MSS — uses window capacity)
//	  fix:  SSThresh = max(4096/2, 2*MSS) = max(2048, 8192) = 8192  (2*MSS — actual flight)
//
// After recovery, CongWin = InitialCongWin > SSThresh so the connection
// immediately operates in CA.  With the bug, SSThresh = 20480 means the next
// slow-start phase (if CongWin ever drops below SSThresh) allows 5*MSS of
// exponential growth before switching to CA — 2.5× more aggressive than the
// 2*MSS RFC minimum.
//
// Fix: in retransmitUnacked's `!conn.InRecovery` block, replace
//
//	conn.SSThresh = conn.CongWin / 2
//
// with a FlightSize loop over all Unacked entries (matching the iter-64 fix
// in ProcessAck):
//
//	var flightSize int
//	for _, e := range conn.Unacked { flightSize += len(e.data) }
//	conn.SSThresh = flightSize / 2
//
// then apply the existing 2*SMSS floor.
//
// GREEN assertion: after an RTO retransmit with CongWin=10*MSS and
// FlightSize=1*MSS, SSThresh == max(FlightSize/2, 2*SMSS) == 8192, NOT
// CongWin/2 == 20480.
func TestTimeoutSSThreshUsesFlightSizeNotCongWin(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	conn := d.ports.NewConnection(7604, protocol.Addr{}, 80)
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
		seqA           = uint32(1000)
		initialCongWin = 10 * MaxSegmentSize // 40960 — window capacity >> FlightSize
		highSSThresh   = 40 * MaxSegmentSize // >> CongWin, not the binding constraint
	)

	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = seqA + MaxSegmentSize
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	conn.LastAck = seqA
	conn.CongWin = initialCongWin
	conn.SSThresh = highSSThresh
	conn.InRecovery = false
	conn.DupAckCount = 0
	conn.RTO = InitialRTO
	// Only 1*MSS in Unacked: FlightSize = 4096, much less than CongWin = 40960.
	conn.Unacked = []*retxEntry{{
		seq:      seqA,
		data:     make([]byte, MaxSegmentSize), // 1*MSS = 4096 bytes
		attempts: 1,
		sentAt:   time.Now().Add(-2 * InitialRTO), // timed out
		sacked:   false,
	}}
	conn.RetxMu.Unlock()

	// Fire the RTO retransmit.
	d.retransmitUnacked(conn)

	if retxSent == 0 {
		t.Fatal("test setup error: retransmitUnacked did not fire; check sentAt and RTO")
	}

	conn.RetxMu.Lock()
	ssthresh := conn.SSThresh
	conn.RetxMu.Unlock()

	// RFC 5681 §3.1 eq. 4: ssthresh = max(FlightSize/2, 2*SMSS).
	// FlightSize = 1*MSS = 4096; FlightSize/2 = 2048 < 2*MSS = 8192 → floor.
	// Bug: ssthresh = CongWin/2 = 40960/2 = 20480 — uses window capacity, not
	// actual bytes outstanding.
	const (
		flightSizeBytes = MaxSegmentSize     // 4096 — only entry in Unacked
		wantSSThresh    = 2 * MaxSegmentSize // max(4096/2=2048, 2*MSS=8192)
		badSSThresh     = initialCongWin / 2 // 20480 — CongWin/2 (wrong)
	)
	if ssthresh != wantSSThresh {
		t.Errorf("RTO retransmit with CongWin=%d, FlightSize=%d: SSThresh=%d, want %d "+
			"(max(FlightSize/2=%d, 2*SMSS=%d)); "+
			"bug: SSThresh = CongWin/2 = %d uses window capacity not actual bytes "+
			"outstanding; RFC 5681 §3.1 eq. 4 defines ssthresh in terms of FlightSize "+
			"(sum of all Unacked entries); fix: replace 'conn.SSThresh = conn.CongWin/2' "+
			"with a loop over conn.Unacked, matching the iter-64 fix in ProcessAck",
			initialCongWin, flightSizeBytes, ssthresh, wantSSThresh,
			flightSizeBytes/2, 2*MaxSegmentSize, badSSThresh)
	}
}
