// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestFastRecoveryPartialAckNoAIMDInflation verifies that a partial ACK during
// fast recovery does NOT trigger additional AIMD congestion-avoidance growth on
// top of the RFC 5681 §3.2 step 7 window deflation.
//
// RFC 5681 §3.2 step 7 (partial ACK during fast retransmit):
//
//	"Deflate the congestion window by the amount of new data acknowledged.
//	 If the partial ACK acknowledges at least one SMSS of new data, then add
//	 back SMSS bytes to the congestion window."
//
// The RFC specifies only this deflation/add-back formula.  Running the normal
// AIMD congestion-avoidance increment on top is not specified and inflates cwnd
// beyond the recovery window, undoing the purpose of fast recovery.
//
// Bug: ProcessAck's AIMD growth block (lines ~918-947) fires whenever
// bytesAcked > 0, regardless of whether the sender is still in fast recovery.
// A 1-SMSS partial ACK (deflate MSS, add back MSS, net ≈ 0) is followed by:
//
//	CA increment = MaxSegmentSize * bytesAcked / CongWin
//	            = 4096 * 4096 / 20480 ≈ 819 bytes
//
// Concrete scenario:
//
//	SSThresh = 2*MSS = 8192
//	CongWin  = SSThresh + 3*MSS = 5*MSS = 20480   (fast-recovery inflation)
//	DupAckCount = 3, InRecovery=true, FastRecovery=true
//	Partial ACK acknowledges 1 MSS:
//	  step 7 deflation: CongWin -= MSS → 16384; += MSS → 20480  (net 0)
//	  bug: AIMD CA adds 819 → CongWin = 21299
//	  fix: skip AIMD when still in fast recovery → CongWin = 20480
//
// Root cause: the AIMD block condition `if bytesAcked > 0` is not guarded by
// `!c.InRecovery` (or the equivalent `!(wasFastRecovery && wasInRecovery &&
// c.InRecovery)`).  The same bytesAcked that drove step-7 deflation also feeds
// AIMD, effectively counting the ACK twice.
//
// Fix: add a guard to skip AIMD while still in fast recovery (InRecovery==true
// after the recovery-exit check, wasFastRecovery==true):
//
//	if bytesAcked > 0 && !(wasFastRecovery && wasInRecovery && c.InRecovery) {
//	    // AIMD growth
//	}
//
// GREEN assertion: after a 1-SMSS partial ACK during fast recovery,
// CongWin == SSThresh + 3*MaxSegmentSize (step 7 neutral; no AIMD).
func TestFastRecoveryPartialAckNoAIMDInflation(t *testing.T) {
	c := newAckTestConn(t)
	c.RetxSend = func(_ *protocol.Packet) {} // step-6a retransmit is a no-op for this test

	const (
		seqA = uint32(1000)
		seqB = seqA + uint32(MaxSegmentSize) // 5096
		seqC = seqB + uint32(MaxSegmentSize) // 9192
	)
	recoveryPoint := seqC + uint32(MaxSegmentSize) // 13288 — not yet reached by seqB ACK

	c.RetxMu.Lock()
	c.LastAck = seqA
	c.DupAckCount = 3
	c.InRecovery = true
	c.FastRecovery = true
	c.RecoveryPoint = recoveryPoint
	c.SSThresh = 2 * MaxSegmentSize           // 8192
	c.CongWin = c.SSThresh + 3*MaxSegmentSize // 5*MSS = 20480

	now := time.Now()
	c.Unacked = []*retxEntry{
		{seq: seqA, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
	}
	c.RetxMu.Unlock()

	expectedCongWin := c.CongWin // 20480 — step 7: deflate MSS, add back MSS, net 0

	// Partial ACK: acks seqA only (ack=seqB).  RecoveryPoint=seqC+MSS not reached.
	c.ProcessAck(seqB, true)

	c.RetxMu.Lock()
	congWin := c.CongWin
	c.RetxMu.Unlock()

	// RFC 5681 §3.2 step 7: 1-SMSS deflation is neutral (deflate MSS, add back MSS).
	// CongWin must not grow beyond the recovery window value.
	if congWin > expectedCongWin {
		t.Errorf("partial ACK during fast recovery: CongWin=%d, want <=%d; "+
			"RFC 5681 §3.2 step 7 specifies only window deflation — AIMD growth "+
			"must be skipped while still in fast recovery; "+
			"step 7 deflation is neutral for 1-SMSS ACK (deflate MSS, add back MSS); "+
			"bug: AIMD CA adds ~%d bytes on top → CongWin=%d; "+
			"fix: guard AIMD with !(wasFastRecovery && wasInRecovery && c.InRecovery)",
			congWin, expectedCongWin, congWin-expectedCongWin, congWin)
	}
}
