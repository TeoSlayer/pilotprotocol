// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import "testing"

func TestCheckAndRecordNonceFirstPacketAccepted(t *testing.T) {
	t.Parallel()
	pc := &peerCrypto{}
	if ok := pc.CheckAndRecordNonce(42); !ok {
		t.Fatalf("first packet counter=42 should be accepted")
	}
	if pc.MaxRecvNonce != 42 {
		t.Fatalf("maxRecvNonce = %d, want 42", pc.MaxRecvNonce)
	}
	bit := uint64(42) % replayWindowSize
	if pc.ReplayBitmap[bit/64]&(1<<(bit%64)) == 0 {
		t.Fatalf("replay bit for 42 should be set after first packet")
	}
}

func TestCheckAndRecordNonceMonotonicAccept(t *testing.T) {
	t.Parallel()
	pc := &peerCrypto{}
	for _, c := range []uint64{10, 11, 12, 13} {
		if !pc.CheckAndRecordNonce(c) {
			t.Fatalf("counter=%d should be accepted in monotonic sequence", c)
		}
	}
	if pc.MaxRecvNonce != 13 {
		t.Fatalf("maxRecvNonce = %d, want 13", pc.MaxRecvNonce)
	}
}

func TestCheckAndRecordNonceExactReplayRejected(t *testing.T) {
	t.Parallel()
	pc := &peerCrypto{}
	if !pc.CheckAndRecordNonce(50) {
		t.Fatalf("first 50 should be accepted")
	}
	if pc.CheckAndRecordNonce(50) {
		t.Fatalf("second 50 (exact replay) should be rejected")
	}
}

func TestCheckAndRecordNonceOutOfOrderWithinWindowAccepted(t *testing.T) {
	t.Parallel()
	pc := &peerCrypto{}
	if !pc.CheckAndRecordNonce(100) {
		t.Fatalf("counter=100 should be accepted")
	}
	// 100 is max; 50 is within window of 256 and NOT yet seen
	if !pc.CheckAndRecordNonce(50) {
		t.Fatalf("counter=50 (within window, unseen) should be accepted")
	}
	// Replay of 50 now rejected
	if pc.CheckAndRecordNonce(50) {
		t.Fatalf("replay of 50 should be rejected")
	}
}

func TestCheckAndRecordNonceTooOldRejected(t *testing.T) {
	t.Parallel()
	pc := &peerCrypto{}
	if !pc.CheckAndRecordNonce(1000) {
		t.Fatalf("counter=1000 should be accepted as first")
	}
	// 1000 - 743 = 257 >= windowSize (256) → too old
	if pc.CheckAndRecordNonce(743) {
		t.Fatalf("counter=743 (diff=257, outside window) should be rejected")
	}
	// Boundary: 1000 - 256 = 744, diff=256 → NOT accepted (diff >= windowSize triggers reject)
	if pc.CheckAndRecordNonce(744) {
		t.Fatalf("counter=744 (diff=256, at boundary, outside window) should be rejected")
	}
	// Just inside window: diff=255
	if !pc.CheckAndRecordNonce(745) {
		t.Fatalf("counter=745 (diff=255, inside window) should be accepted")
	}
}

func TestCheckAndRecordNonceLargeJumpClearsBitmap(t *testing.T) {
	t.Parallel()
	pc := &peerCrypto{}
	// Populate a handful of bits in the low range.
	for _, c := range []uint64{1, 2, 3, 4, 5} {
		if !pc.CheckAndRecordNonce(c) {
			t.Fatalf("seeding counter=%d should accept", c)
		}
	}

	// Big jump: shift >= windowSize clears the entire bitmap.
	jump := uint64(replayWindowSize * 10)
	if !pc.CheckAndRecordNonce(jump) {
		t.Fatalf("large-jump counter=%d should be accepted", jump)
	}

	// The only bit that should be set is for `jump`.
	setBits := 0
	for _, word := range pc.ReplayBitmap {
		for word != 0 {
			setBits++
			word &= word - 1
		}
	}
	if setBits != 1 {
		t.Fatalf("after large jump, set bits = %d, want 1 (only the jump nonce)", setBits)
	}
	bit := jump % replayWindowSize
	if pc.ReplayBitmap[bit/64]&(1<<(bit%64)) == 0 {
		t.Fatalf("replay bit for jump (%d mod %d = %d) should be set", jump, replayWindowSize, bit)
	}
}

func TestCheckAndRecordNonceSmallForwardShiftClearsOnlyNewPositions(t *testing.T) {
	t.Parallel()
	pc := &peerCrypto{}
	// Seed with a couple of low-window nonces
	if !pc.CheckAndRecordNonce(10) {
		t.Fatalf("seed 10")
	}
	if !pc.CheckAndRecordNonce(20) {
		t.Fatalf("seed 20")
	}
	// Small forward jump: shift=5 < windowSize
	if !pc.CheckAndRecordNonce(25) {
		t.Fatalf("counter=25 (shift=5) should be accepted")
	}
	// 10 and 20 are still within window (diff <= 15) and were seen — should be rejected as replay.
	if pc.CheckAndRecordNonce(10) {
		t.Fatalf("replay of 10 after small shift should be rejected")
	}
	if pc.CheckAndRecordNonce(20) {
		t.Fatalf("replay of 20 after small shift should be rejected")
	}
}

func TestSetReplayBitIdempotent(t *testing.T) {
	t.Parallel()
	pc := &peerCrypto{}
	pc.SetReplayBit(77)
	before := pc.ReplayBitmap
	pc.SetReplayBit(77)
	after := pc.ReplayBitmap
	if before != after {
		t.Fatalf("setReplayBit is not idempotent: before=%v after=%v", before, after)
	}
	bit := uint64(77) % replayWindowSize
	if pc.ReplayBitmap[bit/64]&(1<<(bit%64)) == 0 {
		t.Fatalf("bit 77 should be set")
	}
}

func TestSetReplayBitIndependentBits(t *testing.T) {
	t.Parallel()
	pc := &peerCrypto{}
	pc.SetReplayBit(1)
	pc.SetReplayBit(65) // different word (65/64 = 1, not 0)
	pc.SetReplayBit(129)
	for _, c := range []uint64{1, 65, 129} {
		bit := c % replayWindowSize
		if pc.ReplayBitmap[bit/64]&(1<<(bit%64)) == 0 {
			t.Fatalf("bit for counter %d not set", c)
		}
	}
}
