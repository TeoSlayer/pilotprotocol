// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
	"time"
)

// fakePC builds a minimal peerCrypto with a real AEAD so encryptFrame works.
func fakePC(t *testing.T) *peerCrypto {
	t.Helper()
	key := make([]byte, 32) // zero key — fine for tests, never reaches the wire here
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	return &peerCrypto{aead: gcm, ready: true}
}

// TestRecordSalvageBasic verifies plaintext is recorded and copied (not
// referenced).
func TestRecordSalvageBasic(t *testing.T) {
	tm := NewTunnelManager()
	pc := fakePC(t)

	plaintext := []byte("hello-task-frame")
	tm.recordSalvage(pc, plaintext)

	pc.salvageMu.Lock()
	defer pc.salvageMu.Unlock()
	if got := len(pc.salvage); got != 1 {
		t.Fatalf("salvage len = %d, want 1", got)
	}
	if string(pc.salvage[0].plaintext) != "hello-task-frame" {
		t.Fatalf("salvage plaintext mismatch: %q", pc.salvage[0].plaintext)
	}

	// Mutate the original and confirm salvage holds an independent copy.
	plaintext[0] = 'X'
	if pc.salvage[0].plaintext[0] == 'X' {
		t.Fatal("salvage referenced caller's buffer instead of copying")
	}
}

// TestRecordSalvageBoundedBySize ensures the ring buffer stops at
// salvageMaxEntries and drops oldest first.
func TestRecordSalvageBoundedBySize(t *testing.T) {
	tm := NewTunnelManager()
	pc := fakePC(t)

	for i := 0; i < salvageMaxEntries+10; i++ {
		tm.recordSalvage(pc, []byte{byte(i)})
	}

	pc.salvageMu.Lock()
	defer pc.salvageMu.Unlock()
	if got := len(pc.salvage); got != salvageMaxEntries {
		t.Fatalf("salvage len = %d, want %d", got, salvageMaxEntries)
	}
	// Oldest should have been dropped — first entry is byte(10).
	if pc.salvage[0].plaintext[0] != byte(10) {
		t.Fatalf("oldest not dropped: head = %d, want 10", pc.salvage[0].plaintext[0])
	}
}

// TestRecordSalvageBoundedByAge ensures aged entries are trimmed.
func TestRecordSalvageBoundedByAge(t *testing.T) {
	tm := NewTunnelManager()
	pc := fakePC(t)

	// Manually inject an aged entry past the cutoff.
	pc.salvage = []salvageEntry{
		{plaintext: []byte("old"), when: time.Now().Add(-2 * salvageMaxAge)},
	}
	// New record should trim the aged one.
	tm.recordSalvage(pc, []byte("fresh"))

	pc.salvageMu.Lock()
	defer pc.salvageMu.Unlock()
	if got := len(pc.salvage); got != 1 {
		t.Fatalf("salvage len = %d, want 1 (aged trimmed + 1 new)", got)
	}
	if string(pc.salvage[0].plaintext) != "fresh" {
		t.Fatalf("kept wrong entry: %q", pc.salvage[0].plaintext)
	}
}

// TestRecordSalvageNilPCIsNoop guards against nil deref on early callers.
func TestRecordSalvageNilPCIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	tm.recordSalvage(nil, []byte("anything"))
	// no panic = pass
}

// TestReplaySalvageNilArgsIsNoop guards every nil branch.
func TestReplaySalvageNilArgsIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	pc := fakePC(t)
	tm.replaySalvage(nil, pc, 1, nil) // oldPC nil
	tm.replaySalvage(pc, nil, 1, nil) // newPC nil
	tm.replaySalvage(pc, pc, 1, nil)  // addr nil
	// no panic = pass
}

// TestReplaySalvageEmptyOldIsNoop confirms the early-return when nothing
// was buffered.
func TestReplaySalvageEmptyOldIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	old := fakePC(t)
	new := fakePC(t)
	// no recordSalvage, so old.salvage is empty
	tm.replaySalvage(old, new, 42, nil)
	// no panic, no writeFrame attempt = pass
}

// TestRecordSalvageHoldsAcrossMultipleEntries confirms the buffer
// retains entries in FIFO order across many records.
func TestRecordSalvageHoldsAcrossMultipleEntries(t *testing.T) {
	tm := NewTunnelManager()
	pc := fakePC(t)

	tm.recordSalvage(pc, []byte("a"))
	tm.recordSalvage(pc, []byte("b"))
	tm.recordSalvage(pc, []byte("c"))

	pc.salvageMu.Lock()
	defer pc.salvageMu.Unlock()
	if len(pc.salvage) != 3 {
		t.Fatalf("salvage len = %d, want 3", len(pc.salvage))
	}
	for i, want := range []string{"a", "b", "c"} {
		if string(pc.salvage[i].plaintext) != want {
			t.Fatalf("salvage[%d] = %q, want %q", i, pc.salvage[i].plaintext, want)
		}
	}
	// Note: replaySalvage's wire side (encrypt + writeFrame) is exercised
	// by the integration test test_tunnel_desync_recovery.sh, which
	// reproduces a real peer restart and asserts data lands.
}
