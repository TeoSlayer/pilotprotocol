// SPDX-License-Identifier: AGPL-3.0-or-later

package handshake

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// Iter-104 coverage for handleConnection (0% baseline) + processMessage
// (47.1% — 9 validation branches, only the happy path was hit). These funcs
// gate all inbound handshake messages on port 444 before dispatching to the
// handleRequest / handleAccept / handleRejectMsg / handleRevokeMsg switch.

// --- handleConnection: closed RecvBuf returns cleanly ---

func TestHandleConnectionClosedRecvBufReturnsCleanly(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	conn := &daemon.Connection{RecvBuf: make(chan []byte)}
	close(conn.RecvBuf) // triggers `ok=false` branch in handleConnection

	done := make(chan struct{})
	go func() {
		hm.handleConnection(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConnection did not return on closed RecvBuf")
	}
}

// --- handleConnection: invalid JSON triggers Unmarshal-error return ---

func TestHandleConnectionInvalidJSONReturnsCleanly(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)

	conn := &daemon.Connection{RecvBuf: make(chan []byte, 1)}
	conn.RecvBuf <- []byte("this is not json at all {{{")

	done := make(chan struct{})
	go func() {
		hm.handleConnection(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConnection did not return on invalid JSON")
	}
}

// --- handleConnection: valid RejectMsg dispatches through to processMessage ---

func TestHandleConnectionValidMsgDispatchesToProcessMessage(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.outgoing[321] = time.Now()

	msg := HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    321,
		Reason:    "nope",
		Timestamp: time.Now().Unix(),
	}
	raw, _ := json.Marshal(&msg)

	conn := &daemon.Connection{RecvBuf: make(chan []byte, 1)}
	conn.RecvBuf <- raw

	done := make(chan struct{})
	go func() {
		hm.handleConnection(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConnection did not return after valid message")
	}

	hm.mu.RLock()
	_, stillOutgoing := hm.outgoing[321]
	hm.mu.RUnlock()
	if stillOutgoing {
		t.Fatal("outgoing[321] should have been cleared by dispatched handleRejectMsg")
	}
}

// --- processMessage: message older than handshakeMaxAge (5min) is rejected ---

func TestProcessMessageTooOldRejected(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.outgoing[11] = time.Now()

	msg := &HandshakeMsg{
		Type:      HandshakeReject, // would delete outgoing[11] if dispatched
		NodeID:    11,
		Timestamp: time.Now().Add(-10 * time.Minute).Unix(), // well past 5min max
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, stillOutgoing := hm.outgoing[11]
	hm.mu.RUnlock()
	if !stillOutgoing {
		t.Fatal("outgoing[11] should be preserved — too-old msg must not dispatch")
	}
}

// --- processMessage: future-dated message (skew > 30s) is rejected ---

func TestProcessMessageFromFutureRejected(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.outgoing[22] = time.Now()

	msg := &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    22,
		Timestamp: time.Now().Add(5 * time.Minute).Unix(), // way past 30s skew
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, stillOutgoing := hm.outgoing[22]
	hm.mu.RUnlock()
	if !stillOutgoing {
		t.Fatal("outgoing[22] should be preserved — future-dated msg must not dispatch")
	}
}

// --- processMessage: replay of identical msg is caught on 2nd dispatch ---

func TestProcessMessageReplayCaughtOnSecondDispatch(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.outgoing[33] = time.Now()

	msg := &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    33,
		Reason:    "replay-test",
		Timestamp: time.Now().Unix(),
	}

	// First call: clean dispatch → outgoing[33] deleted + hash inserted in replaySet
	hm.processMessage(nil, msg)
	hm.mu.RLock()
	_, firstStillOut := hm.outgoing[33]
	hm.mu.RUnlock()
	if firstStillOut {
		t.Fatal("first dispatch: outgoing[33] should have been cleared by handleRejectMsg")
	}
	// Re-seed for the replay assertion.
	hm.mu.Lock()
	hm.outgoing[33] = time.Now()
	hm.mu.Unlock()

	// Second call: replay detected → early return, outgoing[33] NOT mutated
	hm.processMessage(nil, msg)
	hm.mu.RLock()
	_, stillOut := hm.outgoing[33]
	hm.mu.RUnlock()
	if !stillOut {
		t.Fatal("replay dispatch: outgoing[33] should be preserved because replay path returns early")
	}
}

// --- processMessage: pubkey present but signature empty → rejected ---

func TestProcessMessageSigMissingRejected(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.outgoing[44] = time.Now()

	msg := &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    44,
		PublicKey: "aGVsbG8=", // valid b64 (unused — empty sig kicks us out first)
		Signature: "",
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, stillOut := hm.outgoing[44]
	hm.mu.RUnlock()
	if !stillOut {
		t.Fatal("outgoing[44] should be preserved — sig-missing path must not dispatch")
	}
}

// --- processMessage: invalid base64 pubkey encoding → rejected ---

func TestProcessMessageInvalidPubkeyEncodingRejected(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.outgoing[55] = time.Now()

	msg := &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    55,
		PublicKey: "not-valid-base64!!!", // DecodeString errors
		Signature: "aGVsbG8=",
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, stillOut := hm.outgoing[55]
	hm.mu.RUnlock()
	if !stillOut {
		t.Fatal("outgoing[55] should be preserved — invalid-pubkey-encoding must not dispatch")
	}
}

// --- processMessage: invalid base64 signature encoding → rejected ---

func TestProcessMessageInvalidSigEncodingRejected(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.outgoing[66] = time.Now()

	msg := &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    66,
		PublicKey: base64.StdEncoding.EncodeToString([]byte("fake-32-byte-pubkey-padding-xxx")),
		Signature: "not-valid-base64!!!", // DecodeString errors
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, stillOut := hm.outgoing[66]
	hm.mu.RUnlock()
	if !stillOut {
		t.Fatal("outgoing[66] should be preserved — invalid-sig-encoding must not dispatch")
	}
}

// --- processMessage: valid encodings but wrong signature bytes → verify fails ---

func TestProcessMessageSigVerifyFailsRejected(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.outgoing[88] = time.Now()

	// Well-formed but semantically wrong pubkey + sig. crypto.Verify will reject.
	msg := &HandshakeMsg{
		Type:      HandshakeReject,
		NodeID:    88,
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), // all-zero pubkey
		Signature: base64.StdEncoding.EncodeToString(make([]byte, 64)), // all-zero sig
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, stillOut := hm.outgoing[88]
	hm.mu.RUnlock()
	if !stillOut {
		t.Fatal("outgoing[88] should be preserved — sig-verify-fail must not dispatch")
	}
}

// --- processMessage: Revoke dispatch path removes trusted entry ---

func TestProcessMessageRevokeDispatchRemovesTrusted(t *testing.T) {
	t.Parallel()
	hm := newTestHM(t, "")
	t.Cleanup(hm.Stop)
	hm.trusted[99] = &TrustRecord{NodeID: 99}

	msg := &HandshakeMsg{
		Type:      HandshakeRevoke,
		NodeID:    99,
		Timestamp: time.Now().Unix(),
	}
	hm.processMessage(nil, msg)

	hm.mu.RLock()
	_, stillTrusted := hm.trusted[99]
	hm.mu.RUnlock()
	if stillTrusted {
		t.Fatal("trusted[99] should have been removed by dispatched handleRevokeMsg")
	}
}
