// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// handleHandshake sub-command dispatch coverage.
//
// After T3.3 the handshake manager moved to plugins/handshake; the
// daemon ipc tests use a fake HandshakeService below to drive the
// dispatch paths without pulling the plugin in (which would be an
// L7→L11 upward import).

// fakeHandshakeService is a minimal in-memory HandshakeService used to
// exercise the daemon ipc handler. Tests seed trustedRecs / pendingRecs
// directly and assert that the handler dispatches into the matching
// method. errors map allows the per-method error injection used by
// TestHandleHandshakeRevokeNotTrustedSendsError.
type fakeHandshakeService struct {
	mu          sync.Mutex
	trustedRecs []HandshakeTrustRecord
	pendingRecs []HandshakePendingRecord
	// per-method canned errors (nil = success path)
	sendErr    error
	approveErr error
	rejectErr  error
	revokeErr  error

	stopped bool
}

func (f *fakeHandshakeService) IsTrusted(nodeID uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.trustedRecs {
		if r.NodeID == nodeID {
			return true
		}
	}
	return false
}

func (f *fakeHandshakeService) TrustedPeers() []HandshakeTrustRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]HandshakeTrustRecord(nil), f.trustedRecs...)
}

func (f *fakeHandshakeService) PendingRequests() []HandshakePendingRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]HandshakePendingRecord(nil), f.pendingRecs...)
}

func (f *fakeHandshakeService) PendingCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pendingRecs)
}

func (f *fakeHandshakeService) SendRequest(uint32, string) error     { return f.sendErr }
func (f *fakeHandshakeService) ApproveHandshake(uint32) error        { return f.approveErr }
func (f *fakeHandshakeService) RejectHandshake(uint32, string) error { return f.rejectErr }

func (f *fakeHandshakeService) RevokeTrust(nodeID uint32) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.trustedRecs[:0]
	found := false
	for _, r := range f.trustedRecs {
		if r.NodeID == nodeID {
			found = true
			continue
		}
		out = append(out, r)
	}
	f.trustedRecs = out
	if !found {
		return fmt.Errorf("node %d was not trusted", nodeID)
	}
	return nil
}

func (f *fakeHandshakeService) WaitForTrust(nodeID uint32, _ time.Duration) bool {
	return f.IsTrusted(nodeID)
}

func (f *fakeHandshakeService) ProcessRelayedRequest(uint32, string) {}
func (f *fakeHandshakeService) ProcessRelayedApproval(uint32)        {}
func (f *fakeHandshakeService) ProcessRelayedRejection(uint32)       {}
func (f *fakeHandshakeService) Stop()                                { f.stopped = true }

// installFakeHandshake replaces d.handshakes with a fresh fake. The
// returned fake is the value tests inspect / mutate before / after the
// dispatch.
func installFakeHandshake(d *Daemon) *fakeHandshakeService {
	fs := &fakeHandshakeService{}
	d.RegisterHandshakeService(fs)
	return fs
}

func TestHandleHandshakeSendMissingNodeIDSendsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	installFakeHandshake(d)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, 0, []byte{SubHandshakeSend, 0x00, 0x00}) // only 3 bytes of rest (need 4)
	})
	assertErrorReply(t, reply, "handshake request: missing node_id")
}

func TestHandleHandshakeSendAlreadyTrustedRepliesOK(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	fs := installFakeHandshake(d)
	// Seed the trusted list so a SendRequest dispatch with that node ID returns
	// the success path. The fake's SendRequest returns nil unconditionally;
	// trusting the peer additionally is a defensive belt-and-braces.
	fs.trustedRecs = []HandshakeTrustRecord{{
		NodeID:     0xDEADBEEF,
		ApprovedAt: time.Now(),
	}}

	s := d.ipc
	ic, client := newIPCTestConn(t)

	// [SubHandshakeSend][4-byte node_id][justification...]
	payload := []byte{SubHandshakeSend, 0xDE, 0xAD, 0xBE, 0xEF, 'h', 'i'}
	reply := runHandler(t, client, func() { s.handleHandshake(ic, 0, payload) })

	if reply[0] != CmdHandshakeOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdHandshakeOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if r["status"] != "sent" {
		t.Fatalf("status = %v, want sent", r["status"])
	}
	if uint32(r["node_id"].(float64)) != 0xDEADBEEF {
		t.Fatalf("node_id = %v, want 0xDEADBEEF", r["node_id"])
	}
}

func TestHandleHandshakeApproveMissingNodeIDSendsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	installFakeHandshake(d)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, 0, []byte{SubHandshakeApprove, 0x01})
	})
	assertErrorReply(t, reply, "handshake approve: missing node_id")
}

func TestHandleHandshakeApproveNoPendingRepliesOK(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	installFakeHandshake(d)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	payload := []byte{SubHandshakeApprove, 0x00, 0x00, 0x00, 0x2A} // node_id 42
	reply := runHandler(t, client, func() { s.handleHandshake(ic, 0, payload) })

	if reply[0] != CmdHandshakeOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdHandshakeOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if r["status"] != "approved" {
		t.Fatalf("status = %v, want approved", r["status"])
	}
}

func TestHandleHandshakeRejectMissingNodeIDSendsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	installFakeHandshake(d)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, 0, []byte{SubHandshakeReject})
	})
	assertErrorReply(t, reply, "handshake reject: missing node_id")
}

func TestHandleHandshakeRejectValidRepliesOK(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	installFakeHandshake(d)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	// [SubHandshakeReject][4-byte node_id][reason...]
	payload := []byte{SubHandshakeReject, 0x00, 0x00, 0x00, 0x05, 's', 'p', 'a', 'm'}
	reply := runHandler(t, client, func() { s.handleHandshake(ic, 0, payload) })

	if reply[0] != CmdHandshakeOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdHandshakeOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if r["status"] != "rejected" {
		t.Fatalf("status = %v, want rejected", r["status"])
	}
	if uint32(r["node_id"].(float64)) != 5 {
		t.Fatalf("node_id = %v, want 5", r["node_id"])
	}
}

func TestHandleHandshakePendingEmptyListRepliesOK(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	installFakeHandshake(d)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, 0, []byte{SubHandshakePending})
	})

	if reply[0] != CmdHandshakeOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdHandshakeOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	list, ok := r["pending"].([]interface{})
	if !ok {
		t.Fatalf("pending field missing/wrong type: %v", r)
	}
	if len(list) != 0 {
		t.Fatalf("pending len = %d, want 0", len(list))
	}
}

func TestHandleHandshakePendingPopulatedListRepliesOK(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	fs := installFakeHandshake(d)
	// Seed two pending requests.
	fs.pendingRecs = []HandshakePendingRecord{
		{NodeID: 101, PublicKey: "pub-A", Justification: "one", ReceivedAt: time.Unix(1700000000, 0)},
		{NodeID: 202, PublicKey: "pub-B", Justification: "two", ReceivedAt: time.Unix(1700000100, 0)},
	}

	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, 0, []byte{SubHandshakePending})
	})

	if reply[0] != CmdHandshakeOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdHandshakeOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	list := r["pending"].([]interface{})
	if len(list) != 2 {
		t.Fatalf("pending len = %d, want 2", len(list))
	}
	seen := map[uint32]bool{}
	for _, e := range list {
		em := e.(map[string]interface{})
		seen[uint32(em["node_id"].(float64))] = true
		for _, key := range []string{"node_id", "public_key", "justification", "received_at"} {
			if _, ok := em[key]; !ok {
				t.Fatalf("pending entry missing key %q: %v", key, em)
			}
		}
	}
	if !seen[101] || !seen[202] {
		t.Fatalf("seen = %v, want both 101 and 202", seen)
	}
}

func TestHandleHandshakeTrustedEmptyListRepliesOK(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	installFakeHandshake(d)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, 0, []byte{SubHandshakeTrusted})
	})

	if reply[0] != CmdHandshakeOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdHandshakeOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	list, ok := r["trusted"].([]interface{})
	if !ok {
		t.Fatalf("trusted field missing/wrong type: %v", r)
	}
	if len(list) != 0 {
		t.Fatalf("trusted len = %d, want 0", len(list))
	}
}

func TestHandleHandshakeTrustedPopulatedListRepliesOK(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	fs := installFakeHandshake(d)
	// Seed a trusted peer with every field populated.
	fs.trustedRecs = []HandshakeTrustRecord{{
		NodeID:     777,
		PublicKey:  "pub-X",
		ApprovedAt: time.Unix(1700000000, 0),
		Mutual:     true,
		Network:    42,
	}}

	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, 0, []byte{SubHandshakeTrusted})
	})

	if reply[0] != CmdHandshakeOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdHandshakeOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	list := r["trusted"].([]interface{})
	if len(list) != 1 {
		t.Fatalf("trusted len = %d, want 1", len(list))
	}
	entry := list[0].(map[string]interface{})
	if uint32(entry["node_id"].(float64)) != 777 {
		t.Fatalf("node_id = %v, want 777", entry["node_id"])
	}
	if entry["public_key"] != "pub-X" {
		t.Fatalf("public_key = %v, want pub-X", entry["public_key"])
	}
	if entry["mutual"] != true {
		t.Fatalf("mutual = %v, want true", entry["mutual"])
	}
	if uint16(entry["network"].(float64)) != 42 {
		t.Fatalf("network = %v, want 42", entry["network"])
	}
}

func TestHandleHandshakeRevokeMissingNodeIDSendsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	installFakeHandshake(d)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, 0, []byte{SubHandshakeRevoke, 0x01, 0x02})
	})
	assertErrorReply(t, reply, "handshake revoke: missing node_id")
}

func TestHandleHandshakeRevokeNotTrustedSendsError(t *testing.T) {
	t.Parallel()
	// RevokeTrust returns "node X was not trusted" when the peer wasn't in
	// the trusted set — the fake mirrors that contract.
	d := New(Config{})
	installFakeHandshake(d)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := make([]byte, 5)
	payload[0] = SubHandshakeRevoke
	binary.BigEndian.PutUint32(payload[1:], 12345)
	reply := runHandler(t, client, func() { s.handleHandshake(ic, 0, payload) })
	assertErrorReply(t, reply, "was not trusted")
}

func TestHandleHandshakeRevokeValidClearsTrustedAndRepliesOK(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	fs := installFakeHandshake(d)
	// Seed trusted, then revoke.
	fs.trustedRecs = []HandshakeTrustRecord{{NodeID: 999, ApprovedAt: time.Now()}}
	if !fs.IsTrusted(999) {
		t.Fatal("precondition: peer 999 should be trusted")
	}

	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := make([]byte, 5)
	payload[0] = SubHandshakeRevoke
	binary.BigEndian.PutUint32(payload[1:], 999)

	reply := runHandler(t, client, func() { s.handleHandshake(ic, 0, payload) })

	if reply[0] != CmdHandshakeOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdHandshakeOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if r["status"] != "revoked" {
		t.Fatalf("status = %v, want revoked", r["status"])
	}
	if uint32(r["node_id"].(float64)) != 999 {
		t.Fatalf("node_id = %v, want 999", r["node_id"])
	}
	// Confirm trust actually cleared — this is the behaviour that matters to clients.
	if fs.IsTrusted(999) {
		t.Fatal("peer 999 still trusted after revoke")
	}
}

func TestHandleHandshakeUnknownSubCommandSendsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	installFakeHandshake(d)
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, 0, []byte{0xEE}) // unknown sub
	})
	assertErrorReply(t, reply, "unknown sub-command")
}
