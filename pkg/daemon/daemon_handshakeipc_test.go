// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// handleHandshake sub-command dispatch coverage.

// hsTestDaemon builds a daemon wired to a real test registry + identity so
// handshake sub-commands that touch sendMessage / goRPC don't panic on nil
// regConn. The daemon is registered so regConn.Resolve against *unknown*
// peers will return a clean error (rather than deref nil).
func hsTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	resp, err := rc.RegisterWithKey("127.0.0.1:5555", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	d := New(Config{})
	d.regConn = rc
	d.identity = id
	d.setNodeID_testhelper(nodeID)
	t.Cleanup(func() { d.handshakes.Stop() })
	return d
}

func TestHandleHandshakeSendMissingNodeIDSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, []byte{SubHandshakeSend, 0x00, 0x00}) // only 3 bytes of rest (need 4)
	})
	assertErrorReply(t, reply, "handshake request: missing node_id")
}

func TestHandleHandshakeSendAlreadyTrustedRepliesOK(t *testing.T) {
	d := New(Config{})
	// Seed the trusted map so SendRequest early-returns nil (no registry/tunnel needed).
	d.handshakes.trusted[0xDEADBEEF] = &TrustRecord{
		NodeID:     0xDEADBEEF,
		ApprovedAt: time.Now(),
	}

	s := d.ipc
	ic, client := newIPCTestConn(t)

	// [SubHandshakeSend][4-byte node_id][justification...]
	payload := []byte{SubHandshakeSend, 0xDE, 0xAD, 0xBE, 0xEF, 'h', 'i'}
	reply := runHandler(t, client, func() { s.handleHandshake(ic, payload) })

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
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, []byte{SubHandshakeApprove, 0x01})
	})
	assertErrorReply(t, reply, "handshake approve: missing node_id")
}

func TestHandleHandshakeApproveNoPendingRepliesOK(t *testing.T) {
	d := New(Config{})
	// No pending entry — ApproveHandshake returns nil on the `!ok` branch.
	s := d.ipc
	ic, client := newIPCTestConn(t)

	payload := []byte{SubHandshakeApprove, 0x00, 0x00, 0x00, 0x2A} // node_id 42
	reply := runHandler(t, client, func() { s.handleHandshake(ic, payload) })

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
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, []byte{SubHandshakeReject})
	})
	assertErrorReply(t, reply, "handshake reject: missing node_id")
}

func TestHandleHandshakeRejectValidRepliesOK(t *testing.T) {
	d := hsTestDaemon(t)
	s := d.ipc
	ic, client := newIPCTestConn(t)

	// [SubHandshakeReject][4-byte node_id][reason...]
	payload := []byte{SubHandshakeReject, 0x00, 0x00, 0x00, 0x05, 's', 'p', 'a', 'm'}
	reply := runHandler(t, client, func() { s.handleHandshake(ic, payload) })

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
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)

	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, []byte{SubHandshakePending})
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
	d := New(Config{})
	// Seed two pending requests.
	d.handshakes.pending[101] = &PendingHandshake{
		NodeID:        101,
		PublicKey:     "pub-A",
		Justification: "one",
		ReceivedAt:    time.Unix(1700000000, 0),
	}
	d.handshakes.pending[202] = &PendingHandshake{
		NodeID:        202,
		PublicKey:     "pub-B",
		Justification: "two",
		ReceivedAt:    time.Unix(1700000100, 0),
	}

	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, []byte{SubHandshakePending})
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
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)

	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, []byte{SubHandshakeTrusted})
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
	d := New(Config{})
	// Seed a trusted peer with every field populated.
	d.handshakes.trusted[777] = &TrustRecord{
		NodeID:     777,
		PublicKey:  "pub-X",
		ApprovedAt: time.Unix(1700000000, 0),
		Mutual:     true,
		Network:    42,
	}

	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, []byte{SubHandshakeTrusted})
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
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, []byte{SubHandshakeRevoke, 0x01, 0x02})
	})
	assertErrorReply(t, reply, "handshake revoke: missing node_id")
}

func TestHandleHandshakeRevokeNotTrustedSendsError(t *testing.T) {
	// RevokeTrust returns "node X was not trusted" if the node wasn't trusted
	// — this is a pure-logic path that doesn't touch regConn / sendMessage.
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := make([]byte, 5)
	payload[0] = SubHandshakeRevoke
	binary.BigEndian.PutUint32(payload[1:], 12345)
	reply := runHandler(t, client, func() { s.handleHandshake(ic, payload) })
	assertErrorReply(t, reply, "was not trusted")
}

func TestHandleHandshakeRevokeValidClearsTrustedAndRepliesOK(t *testing.T) {
	d := hsTestDaemon(t)
	// Seed trusted, then revoke.
	d.handshakes.trusted[999] = &TrustRecord{
		NodeID:     999,
		ApprovedAt: time.Now(),
	}
	if !d.handshakes.IsTrusted(999) {
		t.Fatal("precondition: peer 999 should be trusted")
	}

	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := make([]byte, 5)
	payload[0] = SubHandshakeRevoke
	binary.BigEndian.PutUint32(payload[1:], 999)

	reply := runHandler(t, client, func() { s.handleHandshake(ic, payload) })

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
	if d.handshakes.IsTrusted(999) {
		t.Fatal("peer 999 still trusted after revoke")
	}
}

func TestHandleHandshakeUnknownSubCommandSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleHandshake(ic, []byte{0xEE}) // unknown sub
	})
	assertErrorReply(t, reply, "unknown sub-command")
}
