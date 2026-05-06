// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// newIPCTestConn returns (serverConn, clientConn). Wrap serverConn in ipcConn
// and pass to handlers; read replies from clientConn. Uses newIPCConn so the
// async writer goroutine is properly started — handlers' ipcWrite calls
// would block indefinitely on a zero-value sendCh otherwise.
func newIPCTestConn(t *testing.T) (*ipcConn, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	ic := newIPCConn(server)
	t.Cleanup(func() {
		_ = ic.Close() // signals writer goroutine to drain + exit
		_ = client.Close()
	})
	return ic, client
}

// readIPCReply reads a length-prefixed reply from the client side with a
// deadline. Returns the raw (unframed) bytes — first byte is the command.
func readIPCReply(t *testing.T, client net.Conn, timeout time.Duration) []byte {
	t.Helper()
	_ = client.SetReadDeadline(time.Now().Add(timeout))
	msg, err := ipcutil.Read(client)
	if err != nil {
		t.Fatalf("ipcutil.Read: %v", err)
	}
	return msg
}

// assertErrorReply checks a sendError frame layout: [CmdError][2-byte code][msg].
func assertErrorReply(t *testing.T, reply []byte, wantSubstr string) {
	t.Helper()
	if len(reply) < 3 {
		t.Fatalf("error reply too short: %d bytes", len(reply))
	}
	if reply[0] != CmdError {
		t.Fatalf("reply[0] = 0x%02X, want CmdError (0x%02X)", reply[0], CmdError)
	}
	if code := binary.BigEndian.Uint16(reply[1:3]); code != 1 {
		t.Fatalf("error code = %d, want 1", code)
	}
	msg := string(reply[3:])
	if !strings.Contains(msg, wantSubstr) {
		t.Fatalf("error msg = %q, want to contain %q", msg, wantSubstr)
	}
}

// runHandler invokes fn in a goroutine so a net.Pipe write doesn't deadlock.
// Returns the reply bytes collected from the client side.
func runHandler(t *testing.T, client net.Conn, fn func()) []byte {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	reply := readIPCReply(t, client, 500*time.Millisecond)
	// Make sure the handler goroutine actually returns (not strictly needed but
	// avoids goroutine leaks polluting later tests).
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		// not fatal — the handler may have background goroutines
	}
	return reply
}

// --- handleBind ---

func TestHandleBindShortPayloadSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleBind(ic, []byte{0x00}) })
	assertErrorReply(t, reply, "bind: missing port")
}

func TestHandleBindValidPayloadSendsBindOK(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)

	payload := []byte{0x10, 0x20} // port 0x1020 = 4128
	reply := runHandler(t, client, func() { s.handleBind(ic, payload) })

	if len(reply) != 3 {
		t.Fatalf("reply len = %d, want 3", len(reply))
	}
	if reply[0] != CmdBindOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdBindOK (0x%02X)", reply[0], CmdBindOK)
	}
	if p := binary.BigEndian.Uint16(reply[1:3]); p != 4128 {
		t.Fatalf("reply port = %d, want 4128", p)
	}

	ic.rmu.Lock()
	tracked := append([]uint16(nil), ic.ports...)
	ic.rmu.Unlock()
	if len(tracked) != 1 || tracked[0] != 4128 {
		t.Fatalf("tracked ports = %v, want [4128]", tracked)
	}
}

func TestHandleBindDoubleBindSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	// Pre-bind port 9000 via ports manager so the second bind will fail.
	if _, err := d.ports.Bind(9000); err != nil {
		t.Fatalf("pre-bind: %v", err)
	}
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleBind(ic, []byte{0x23, 0x28}) }) // port 9000
	assertErrorReply(t, reply, "port")                                              // "already bound" or similar
}

// --- handleDial ---

func TestHandleDialShortPayloadSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleDial(ic, []byte{0x00, 0x01}) })
	assertErrorReply(t, reply, "dial: missing address/port")
}

func TestHandleDialPortDeniedByPolicySendsError(t *testing.T) {
	d := New(Config{})
	// Restrict network 7 to only port 80 — then dialing port 443 will be denied.
	d.netPolicyMu.Lock()
	d.netPolicies[7] = []uint16{80}
	d.netPolicyMu.Unlock()

	s := d.ipc
	ic, client := newIPCTestConn(t)
	// Build payload: AddrSize-byte addr + 2-byte port
	payload := make([]byte, protocol.AddrSize+2)
	addr := protocol.Addr{Network: 7, Node: 0xAABB0001}
	addr.MarshalTo(payload, 0)
	binary.BigEndian.PutUint16(payload[protocol.AddrSize:], 443)
	reply := runHandler(t, client, func() { s.handleDial(ic, payload) })
	assertErrorReply(t, reply, "not allowed")
}

// --- handleSend ---

func TestHandleSendShortPayloadSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleSend(ic, []byte{0x01}) }) // <4 bytes
	assertErrorReply(t, reply, "send: missing conn_id")
}

func TestHandleSendUnknownConnIDSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	// 4-byte conn_id that doesn't exist + some payload.
	payload := []byte{0x00, 0x00, 0x00, 0x7B, 'a', 'b', 'c'} // conn_id 123
	reply := runHandler(t, client, func() { s.handleSend(ic, payload) })
	assertErrorReply(t, reply, "connection 123 not found")
}

// --- handleClose ---

func TestHandleCloseShortPayloadSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleClose(ic, []byte{0xAA}) })
	assertErrorReply(t, reply, "close: missing conn_id")
}

func TestHandleCloseUnknownConnIDStillSendsCloseOK(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := []byte{0x00, 0x00, 0x00, 0x2A} // conn_id 42
	reply := runHandler(t, client, func() { s.handleClose(ic, payload) })

	if len(reply) != 5 {
		t.Fatalf("reply len = %d, want 5", len(reply))
	}
	if reply[0] != CmdCloseOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdCloseOK", reply[0])
	}
	if cid := binary.BigEndian.Uint32(reply[1:5]); cid != 42 {
		t.Fatalf("reply conn_id = %d, want 42", cid)
	}
}

// --- handleSendTo ---

func TestHandleSendToShortPayloadSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleSendTo(ic, []byte{0x00}) })
	assertErrorReply(t, reply, "sendto: missing address/port")
}

func TestHandleSendToBroadcastOnNetworkZeroSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)

	// Build: [broadcast addr network 0][port 80][payload]
	payload := make([]byte, protocol.AddrSize+2+4)
	addr := protocol.BroadcastAddr(0)
	addr.MarshalTo(payload, 0)
	binary.BigEndian.PutUint16(payload[protocol.AddrSize:], 80)
	copy(payload[protocol.AddrSize+2:], "data")

	reply := runHandler(t, client, func() { s.handleSendTo(ic, payload) })
	assertErrorReply(t, reply, "sendto:")
}

// --- handleInfo ---

func TestHandleInfoReturnsValidJSON(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	// Register ourselves so nodeNetworks() can succeed.
	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:5000", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	d := New(Config{})
	d.regConn = rc
	d.setNodeID_testhelper(nodeID)

	s := d.ipc
	ic, client := newIPCTestConn(t)

	reply := runHandler(t, client, func() { s.handleInfo(ic) })

	if len(reply) < 2 {
		t.Fatalf("reply len = %d", len(reply))
	}
	if reply[0] != CmdInfoOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdInfoOK", reply[0])
	}

	var info map[string]interface{}
	if err := json.Unmarshal(reply[1:], &info); err != nil {
		t.Fatalf("info JSON: %v", err)
	}
	gotID, _ := info["node_id"].(float64)
	if uint32(gotID) != nodeID {
		t.Fatalf("node_id = 0x%X, want 0x%X", uint32(gotID), nodeID)
	}
	if c, _ := info["connections"].(float64); c != 0 {
		t.Fatalf("connections = %v, want 0", c)
	}
}

// --- handleHealth ---

func TestHandleHealthReturnsValidJSON(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	id, _ := crypto.GenerateIdentity()
	resp, err := rc.RegisterWithKey("127.0.0.1:5001", crypto.EncodePublicKey(id.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeID := uint32(resp["node_id"].(float64))

	d := New(Config{})
	d.regConn = rc
	d.setNodeID_testhelper(nodeID)

	s := d.ipc
	ic, client := newIPCTestConn(t)

	reply := runHandler(t, client, func() { s.handleHealth(ic) })

	if reply[0] != CmdHealthOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdHealthOK", reply[0])
	}
	var h map[string]interface{}
	if err := json.Unmarshal(reply[1:], &h); err != nil {
		t.Fatalf("health JSON: %v", err)
	}
	if h["status"] != "ok" {
		t.Fatalf("status = %v, want ok", h["status"])
	}
}

// --- handleSetWebhook ---

func TestHandleSetWebhookEmptyPayloadClearsWebhookAndRepliesOK(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)

	reply := runHandler(t, client, func() { s.handleSetWebhook(ic, nil) })

	if reply[0] != CmdSetWebhookOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdSetWebhookOK", reply[0])
	}
	var r map[string]interface{}
	if err := json.Unmarshal(reply[1:], &r); err != nil {
		t.Fatalf("set_webhook JSON: %v", err)
	}
	if r["webhook"] != "" {
		t.Fatalf("webhook = %v, want empty", r["webhook"])
	}
	if d.webhook != nil {
		t.Fatalf("webhook should be nil after clear, got %v", d.webhook)
	}
}

func TestHandleSetWebhookInvalidSchemeSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)

	reply := runHandler(t, client, func() { s.handleSetWebhook(ic, []byte("ftp://evil.example.com/hook")) })
	assertErrorReply(t, reply, "scheme")
}

func TestHandleSetWebhookValidHTTPSConfiguresAndRepliesOK(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)

	reply := runHandler(t, client, func() { s.handleSetWebhook(ic, []byte("https://example.com/hook")) })

	if reply[0] != CmdSetWebhookOK {
		t.Fatalf("reply[0] = 0x%02X, want CmdSetWebhookOK", reply[0])
	}
	if d.webhook == nil {
		t.Fatal("webhook should be set for valid URL")
	}
}

// --- handleSetVisibility ---

func TestHandleSetVisibilityShortPayloadSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleSetVisibility(ic, nil) })
	assertErrorReply(t, reply, "set_visibility: missing value")
}

// --- handleSetTaskExec ---

func TestHandleSetTaskExecShortPayloadSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleSetTaskExec(ic, nil) })
	assertErrorReply(t, reply, "set_task_exec: missing value")
}

// --- handleSetTags ---

func TestHandleSetTagsInvalidJSONSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleSetTags(ic, []byte("not-json")) })
	assertErrorReply(t, reply, "set_tags: invalid JSON")
}

func TestHandleSetTagsTooManyTagsSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	body := []byte(`["a","b","c","d"]`) // 4 tags > 3 limit
	reply := runHandler(t, client, func() { s.handleSetTags(ic, body) })
	assertErrorReply(t, reply, "maximum 3 tags allowed")
}

// --- handleResolveHostname ---

func TestHandleResolveHostnameEmptySendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleResolveHostname(ic, nil) })
	assertErrorReply(t, reply, "resolve_hostname: missing hostname")
}

// --- handleNetwork ---

func TestHandleNetworkShortPayloadSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleNetwork(ic, nil) })
	assertErrorReply(t, reply, "network: missing sub-command")
}

func TestHandleNetworkUnknownSubCommandSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleNetwork(ic, []byte{0xEE}) })
	assertErrorReply(t, reply, "unknown sub-command")
}

func TestHandleNetworkJoinShortRestSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleNetwork(ic, []byte{SubNetworkJoin, 0x00}) })
	assertErrorReply(t, reply, "network join: missing network_id")
}

func TestHandleNetworkLeaveShortRestSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleNetwork(ic, []byte{SubNetworkLeave}) })
	assertErrorReply(t, reply, "network leave: missing network_id")
}

// --- handleManaged ---

func TestHandleManagedShortPayloadSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleManaged(ic, nil) })
	assertErrorReply(t, reply, "managed: missing sub-command")
}

func TestHandleManagedScoreShortRestSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleManaged(ic, []byte{SubManagedScore, 0x00, 0x01}) })
	assertErrorReply(t, reply, "missing fields")
}

func TestHandleManagedStatusNoEngineSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleManaged(ic, []byte{SubManagedStatus}) })
	assertErrorReply(t, reply, "no active managed networks")
}

func TestHandleManagedPolicyShortRestSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleManaged(ic, []byte{SubManagedPolicy, 0x00}) })
	assertErrorReply(t, reply, "missing sub-sub-command")
}

// --- handleHandshake ---

func TestHandleHandshakeShortPayloadSendsError(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleHandshake(ic, nil) })
	assertErrorReply(t, reply, "handshake: missing sub-command")
}

// --- sendError format ---

func TestSendErrorFrameLayout(t *testing.T) {
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.sendError(ic, "custom-error") })

	if reply[0] != CmdError {
		t.Fatalf("reply[0] = 0x%02X, want CmdError", reply[0])
	}
	if code := binary.BigEndian.Uint16(reply[1:3]); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if string(reply[3:]) != "custom-error" {
		t.Fatalf("msg = %q, want 'custom-error'", string(reply[3:]))
	}
}
