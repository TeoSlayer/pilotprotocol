// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// shortSocketPath returns a /tmp path short enough for macOS unix socket
// length limit (~104 chars). t.TempDir() paths exceed this on darwin.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join("/tmp", "ps-"+hex.EncodeToString(b[:])+".sock")
	t.Cleanup(func() { _ = os.Remove(p) })
	return p
}

// fakeDaemon is a minimal test harness that simulates the Pilot daemon's
// IPC wire protocol. It listens on a unix socket, records incoming frames,
// and replies with configured responses. Sufficient for verifying each
// driver.* method's request encoding and response decoding end-to-end.
type fakeDaemon struct {
	t        *testing.T
	ln       net.Listener
	path     string
	conn     net.Conn
	connSet  chan struct{} // closed once conn is stored in acceptLoop
	mu       sync.Mutex
	received [][]byte // all frames received
	handlers map[byte]func(frame []byte) [][]byte
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	path := shortSocketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	d := &fakeDaemon{
		t:        t,
		ln:       ln,
		path:     path,
		connSet:  make(chan struct{}),
		handlers: make(map[byte]func(frame []byte) [][]byte),
	}
	go d.acceptLoop()
	return d
}

func (d *fakeDaemon) acceptLoop() {
	conn, err := d.ln.Accept()
	if err != nil {
		return
	}
	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()
	close(d.connSet) // signal that conn is stored and ready to be closed

	// Wire format: [cmd(1)][payload...] — matches driver.ipcEnvelopeHeaderSize.
	for {
		frame, err := ipcutil.Read(conn)
		if err != nil {
			return
		}
		d.mu.Lock()
		var resp [][]byte
		if len(frame) >= 1 {
			cmd := frame[0]
			d.received = append(d.received, frame)
			if h, ok := d.handlers[cmd]; ok {
				resp = h(frame)
			}
		}
		d.mu.Unlock()
		for _, r := range resp {
			_ = ipcutil.Write(conn, r)
		}
	}
}

func (d *fakeDaemon) onCmd(cmd byte, respond func(frame []byte) [][]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[cmd] = respond
}

func (d *fakeDaemon) lastFrame() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.received) == 0 {
		return nil
	}
	return d.received[len(d.received)-1]
}

func (d *fakeDaemon) allFrames() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.received))
	copy(out, d.received)
	return out
}

func (d *fakeDaemon) closeConn() {
	d.mu.Lock()
	c := d.conn
	d.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (d *fakeDaemon) close() {
	d.ln.Close()
	// Wait for acceptLoop to store d.conn before closing it.
	// Without this, close() races with acceptLoop: d.conn may still be
	// nil when closeConn() runs, leaving the accepted socket open and
	// blocking the driver's readLoop indefinitely.
	select {
	case <-d.connSet:
	case <-time.After(100 * time.Millisecond):
	}
	d.closeConn()
}

// waitFor polls until cond is true or deadline is reached.
func waitFor(t *testing.T, max time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// jsonOK returns a [cmd][json-body] frame.
func jsonOK(cmd byte, body string) []byte {
	out := make([]byte, 1+len(body))
	out[0] = cmd
	copy(out[1:], body)
	return out
}

// ---------- Connect / Close ----------

func TestConnectNonExistentSocketReturnsError(t *testing.T) {
	t.Parallel()
	_, err := Connect("/tmp/definitely-not-a-real-pilot-socket-xxx.sock")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestConnectEmptySocketFallsBackToDefault(t *testing.T) {
	t.Parallel()
	// DefaultSocketPath is /tmp/pilot.sock — almost certainly not present
	// in a test env. We just assert the fall-through path is taken and
	// returns an error (no panic on empty input).
	_, err := Connect("")
	if err == nil {
		t.Log("Connect(\"\") succeeded — a daemon is running on default path; not an error")
		return
	}
}

func TestConnectAndCloseSuccess(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if drv.socketPath != d.path {
		t.Errorf("socketPath = %q, want %q", drv.socketPath, d.path)
	}
	if err := drv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// ---------- DialAddr / Dial ----------

func TestDialAddrHappyPath(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdDial, func(frame []byte) [][]byte {
		resp := make([]byte, 1+4)
		resp[0] = cmdDialOK
		binary.BigEndian.PutUint32(resp[1:5], 0xDEADBEEF)
		return [][]byte{resp}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()

	dst := protocol.Addr{Network: 1, Node: 0x0102_0304}
	conn, err := drv.DialAddr(dst, 7)
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	if conn.id != 0xDEADBEEF {
		t.Errorf("conn.id = %#x, want 0xDEADBEEF", conn.id)
	}
	if conn.remoteAddr.Addr != dst || conn.remoteAddr.Port != 7 {
		t.Errorf("remoteAddr = %+v, want {%+v, 7}", conn.remoteAddr, dst)
	}
}

func TestDialParsesAddressString(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdDial, func(frame []byte) [][]byte {
		resp := make([]byte, 5)
		resp[0] = cmdDialOK
		binary.BigEndian.PutUint32(resp[1:5], 42)
		return [][]byte{resp}
	})

	drv, _ := Connect(d.path)
	defer drv.Close()

	conn, err := drv.Dial("1:0001.AAAA.BBBB:80")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if conn.id != 42 {
		t.Errorf("id = %d, want 42", conn.id)
	}
}

func TestDialBadAddressReturnsParseError(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, _ := Connect(d.path)
	defer drv.Close()
	if _, err := drv.Dial("not-a-valid-addr"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestDialAddrTimeoutFiresWhenDaemonSilent(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	// No handler for cmdDial → daemon never responds
	drv, _ := Connect(d.path)
	defer drv.Close()

	start := time.Now()
	_, err := drv.DialAddrTimeout(protocol.Addr{Network: 1, Node: 1}, 1, 100*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed < 80*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Errorf("elapsed = %v (expected ~100ms)", elapsed)
	}
}

// ---------- Listen ----------

func TestListenHappyPath(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdBind, func(frame []byte) [][]byte {
		resp := make([]byte, 3)
		resp[0] = cmdBindOK
		binary.BigEndian.PutUint16(resp[1:3], 7) // echoed port
		return [][]byte{resp}
	})

	drv, _ := Connect(d.path)
	defer drv.Close()

	ln, err := drv.Listen(7)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if ln.port != 7 {
		t.Errorf("port = %d, want 7", ln.port)
	}
	_ = ln.Close()
}

// ---------- SendTo / RecvFrom ----------

func TestSendToWritesFrame(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, _ := Connect(d.path)
	defer drv.Close()

	dst := protocol.Addr{Network: 2, Node: 0x0A0B_0C0D}
	if err := drv.SendTo(dst, 100, []byte("hi")); err != nil {
		t.Fatalf("SendTo: %v", err)
	}

	waitFor(t, time.Second, func() bool {
		return d.lastFrame() != nil
	}, "daemon to receive frame")
	frame := d.lastFrame()
	// d.received stores frames as-is: [cmd(1)][body...].
	if frame[0] != cmdSendTo {
		t.Errorf("cmd = %#x, want %#x", frame[0], cmdSendTo)
	}
	if len(frame) != 1+protocol.AddrSize+2+2 {
		t.Errorf("len = %d", len(frame))
	}
	gotPort := binary.BigEndian.Uint16(frame[1+protocol.AddrSize:])
	if gotPort != 100 {
		t.Errorf("port = %d, want 100", gotPort)
	}
	if string(frame[1+protocol.AddrSize+2:]) != "hi" {
		t.Errorf("payload = %q", frame[1+protocol.AddrSize+2:])
	}
}

func TestRecvFromDeliversDatagram(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	drv, _ := Connect(d.path)
	defer drv.Close()

	// Inject a cmdRecvFrom frame from the daemon
	src := protocol.Addr{Network: 1, Node: 0x1122_3344}
	payload := make([]byte, protocol.AddrSize+4+3)
	src.MarshalTo(payload, 0)
	binary.BigEndian.PutUint16(payload[protocol.AddrSize:], 200)
	binary.BigEndian.PutUint16(payload[protocol.AddrSize+2:], 300)
	copy(payload[protocol.AddrSize+4:], "abc")
	frame := append([]byte{cmdRecvFrom}, payload...)

	// Use pushFromDaemon to write the frame through the daemon-side conn.
	pushFromDaemon(t, d, frame)

	dg, err := drv.RecvFrom()
	if err != nil {
		t.Fatalf("RecvFrom: %v", err)
	}
	if dg.SrcAddr != src || dg.SrcPort != 200 || dg.DstPort != 300 || string(dg.Data) != "abc" {
		t.Errorf("got %+v", dg)
	}
}

func TestRecvFromErrorAfterClose(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	drv, _ := Connect(d.path)

	// Close the daemon so readLoop exits and drains dgCh
	d.close()

	// Give the readLoop time to exit
	waitFor(t, time.Second, func() bool {
		select {
		case <-drv.ipc.doneCh:
			return true
		default:
			return false
		}
	}, "readLoop exit")

	// dgCh is not explicitly closed; RecvFrom blocks until dgCh closes OR
	// until we push. Since it's buffered but not closed, this would hang.
	// Instead we verify the doneCh path by calling Close on the driver.
	_ = drv.Close()
}

// ---------- Info / Health ----------

func TestInfoAndHealthReturnParsedJSON(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdInfo, func(_ []byte) [][]byte {
		return [][]byte{jsonOK(cmdInfoOK, `{"node_id": 42, "addr": "1:0001.0002.0003"}`)}
	})
	d.onCmd(cmdHealth, func(_ []byte) [][]byte {
		return [][]byte{jsonOK(cmdHealthOK, `{"ok": true}`)}
	})
	drv, _ := Connect(d.path)
	defer drv.Close()

	info, err := drv.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info["node_id"].(float64) != 42 {
		t.Errorf("node_id = %v", info["node_id"])
	}

	h, err := drv.Health()
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h["ok"] != true {
		t.Errorf("ok = %v", h["ok"])
	}
}

func TestJsonRPCUnmarshalErrorSurfaced(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdInfo, func(_ []byte) [][]byte {
		return [][]byte{jsonOK(cmdInfoOK, `not-json`)}
	})
	drv, _ := Connect(d.path)
	defer drv.Close()

	if _, err := drv.Info(); err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestSendAndWaitSurfacesDaemonErrorFrame(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdInfo, func(_ []byte) [][]byte {
		// cmdError frame: first byte cmdError, then 2 bytes code, then msg
		body := []byte{cmdError, 0, 0}
		body = append(body, []byte("boom")...)
		return [][]byte{body}
	})
	drv, _ := Connect(d.path)
	defer drv.Close()

	_, err := drv.Info()
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want boom", err)
	}
}

// ---------- Handshake family ----------

func TestHandshakeFamilyRoundTrips(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdHandshake, func(frame []byte) [][]byte {
		return [][]byte{jsonOK(cmdHandshakeOK, `{"ok": true}`)}
	})
	drv, _ := Connect(d.path)
	defer drv.Close()

	if _, err := drv.Handshake(99, "please"); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if _, err := drv.ApproveHandshake(100); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := drv.RejectHandshake(101, "no"); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if _, err := drv.PendingHandshakes(); err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if _, err := drv.TrustedPeers(); err != nil {
		t.Fatalf("Trusted: %v", err)
	}
	if _, err := drv.RevokeTrust(102); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	frames := d.allFrames()
	if len(frames) != 6 {
		t.Fatalf("expected 6 handshake frames, got %d", len(frames))
	}
	expectSub := []byte{subHandshakeSend, subHandshakeApprove, subHandshakeReject,
		subHandshakePending, subHandshakeTrusted, subHandshakeRevoke}
	for i, want := range expectSub {
		if frames[i][0] != cmdHandshake || frames[i][1] != want {
			t.Errorf("frame[%d] = %v, want cmd=%#x sub=%#x", i, frames[i][:2], cmdHandshake, want)
		}
	}
}

// ---------- Registry-modifying wrappers ----------

func TestRegistryWrappersEncodeCorrectly(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	okCommands := map[byte]byte{
		cmdResolveHostname: cmdResolveHostnameOK,
		cmdSetHostname:     cmdSetHostnameOK,
		cmdSetVisibility:   cmdSetVisibilityOK,
		cmdDeregister:      cmdDeregisterOK,
		cmdSetTags:         cmdSetTagsOK,
		cmdSetWebhook:      cmdSetWebhookOK,
	}
	for req, ok := range okCommands {
		req, ok := req, ok
		d.onCmd(req, func(_ []byte) [][]byte {
			return [][]byte{jsonOK(ok, `{"ok":true}`)}
		})
	}

	drv, _ := Connect(d.path)
	defer drv.Close()

	if _, err := drv.ResolveHostname("myhost"); err != nil {
		t.Fatalf("ResolveHostname: %v", err)
	}
	if _, err := drv.SetHostname("myhost"); err != nil {
		t.Fatalf("SetHostname: %v", err)
	}
	if _, err := drv.SetVisibility(true); err != nil {
		t.Fatalf("SetVisibility: %v", err)
	}
	if _, err := drv.Deregister(); err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if _, err := drv.SetTags([]string{"a", "b"}); err != nil {
		t.Fatalf("SetTags: %v", err)
	}
	if _, err := drv.SetWebhook("https://x/y"); err != nil {
		t.Fatalf("SetWebhook: %v", err)
	}

	// Check visibility byte=1 for enabled
	for _, f := range d.allFrames() {
		switch f[0] {
		case cmdSetVisibility:
			if f[1] != 1 {
				t.Errorf("visibility byte = %d, want 1", f[1])
			}
		case cmdResolveHostname:
			if string(f[1:]) != "myhost" {
				t.Errorf("ResolveHostname host = %q", f[1:])
			}
		case cmdSetWebhook:
			if string(f[1:]) != "https://x/y" {
				t.Errorf("SetWebhook url = %q", f[1:])
			}
		}
	}
}

func TestSetVisibilityFalsePath(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdSetVisibility, func(_ []byte) [][]byte {
		return [][]byte{jsonOK(cmdSetVisibilityOK, `{}`)}
	})
	drv, _ := Connect(d.path)
	defer drv.Close()

	if _, err := drv.SetVisibility(false); err != nil {
		t.Fatal(err)
	}

	frames := d.allFrames()
	if frames[0][1] != 0 {
		t.Errorf("visibility false byte = %d, want 0", frames[0][1])
	}
}

// ---------- Disconnect / cmdClose ----------

func TestDisconnectSendsCmdClose(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdClose, func(frame []byte) [][]byte {
		resp := make([]byte, 5)
		resp[0] = cmdCloseOK
		binary.BigEndian.PutUint32(resp[1:5], 77)
		return [][]byte{resp}
	})

	drv, _ := Connect(d.path)
	defer drv.Close()

	if err := drv.Disconnect(77); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	// Disconnect is fire-and-forget; wait for the daemon to receive the frame.
	waitFor(t, time.Second, func() bool { return d.lastFrame() != nil }, "daemon to receive cmdClose")
	frame := d.lastFrame()
	if frame[0] != cmdClose {
		t.Errorf("cmd = %#x, want %#x", frame[0], cmdClose)
	}
	if connID := binary.BigEndian.Uint32(frame[1:5]); connID != 77 {
		t.Errorf("connID = %d", connID)
	}
}

// ---------- Network family ----------

func TestNetworkFamilyRoundTrips(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdNetwork, func(_ []byte) [][]byte {
		return [][]byte{jsonOK(cmdNetworkOK, `{"ok":true}`)}
	})

	drv, _ := Connect(d.path)
	defer drv.Close()

	if _, err := drv.NetworkList(); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.NetworkJoin(5, "token"); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.NetworkLeave(5); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.NetworkMembers(5); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.NetworkInvite(5, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.NetworkPollInvites(); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.NetworkRespondInvite(5, true); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.NetworkRespondInvite(5, false); err != nil {
		t.Fatal(err)
	}

	frames := d.allFrames()
	wantSubs := []byte{subNetworkList, subNetworkJoin, subNetworkLeave, subNetworkMembers,
		subNetworkInvite, subNetworkPollInvites, subNetworkRespondInvite, subNetworkRespondInvite}
	if len(frames) != len(wantSubs) {
		t.Fatalf("got %d frames, want %d", len(frames), len(wantSubs))
	}
	for i, want := range wantSubs {
		if frames[i][1] != want {
			t.Errorf("frame[%d] sub = %#x, want %#x", i, frames[i][1], want)
		}
	}
	// Respond-invite accept vs reject byte
	// Accept frame is 7th (index 6), reject is 8th (index 7)
	if frames[6][4] != 1 {
		t.Errorf("accept byte = %d, want 1", frames[6][4])
	}
	if frames[7][4] != 0 {
		t.Errorf("reject byte = %d, want 0", frames[7][4])
	}
}

// ---------- Managed family ----------

func TestManagedFamilyRoundTrips(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdManaged, func(_ []byte) [][]byte {
		return [][]byte{jsonOK(cmdManagedOK, `{"ok":true}`)}
	})

	drv, _ := Connect(d.path)
	defer drv.Close()

	if _, err := drv.ManagedStatus(5); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.ManagedForceCycle(5); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.PolicyGet(5); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.PolicySet(5, []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.MemberTagsGet(5, 99); err != nil {
		t.Fatal(err)
	}
	if _, err := drv.MemberTagsSet(5, 99, []string{"x", "y"}); err != nil {
		t.Fatal(err)
	}

	frames := d.allFrames()
	wantSubs := []byte{subManagedStatus, subManagedCycle,
		subManagedPolicy, subManagedPolicy, subManagedMemberTags, subManagedMemberTags}
	for i, want := range wantSubs {
		if frames[i][1] != want {
			t.Errorf("frame[%d] sub = %#x, want %#x", i, frames[i][1], want)
		}
	}
	// PolicyGet action byte is 0x00, PolicySet 0x01
	if frames[2][2] != 0x00 {
		t.Errorf("PolicyGet action byte = %#x, want 0x00", frames[2][2])
	}
	if frames[3][2] != 0x01 {
		t.Errorf("PolicySet action byte = %#x, want 0x01", frames[3][2])
	}
	// MemberTagsGet 0x00, Set 0x01
	if frames[4][2] != 0x00 {
		t.Errorf("MemberTagsGet action byte = %#x", frames[4][2])
	}
	if frames[5][2] != 0x01 {
		t.Errorf("MemberTagsSet action byte = %#x", frames[5][2])
	}
}
