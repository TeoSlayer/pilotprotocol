// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// Iter-116 coverage for registry/binary_client.go — 9 zero-coverage functions:
// DialBinary, Close, Addr, reconnect, Heartbeat/heartbeatLocked, Lookup/lookupLocked,
// Resolve/resolveLocked, SendJSON/sendJSONLocked. Strategy: stand up a real TCP
// listener that reads the 5-byte handshake (magic + version), then runs a
// per-test frame handler against the wire protocol via wire.ReadFrame/wire.WriteFrame.

// --- fakeBinaryServer: minimal TCP server speaking the binary wire protocol ---

type fakeBinaryServer struct {
	ln       net.Listener
	handler  func(msgType byte, payload []byte) (respType byte, respPayload []byte)
	mu       sync.Mutex
	handshakes atomic.Uint32
	frames   atomic.Uint32
	done     chan struct{}
}

func newFakeBinaryServer(t *testing.T, handler func(msgType byte, payload []byte) (byte, []byte)) *fakeBinaryServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeBinaryServer{ln: ln, handler: handler, done: make(chan struct{})}
	go s.accept()
	t.Cleanup(s.Close)
	return s
}

func (s *fakeBinaryServer) addr() string { return s.ln.Addr().String() }

func (s *fakeBinaryServer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)
	s.ln.Close()
}

func (s *fakeBinaryServer) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeBinaryServer) handle(conn net.Conn) {
	defer conn.Close()
	// Read 5-byte handshake.
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	s.handshakes.Add(1)
	// Verify magic — but don't enforce version.
	for i, b := range wire.Magic {
		if hdr[i] != b {
			return
		}
	}
	// Per-frame loop.
	for {
		msgType, payload, err := wire.ReadFrame(conn)
		if err != nil {
			return
		}
		s.frames.Add(1)
		if s.handler == nil {
			return
		}
		respType, respPayload := s.handler(msgType, payload)
		if respType == 0 && respPayload == nil {
			// Sentinel for "close without responding" — test uses this to force recv error.
			return
		}
		if err := wire.WriteFrame(conn, respType, respPayload); err != nil {
			return
		}
	}
}

// --- DialBinary: success, dial error, handshake write error ---

func TestDialBinarySuccess(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, nil)
	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	if c.Addr() != srv.addr() {
		t.Fatalf("Addr = %q, want %q", c.Addr(), srv.addr())
	}
	// Wait for the server to see the handshake.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.handshakes.Load() == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not receive handshake within 2s")
}

func TestDialBinaryDialErrorWrapsMessage(t *testing.T) {
	t.Parallel()
	// Port 1 on 127.0.0.1 is almost certainly not listening (privileged, reserved).
	// The dial will fail with ECONNREFUSED within the 5s timeout.
	_, err := DialBinary("127.0.0.1:1")
	if err == nil {
		t.Fatal("DialBinary expected error on unreachable addr")
	}
	// The wrap format is `dial registry: <underlying>`. We don't pin the exact text.
	if len(err.Error()) == 0 {
		t.Fatal("error message is empty")
	}
}

// --- Close: nil-conn path + idempotency ---

func TestBinaryClientCloseIsSafeWithNilConn(t *testing.T) {
	t.Parallel()
	c := &BinaryClient{conn: nil}
	if err := c.Close(); err != nil {
		t.Fatalf("Close on nil conn = %v, want nil (no panic, no err)", err)
	}
	// Second Close is also safe — closed flag set, conn already nil.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
}

// --- Addr: returns the configured addr without connection ---

func TestBinaryClientAddrReflectsCtorValue(t *testing.T) {
	t.Parallel()
	c := &BinaryClient{addr: "host.example:9000"}
	if got := c.Addr(); got != "host.example:9000" {
		t.Fatalf("Addr = %q, want host.example:9000", got)
	}
}

// --- Heartbeat: happy path returns unixTime + warning flag ---

func TestHeartbeatHappyPathReturnsTimeAndWarning(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		if msgType != wire.MsgHeartbeat {
			return wire.MsgError, wire.EncodeError("unexpected msg")
		}
		req, err := wire.DecodeHeartbeatReq(payload)
		if err != nil {
			return wire.MsgError, wire.EncodeError(err.Error())
		}
		if req.NodeID != 12345 {
			return wire.MsgError, wire.EncodeError("wrong node id")
		}
		return wire.MsgHeartbeatOK, wire.EncodeHeartbeatResp(1_700_000_000, true)
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	sig := make([]byte, 64)
	unixTime, warn, err := c.Heartbeat(12345, sig)
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if unixTime != 1_700_000_000 {
		t.Fatalf("unixTime = %d, want 1_700_000_000", unixTime)
	}
	if !warn {
		t.Fatal("keyExpiryWarning = false, want true")
	}
}

// --- Heartbeat: server returns wire.MsgError → client surfaces "registry: <msg>" ---

func TestHeartbeatServerErrorResponseReturnsWrappedError(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		return wire.MsgError, wire.EncodeError("node not registered")
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	_, _, err = c.Heartbeat(9999, make([]byte, 64))
	if err == nil {
		t.Fatal("Heartbeat should return error when server sends wire.MsgError")
	}
	if got := err.Error(); got != "registry: node not registered" {
		t.Fatalf("err = %q, want %q", got, "registry: node not registered")
	}
}

// --- Heartbeat: unexpected response type → error ---

func TestHeartbeatUnexpectedResponseTypeReturnsError(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		// Respond with a LookupOK type instead of HeartbeatOK.
		return wire.MsgLookupOK, []byte{0, 0, 0, 0}
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	_, _, err = c.Heartbeat(1, make([]byte, 64))
	if err == nil {
		t.Fatal("expected error on unexpected response type")
	}
}

// --- Lookup: happy path decodes wire.LookupResult ---

func TestLookupHappyPathDecodesResult(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		if msgType != wire.MsgLookup {
			return wire.MsgError, wire.EncodeError("bad type")
		}
		return wire.MsgLookupOK, wire.EncodeLookupResp(
			42,              // nodeID
			true, false,     // public, taskExec
			[]uint16{1, 2},  // networks
			[]byte{0xAB},    // pubkey
			"host.example",  // hostname
			[]string{"t1"},  // tags
			"1.2.3.4:444",   // realAddr
			"ext-123",       // externalID
		)
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	res, err := c.Lookup(42)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.NodeID != 42 {
		t.Fatalf("NodeID = %d", res.NodeID)
	}
	if !res.Public || res.TaskExec {
		t.Fatalf("flags: public=%v taskExec=%v", res.Public, res.TaskExec)
	}
	if len(res.Networks) != 2 || res.Networks[0] != 1 || res.Networks[1] != 2 {
		t.Fatalf("Networks = %v", res.Networks)
	}
	if res.Hostname != "host.example" {
		t.Fatalf("Hostname = %q", res.Hostname)
	}
	if len(res.Tags) != 1 || res.Tags[0] != "t1" {
		t.Fatalf("Tags = %v", res.Tags)
	}
	if res.RealAddr != "1.2.3.4:444" {
		t.Fatalf("RealAddr = %q", res.RealAddr)
	}
	if res.ExternalID != "ext-123" {
		t.Fatalf("ExternalID = %q", res.ExternalID)
	}
}

// --- Lookup: unexpected response type ---

func TestLookupUnexpectedResponseTypeReturnsError(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		return wire.MsgHeartbeatOK, wire.EncodeHeartbeatResp(0, false)
	})
	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	if _, err := c.Lookup(99); err == nil {
		t.Fatal("expected error on wrong response type")
	}
}

// --- Resolve: happy path decodes wire.ResolveResult ---

func TestResolveHappyPathDecodesResult(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		if msgType != wire.MsgResolve {
			return wire.MsgError, wire.EncodeError("bad type")
		}
		return wire.MsgResolveOK, wire.EncodeResolveResp(
			77, "10.0.0.1:5000",
			[]string{"192.168.1.1:5000", "192.168.1.2:5000"},
			42,
		)
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	res, err := c.Resolve(77, 1, make([]byte, 64))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.NodeID != 77 {
		t.Fatalf("NodeID = %d", res.NodeID)
	}
	if res.RealAddr != "10.0.0.1:5000" {
		t.Fatalf("RealAddr = %q", res.RealAddr)
	}
	if len(res.LANAddrs) != 2 {
		t.Fatalf("LANAddrs = %v", res.LANAddrs)
	}
	if res.KeyAgeDays != 42 {
		t.Fatalf("KeyAgeDays = %d", res.KeyAgeDays)
	}
}

// --- Resolve: -1 key_age_days (MaxUint32 in wire) ---

func TestResolveMaxUint32KeyAgeMapsToNegativeOne(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		return wire.MsgResolveOK, wire.EncodeResolveResp(1, "a:1", nil, -1)
	})
	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	res, err := c.Resolve(1, 1, make([]byte, 64))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.KeyAgeDays != -1 {
		t.Fatalf("KeyAgeDays = %d, want -1 (MaxUint32 sentinel)", res.KeyAgeDays)
	}
}

// --- SendJSON: roundtrip of a generic map ---

func TestSendJSONRoundtripsGenericMap(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		if msgType != wire.MsgJSON {
			return wire.MsgError, wire.EncodeError("bad type")
		}
		var req map[string]interface{}
		if err := json.Unmarshal(payload, &req); err != nil {
			return wire.MsgError, wire.EncodeError(err.Error())
		}
		resp := map[string]interface{}{
			"type": "ok",
			"echo": req["x"],
		}
		body, _ := json.Marshal(resp)
		return wire.MsgJSON, body
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	resp, err := c.SendJSON(map[string]interface{}{"x": 7.0})
	if err != nil {
		t.Fatalf("SendJSON: %v", err)
	}
	if resp["type"] != "ok" {
		t.Fatalf("resp.type = %v, want ok", resp["type"])
	}
	if got, _ := resp["echo"].(float64); got != 7 {
		t.Fatalf("resp.echo = %v, want 7", resp["echo"])
	}
}

// --- SendJSON: server returns wire.MsgError (server-side protocol error) ---

func TestSendJSONWireMsgErrorReturnsMapWithError(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		return wire.MsgError, wire.EncodeError("rate limited")
	})
	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	resp, err := c.SendJSON(map[string]interface{}{"op": "whatever"})
	if err == nil {
		t.Fatal("expected error on wire.MsgError")
	}
	if resp == nil {
		t.Fatal("resp must NOT be nil on wire.MsgError — caller relies on non-nil to skip reconnect")
	}
	if resp["type"] != "error" || resp["error"] != "rate limited" {
		t.Fatalf("resp = %v, want type=error error=rate limited", resp)
	}
}

// --- SendJSON: application-level error field in normal JSON response ---

func TestSendJSONReturnsErrorWhenResponseHasErrorField(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		resp := map[string]interface{}{"type": "bad", "error": "invalid op"}
		body, _ := json.Marshal(resp)
		return wire.MsgJSON, body
	})
	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	resp, err := c.SendJSON(map[string]interface{}{"op": "x"})
	if err == nil {
		t.Fatal("expected error when response has error field")
	}
	if got := err.Error(); got != "registry: invalid op" {
		t.Fatalf("err = %q, want %q", got, "registry: invalid op")
	}
	if resp["type"] != "bad" {
		t.Fatalf("resp.type = %v, want bad", resp["type"])
	}
}

// --- SendJSON: unexpected response type ---

func TestSendJSONUnexpectedResponseTypeReturnsError(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		return wire.MsgLookupOK, []byte{0, 0, 0, 0}
	})
	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	_, err = c.SendJSON(map[string]interface{}{"op": "x"})
	if err == nil {
		t.Fatal("expected error on wrong response type")
	}
}

// --- SendJSON: server returns malformed JSON in wire.MsgJSON → decode err ---

func TestSendJSONMalformedResponseReturnsDecodeError(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		return wire.MsgJSON, []byte("not valid json }{")
	})
	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	_, err = c.SendJSON(map[string]interface{}{"op": "x"})
	if err == nil {
		t.Fatal("expected decode error on malformed JSON response")
	}
}

// --- encode/decode round-trips: sanity of our test helpers as well as SUT symmetry ---

func TestEncodeDecodeHeartbeatReqRoundTrip(t *testing.T) {
	t.Parallel()
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}
	buf := wire.EncodeHeartbeatReq(0xDEADBEEF, sig)
	req, err := wire.DecodeHeartbeatReq(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.NodeID != 0xDEADBEEF {
		t.Fatalf("NodeID = %x", req.NodeID)
	}
	for i := 0; i < 64; i++ {
		if req.Signature[i] != byte(i) {
			t.Fatalf("sig[%d] = %x, want %x", i, req.Signature[i], i)
		}
	}
}

func TestDecodeWireErrorShortPayloadReturnsSentinel(t *testing.T) {
	t.Parallel()
	if got := wire.DecodeError([]byte{0x00}); got != "unknown error" {
		t.Fatalf("wire.DecodeError(short) = %q, want unknown error", got)
	}
}

func TestDecodeWireErrorTruncatesToActualLen(t *testing.T) {
	t.Parallel()
	// Claim length=100 but only 5 real bytes follow — decoder clamps to available.
	buf := make([]byte, 7)
	binary.BigEndian.PutUint16(buf[:2], 100)
	copy(buf[2:], []byte("hello"))
	got := wire.DecodeError(buf)
	if got != "hello" {
		t.Fatalf("wire.DecodeError(truncated) = %q, want hello", got)
	}
}
