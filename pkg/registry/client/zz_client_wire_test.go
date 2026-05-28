// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeJSONServer speaks the registry JSON-over-TCP wire protocol
// (4-byte big-endian length prefix + JSON body). Each connection handshake
// is dispatched to a handler callback that can read the request and write
// a reply.
type fakeJSONServer struct {
	ln          net.Listener
	handler     func(req map[string]interface{}) map[string]interface{}
	requests    atomic.Uint32
	connections atomic.Uint32
	done        chan struct{}
}

func newFakeJSONServer(t *testing.T, handler func(req map[string]interface{}) map[string]interface{}) *fakeJSONServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeJSONServer{ln: ln, handler: handler, done: make(chan struct{})}
	go s.accept()
	return s
}

func (s *fakeJSONServer) addr() string { return s.ln.Addr().String() }

func (s *fakeJSONServer) close() { s.ln.Close(); close(s.done) }

func (s *fakeJSONServer) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.connections.Add(1)
		go s.handle(conn)
	}
}

func (s *fakeJSONServer) handle(conn net.Conn) {
	defer conn.Close()
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		// Defensive cap: any caller that sends non-JSON framing (e.g. TLS
		// ClientHello) would otherwise block this goroutine in io.ReadFull
		// until the full test timeout.
		if n > 1<<20 {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			return
		}
		s.requests.Add(1)
		resp := s.handler(req)
		if resp == nil {
			return
		}
		out, _ := json.Marshal(resp)
		var outLen [4]byte
		binary.BigEndian.PutUint32(outLen[:], uint32(len(out)))
		conn.Write(outLen[:])
		conn.Write(out)
	}
}

// Echo the request type, plus include every key that was sent, under "echo".
// Tests can assert that the wire payload carried the right keys.
func echoHandler() func(map[string]interface{}) map[string]interface{} {
	return func(req map[string]interface{}) map[string]interface{} {
		resp := map[string]interface{}{"type": "ok", "echo": req}
		return resp
	}
}

// --- Dial / Close / Addr ----------------------------------------------------

func TestDialSuccessReturnsClientWithAddr(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if c.addr != srv.addr() {
		t.Fatalf("addr: want %q, got %q", srv.addr(), c.addr)
	}
	if c.conn == nil {
		t.Fatalf("conn should be set")
	}
}

func TestDialErrorOnBadAddress(t *testing.T) {
	t.Parallel()
	// Grab a port from the kernel and immediately release it so Dial
	// fails fast with ECONNREFUSED on loopback (no DNS/route wait).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, err = Dial(addr)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "dial registry") {
		t.Fatalf("error should mention dial registry: %v", err)
	}
}

func TestDialTLSReturnsErrorWhenConfigNil(t *testing.T) {
	t.Parallel()
	if _, err := DialTLS("127.0.0.1:1", nil); err == nil {
		t.Fatalf("expected error on nil tlsConfig")
	}
}

// closeOnAcceptListener accepts each connection and immediately closes it, so
// a TLS dial against it fails fast with EOF during the handshake.
func closeOnAcceptListener(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestDialTLSFailsConnectToPlainServer(t *testing.T) {
	t.Parallel()
	addr, stop := closeOnAcceptListener(t)
	defer stop()
	_, err := DialTLS(addr, minimalTLSConfig())
	if err == nil {
		t.Fatalf("expected TLS error")
	}
	if !strings.Contains(err.Error(), "dial registry TLS") {
		t.Fatalf("error should mention TLS dial: %v", err)
	}
}

func TestDialTLSPinnedFailsConnectToPlainServer(t *testing.T) {
	t.Parallel()
	addr, stop := closeOnAcceptListener(t)
	defer stop()
	_, err := DialTLSPinned(addr, "deadbeef")
	if err == nil {
		t.Fatalf("expected TLS pin error")
	}
	if !strings.Contains(err.Error(), "dial registry TLS pinned") {
		t.Fatalf("error should mention TLS pinned dial: %v", err)
	}
}

func TestCloseSafeWhenNilConn(t *testing.T) {
	t.Parallel()
	c := &Client{}
	if err := c.Close(); err != nil {
		t.Fatalf("Close on empty client should not error: %v", err)
	}
	if !c.closed {
		t.Fatalf("client should report closed after Close()")
	}
}

func TestCloseClosesRealConn(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// After Close, conn.Write should error.
	if _, err := c.conn.Write([]byte{0}); err == nil {
		t.Fatalf("expected write error after Close")
	}
}

// --- Signer -----------------------------------------------------------------

func TestSetSignerReturnsSignature(t *testing.T) {
	t.Parallel()
	c := &Client{}
	sig, err := c.sign("whatever")
	if err == nil {
		t.Fatalf("expected error with no signer, got sig=%q", sig)
	}
	c.SetSigner(func(challenge string) string {
		return "sig(" + challenge + ")"
	})
	sig, err = c.sign("abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig != "sig(abc)" {
		t.Fatalf("expected sig(abc), got %q", sig)
	}
}

func TestResolveIncludesSignatureWhenSignerSet(t *testing.T) {
	t.Parallel()
	var gotChallenge string
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	c.SetSigner(func(challenge string) string {
		gotChallenge = challenge
		return "SIG"
	})
	resp, err := c.Resolve(42, 7)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if gotChallenge != "resolve:7:42" {
		t.Fatalf("challenge: want resolve:7:42, got %q", gotChallenge)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if sig, _ := echo["signature"].(string); sig != "SIG" {
		t.Fatalf("signature wire value: want SIG, got %q", sig)
	}
}

// --- Send / sendLocked ------------------------------------------------------

func TestSendReturnsServerErrorResponse(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, func(_ map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "boom"}
	})
	defer srv.close()

	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	resp, err := c.Send(map[string]interface{}{"type": "ping"})
	if err == nil {
		t.Fatalf("expected server error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error should contain 'boom': %v", err)
	}
	// resp is non-nil for server errors so the caller can inspect it.
	if resp == nil {
		t.Fatalf("expected non-nil response on server error")
	}
}

func TestSendHappyPath(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	resp, err := c.Send(map[string]interface{}{"type": "hello", "num": float64(3)})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got, _ := resp["type"].(string); got != "ok" {
		t.Fatalf("type: want ok, got %q", got)
	}
}

func TestSendReconnectsAfterDroppedConnection(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Simulate a connection-level failure by closing the client's conn
	// without marking the Client closed. The next Send should reconnect.
	c.mu.Lock()
	_ = c.conn.Close()
	c.mu.Unlock()

	resp, err := c.Send(map[string]interface{}{"type": "hello"})
	if err != nil {
		t.Fatalf("send after reconnect: %v", err)
	}
	if got, _ := resp["type"].(string); got != "ok" {
		t.Fatalf("type: want ok, got %q", got)
	}
	if srv.connections.Load() < 2 {
		t.Fatalf("expected second connection from reconnect, got %d", srv.connections.Load())
	}
}

func TestSendFailsWhenClosed(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()

	_, err = c.Send(map[string]interface{}{"type": "hello"})
	if err == nil {
		t.Fatalf("expected error after Close")
	}
}

// --- Register family --------------------------------------------------------

func TestRegisterSendsCorrectWireMessage(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	resp, err := c.Register("1.2.3.4:4000")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if got, _ := echo["type"].(string); got != "register" {
		t.Fatalf("wire type: want register, got %q", got)
	}
	if got, _ := echo["listen_addr"].(string); got != "1.2.3.4:4000" {
		t.Fatalf("listen_addr: want 1.2.3.4:4000, got %q", got)
	}
}

func TestRegisterWithOwnerIncludesOwner(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	resp, err := c.RegisterWithOwner("x:1", "alice@example.com")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if got, _ := echo["owner"].(string); got != "alice@example.com" {
		t.Fatalf("owner: %q", got)
	}
}

func TestRegisterWithKeyOmitsBlankOwnerAndLAN(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	resp, err := c.RegisterWithKey("x:1", "PUB==", "", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if _, ok := echo["owner"]; ok {
		t.Fatalf("owner should be omitted when blank")
	}
	if _, ok := echo["lan_addrs"]; ok {
		t.Fatalf("lan_addrs should be omitted when empty")
	}
	if _, ok := echo["version"]; ok {
		t.Fatalf("version should be omitted when not supplied")
	}
	if got, _ := echo["public_key"].(string); got != "PUB==" {
		t.Fatalf("public_key: %q", got)
	}
}

func TestRegisterWithKeyIncludesAllFields(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	resp, err := c.RegisterWithKey("x:1", "PUB==", "bob", []string{"10.0.0.1:80"}, "v1.2.3")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if got, _ := echo["owner"].(string); got != "bob" {
		t.Fatalf("owner: %q", got)
	}
	if got, _ := echo["version"].(string); got != "v1.2.3" {
		t.Fatalf("version: %q", got)
	}
	lan, _ := echo["lan_addrs"].([]interface{})
	if len(lan) != 1 || lan[0] != "10.0.0.1:80" {
		t.Fatalf("lan_addrs: %v", lan)
	}
}

// --- Lookup / Resolve / ReportTrust / RevokeTrust / SetVisibility ----------

func TestLookupSendsNodeID(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	resp, err := c.Lookup(42)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if got, _ := echo["type"].(string); got != "lookup" {
		t.Fatalf("type: %q", got)
	}
	if got := uint32(echo["node_id"].(float64)); got != 42 {
		t.Fatalf("node_id: %d", got)
	}
}

func TestReportTrustAndRevokeTrustFormat(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()
	c.SetSigner(func(ch string) string { return "SIG:" + ch })

	for name, fn := range map[string]func() (map[string]interface{}, error){
		"report_trust": func() (map[string]interface{}, error) { return c.ReportTrust(1, 2) },
		"revoke_trust": func() (map[string]interface{}, error) { return c.RevokeTrust(1, 2) },
	} {
		resp, err := fn()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		echo, _ := resp["echo"].(map[string]interface{})
		if got, _ := echo["type"].(string); got != name {
			t.Fatalf("%s: type=%q", name, got)
		}
		if got := uint32(echo["node_id"].(float64)); got != 1 {
			t.Fatalf("%s: node_id=%d", name, got)
		}
		if got := uint32(echo["peer_id"].(float64)); got != 2 {
			t.Fatalf("%s: peer_id=%d", name, got)
		}
	}
}

func TestSetVisibilityPublicFlagSerialized(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()
	c.SetSigner(func(ch string) string { return "SIG:" + ch })

	resp, err := c.SetVisibility(9, true)
	if err != nil {
		t.Fatalf("set_visibility: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if got, _ := echo["public"].(bool); got != true {
		t.Fatalf("public: %v", got)
	}
}

// --- CreateNetwork / CreateManagedNetwork ----------------------------------

func TestCreateNetworkBasicAndFull(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	// Basic: no adminToken, no enterprise, no networkAdminToken.
	resp, err := c.CreateNetwork(1, "foo", "public", "tok", "", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if _, ok := echo["admin_token"]; ok {
		t.Fatalf("admin_token should be omitted when blank")
	}
	if _, ok := echo["enterprise"]; ok {
		t.Fatalf("enterprise should be omitted when false")
	}
	if _, ok := echo["network_admin_token"]; ok {
		t.Fatalf("network_admin_token should be omitted when not supplied")
	}

	// Full: adminToken + enterprise + networkAdminToken.
	resp, err = c.CreateNetwork(1, "foo", "public", "tok", "ADM", true, "NAT")
	if err != nil {
		t.Fatalf("create full: %v", err)
	}
	echo, _ = resp["echo"].(map[string]interface{})
	if got, _ := echo["admin_token"].(string); got != "ADM" {
		t.Fatalf("admin_token: %q", got)
	}
	if got, _ := echo["enterprise"].(bool); !got {
		t.Fatalf("enterprise: %v", got)
	}
	if got, _ := echo["network_admin_token"].(string); got != "NAT" {
		t.Fatalf("network_admin_token: %q", got)
	}
}

func TestCreateManagedNetworkIncludesRules(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	resp, err := c.CreateManagedNetwork(2, "n", "invite", "tok", "", false, `{"a":1}`)
	if err != nil {
		t.Fatalf("managed: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if got, _ := echo["rules"].(string); got != `{"a":1}` {
		t.Fatalf("rules: %q", got)
	}
}

// --- RotateKey --------------------------------------------------------------

func TestRotateKeyOmitsBlankSignatureAndPubKey(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	resp, err := c.RotateKey(7, "", "")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if _, ok := echo["signature"]; ok {
		t.Fatalf("signature should be omitted when blank")
	}
	if _, ok := echo["new_public_key"]; ok {
		t.Fatalf("new_public_key should be omitted when blank")
	}

	resp, err = c.RotateKey(7, "SIG", "NPK")
	if err != nil {
		t.Fatalf("rotate full: %v", err)
	}
	echo, _ = resp["echo"].(map[string]interface{})
	if got, _ := echo["signature"].(string); got != "SIG" {
		t.Fatalf("signature: %q", got)
	}
	if got, _ := echo["new_public_key"].(string); got != "NPK" {
		t.Fatalf("new_public_key: %q", got)
	}
}

func minimalTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // test-only
}
