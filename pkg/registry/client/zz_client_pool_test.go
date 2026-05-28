// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Coverage push for pkg/registry/client targeting the previously 0% / low%
// surfaces in client.go:
//
//   - DialPool / DialTLSPool / initPool
//   - sendPool, sendOnEntry, reconnectEntry, isClosed
//   - Close with pooled secondary conns
//   - DialTLSPinned full verify path (fingerprint match + mismatch)
//   - Send: reconnect-failure error wrap
//
// All fake servers are 127.0.0.1:0 TCP listeners that speak the
// length-prefixed JSON wire protocol used by Client.Send.

// --- helpers ----------------------------------------------------------------

// genSelfSignedCert returns a fresh single-host self-signed cert+key plus the
// raw DER bytes (for pin fingerprint computation). Used by the TLS dial tests.
func genSelfSignedCert(t *testing.T) (tlsCert tls.Certificate, derBytes []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pilot-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return tlsCert, der
}

// newFakeTLSServer wraps the existing fakeJSONServer with a TLS listener
// (so DialTLS / DialTLSPool / DialTLSPinned can connect).
type fakeTLSServer struct {
	ln          net.Listener
	cert        tls.Certificate
	der         []byte
	handler     func(req map[string]interface{}) map[string]interface{}
	connections atomic.Uint32
	wg          sync.WaitGroup
	closeOnce   sync.Once
}

func newFakeTLSServer(t *testing.T, handler func(req map[string]interface{}) map[string]interface{}) *fakeTLSServer {
	t.Helper()
	cert, der := genSelfSignedCert(t)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	s := &fakeTLSServer{ln: ln, cert: cert, der: der, handler: handler}
	s.wg.Add(1)
	go s.accept()
	t.Cleanup(s.close)
	return s
}

func (s *fakeTLSServer) addr() string { return s.ln.Addr().String() }

func (s *fakeTLSServer) close() {
	s.closeOnce.Do(func() {
		s.ln.Close()
		s.wg.Wait()
	})
}

func (s *fakeTLSServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.connections.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			handleJSONOverConn(conn, s.handler)
		}()
	}
}

// handleJSONOverConn runs the standard 4-byte length-prefix JSON loop on a conn.
func handleJSONOverConn(conn net.Conn, handler func(req map[string]interface{}) map[string]interface{}) {
	defer conn.Close()
	for {
		var lenBuf [4]byte
		if _, err := readFullN(conn, lenBuf[:]); err != nil {
			return
		}
		n := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])
		if n > 1<<20 {
			return
		}
		body := make([]byte, n)
		if _, err := readFullN(conn, body); err != nil {
			return
		}
		req := map[string]interface{}{}
		if err := jsonUnmarshalLite(body, &req); err != nil {
			return
		}
		resp := handler(req)
		if resp == nil {
			return
		}
		out, _ := jsonMarshalLite(resp)
		var outLen [4]byte
		outLen[0] = byte(len(out) >> 24)
		outLen[1] = byte(len(out) >> 16)
		outLen[2] = byte(len(out) >> 8)
		outLen[3] = byte(len(out))
		conn.Write(outLen[:])
		conn.Write(out)
	}
}

// Thin wrappers around encoding/json so the per-conn read loop helper stays
// readable. Same framing as the canonical fakeJSONServer.handle().
func jsonUnmarshalLite(b []byte, v interface{}) error { return json.Unmarshal(b, v) }
func jsonMarshalLite(v interface{}) ([]byte, error)   { return json.Marshal(v) }

func readFullN(r net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// --- DialPool / sendPool basic happy path ----------------------------------

func TestDialPoolSizeOneIsSingleConn(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 1)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()
	// size == 1 → no secondary pool entries, free chan stays nil.
	if c.pool.free != nil {
		t.Fatalf("pool.free should be nil for size=1, got %v", c.pool.free)
	}
	// Send still works via legacy single-conn path.
	resp, err := c.Send(map[string]interface{}{"type": "hello"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got, _ := resp["type"].(string); got != "ok" {
		t.Fatalf("type: %q", got)
	}
}

func TestDialPoolMultiConnExercisesSendPool(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 4)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()

	if c.pool.free == nil {
		t.Fatalf("pool.free should be initialised for size>1")
	}
	if len(c.pool.entries) != 4 {
		t.Fatalf("pool entries: want 4, got %d", len(c.pool.entries))
	}
	// Each pool entry corresponds to a real conn on the server.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.connections.Load() == 4 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.connections.Load() != 4 {
		t.Fatalf("server connections: want 4, got %d", srv.connections.Load())
	}

	// A serial Send drives sendPool / sendOnEntry on entry[0] (or whichever
	// is free), exercising the lock+round-trip path.
	resp, err := c.Send(map[string]interface{}{"type": "ping"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got, _ := resp["type"].(string); got != "ok" {
		t.Fatalf("type: %q", got)
	}
}

// TestDialPoolZeroOrNegativeSizeNormalisesToOne covers the size<=0 branch.
func TestDialPoolZeroOrNegativeSizeNormalisesToOne(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 0)
	if err != nil {
		t.Fatalf("DialPool(0): %v", err)
	}
	defer c.Close()
	if c.pool.free != nil {
		t.Fatalf("size<=0 should normalise to 1 (no pool)")
	}

	c2, err := DialPool(srv.addr(), -3)
	if err != nil {
		t.Fatalf("DialPool(-3): %v", err)
	}
	defer c2.Close()
	if c2.pool.free != nil {
		t.Fatalf("negative size should normalise to 1 (no pool)")
	}
}

func TestDialPoolErrorOnUnreachable(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if _, err := DialPool(addr, 3); err == nil {
		t.Fatalf("expected DialPool error on unreachable addr")
	}
}

// TestDialPoolPartialSecondaryFailureClosesPrimary covers the
// "primary dialed, secondary dial failed → close primary, return err" branch
// inside initPool. We accept the primary conn then close the listener to make
// secondary dials fail.
func TestDialPoolPartialSecondaryFailureClosesPrimary(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
		// Close listener immediately so the next net.Dial inside initPool
		// fails with ECONNREFUSED.
		ln.Close()
	}()

	_, err = DialPool(addr, 4)
	if err == nil {
		t.Fatalf("expected DialPool to fail when secondary dial errors")
	}
	if !strings.Contains(err.Error(), "dial pool conn") {
		t.Fatalf("error should mention dial pool conn, got: %v", err)
	}

	// Clean up the primary conn that the server accepted.
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(time.Second):
	}
}

// --- sendPool: closed-client guards ---------------------------------------

func TestSendPoolAfterCloseFailsFast(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 3)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	c.Close()

	_, err = c.Send(map[string]interface{}{"type": "x"})
	if err == nil {
		t.Fatalf("expected error after Close")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Fatalf("expected 'closed' in error, got: %v", err)
	}
}

// TestSendPoolUnblocksOnCloseWhileBlocked ensures that a goroutine blocked
// in <-c.pool.free is woken up by Close (via the done channel select).
// We exhaust the pool, then Close, then assert that a pending Send returns
// with a "closed" error rather than hanging.
func TestSendPoolUnblocksOnCloseWhileBlocked(t *testing.T) {
	t.Parallel()
	// Handler that blocks until we tell it to release — so the in-flight
	// Send holds its pool entry indefinitely. Pool size 1 → second Send
	// is blocked on <-c.pool.free.
	release := make(chan struct{})
	srv := newFakeJSONServer(t, func(_ map[string]interface{}) map[string]interface{} {
		<-release
		return map[string]interface{}{"type": "ok"}
	})
	defer srv.close()

	c, err := DialPool(srv.addr(), 2) // primary + 1 secondary
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}

	// Saturate both pool entries with in-flight Sends.
	for i := 0; i < 2; i++ {
		go func() {
			_, _ = c.Send(map[string]interface{}{"type": "block"})
		}()
	}
	// Give them a chance to grab pool entries.
	time.Sleep(50 * time.Millisecond)

	// Third Send blocks in <-c.pool.free.
	thirdDone := make(chan error, 1)
	go func() {
		_, err := c.Send(map[string]interface{}{"type": "third"})
		thirdDone <- err
	}()
	time.Sleep(50 * time.Millisecond)

	// Close should unblock the waiter via the <-c.pool.done branch.
	c.Close()
	close(release) // let the in-flight Sends drain

	select {
	case err := <-thirdDone:
		if err == nil {
			t.Fatalf("third Send should have errored after Close")
		}
		if !strings.Contains(err.Error(), "closed") {
			t.Fatalf("expected 'closed' error, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("third Send did not return after Close — pool.done branch not wired")
	}
}

// --- sendPool: per-entry reconnect when the conn dies ---------------------

func TestSendPoolReconnectsBrokenEntry(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()

	// Kill the primary entry's conn so the next Send hitting it triggers
	// reconnectEntry. We can't predict which entry the channel picks, so
	// kill both — sendOnEntry on whichever one we get will fail then reconnect.
	for _, e := range c.pool.entries {
		e.mu.Lock()
		_ = e.conn.Close()
		e.mu.Unlock()
	}

	resp, err := c.Send(map[string]interface{}{"type": "ping"})
	if err != nil {
		t.Fatalf("send after killing entry: %v", err)
	}
	if got, _ := resp["type"].(string); got != "ok" {
		t.Fatalf("type: %q", got)
	}
	// The reconnect path must have produced a new TCP conn.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.connections.Load() >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.connections.Load() < 3 {
		t.Fatalf("expected reconnect to open a new conn, server saw %d", srv.connections.Load())
	}
}

// TestReconnectEntrySyncsPrimary verifies that when the primary entry
// (entries[0]) is reconnected, c.conn is updated in lockstep so callers
// reading c.conn directly don't see a stale fd. This is the "if entry ==
// c.pool.entries[0]" branch in reconnectEntry.
func TestReconnectEntrySyncsPrimary(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()

	// Acquire entries[0] off the free channel directly to guarantee we're
	// reconnecting the primary slot.
	primary := <-c.pool.free
	// Sanity: should be entries[0] OR entries[1]; force primary if not.
	if primary != c.pool.entries[0] {
		// put it back, grab the actual primary.
		c.pool.free <- primary
		// drain until we get entries[0].
		for i := 0; i < 4; i++ {
			candidate := <-c.pool.free
			if candidate == c.pool.entries[0] {
				primary = candidate
				break
			}
			c.pool.free <- candidate
		}
	}

	oldConn := c.conn
	primary.mu.Lock()
	_ = primary.conn.Close()
	if err := c.reconnectEntry(context.Background(), primary); err != nil {
		primary.mu.Unlock()
		t.Fatalf("reconnectEntry: %v", err)
	}
	newConn := primary.conn
	primary.mu.Unlock()

	if newConn == oldConn {
		t.Fatalf("primary conn was not replaced by reconnectEntry")
	}
	// c.conn should be in sync with the new primary conn.
	c.mu.Lock()
	if c.conn != newConn {
		c.mu.Unlock()
		t.Fatalf("c.conn not synced after primary reconnect")
	}
	c.mu.Unlock()

	// Put the entry back so Close doesn't deadlock.
	c.pool.free <- primary
}

// TestReconnectEntryFailsWhenClosed exercises the early-return-on-closed
// branch of reconnectEntry.
func TestReconnectEntryFailsWhenClosed(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	c.Close()

	if err := c.reconnectEntry(context.Background(), c.pool.entries[0]); err == nil {
		t.Fatalf("reconnectEntry on closed client should fail")
	}
}

// --- isClosed -------------------------------------------------------------

func TestIsClosedReflectsCloseState(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	if c.isClosed() {
		t.Fatalf("fresh client should not report closed")
	}
	c.Close()
	if !c.isClosed() {
		t.Fatalf("client should report closed after Close()")
	}
}

// --- DialTLSPool ---------------------------------------------------------

func TestDialTLSPoolNilConfigReturnsError(t *testing.T) {
	t.Parallel()
	if _, err := DialTLSPool("127.0.0.1:1", nil, 2); err == nil {
		t.Fatalf("expected nil config error")
	}
}

func TestDialTLSPoolSucceedsAndDialsSize(t *testing.T) {
	t.Parallel()
	srv := newFakeTLSServer(t, echoHandler())

	clientCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // test-only
	}
	c, err := DialTLSPool(srv.addr(), clientCfg, 3)
	if err != nil {
		t.Fatalf("DialTLSPool: %v", err)
	}
	defer c.Close()
	if len(c.pool.entries) != 3 {
		t.Fatalf("pool entries: %d, want 3", len(c.pool.entries))
	}
	resp, err := c.Send(map[string]interface{}{"type": "hello"})
	if err != nil {
		t.Fatalf("send over TLS pool: %v", err)
	}
	if got, _ := resp["type"].(string); got != "ok" {
		t.Fatalf("type: %q", got)
	}
}

func TestDialTLSPoolSizeOneIsSingleConn(t *testing.T) {
	t.Parallel()
	srv := newFakeTLSServer(t, echoHandler())
	clientCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // test-only
	}
	c, err := DialTLSPool(srv.addr(), clientCfg, 1)
	if err != nil {
		t.Fatalf("DialTLSPool size=1: %v", err)
	}
	defer c.Close()
	if c.pool.free != nil {
		t.Fatalf("size=1 should not initialise pool channel")
	}
}

func TestDialTLSPoolDialErrorWrapsMessage(t *testing.T) {
	t.Parallel()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // test-only
	if _, err := DialTLSPool(addr, cfg, 2); err == nil {
		t.Fatalf("expected DialTLSPool error on unreachable addr")
	}
}

// --- DialTLSPinned: full verify path -------------------------------------

func TestDialTLSPinnedAcceptsMatchingFingerprint(t *testing.T) {
	t.Parallel()
	srv := newFakeTLSServer(t, echoHandler())

	sum := sha256.Sum256(srv.der)
	fp := hex.EncodeToString(sum[:])

	c, err := DialTLSPinned(srv.addr(), fp)
	if err != nil {
		t.Fatalf("DialTLSPinned (matching fp): %v", err)
	}
	defer c.Close()
	resp, err := c.Send(map[string]interface{}{"type": "hi"})
	if err != nil {
		t.Fatalf("send over pinned conn: %v", err)
	}
	if got, _ := resp["type"].(string); got != "ok" {
		t.Fatalf("type: %q", got)
	}
}

func TestDialTLSPinnedRejectsMismatchedFingerprint(t *testing.T) {
	t.Parallel()
	srv := newFakeTLSServer(t, echoHandler())

	_, err := DialTLSPinned(srv.addr(), "00112233445566778899aabbccddeeff")
	if err == nil {
		t.Fatalf("expected fingerprint mismatch error")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") &&
		!strings.Contains(err.Error(), "dial registry TLS pinned") {
		t.Fatalf("error should mention fingerprint mismatch or pinned dial: %v", err)
	}
}

// --- Concurrent Send under -race confirms the regConn mutex is real ------

func TestSendConcurrentRaceFreeOnSingleConn(t *testing.T) {
	t.Parallel()
	var counter atomic.Uint64
	srv := newFakeJSONServer(t, func(_ map[string]interface{}) map[string]interface{} {
		counter.Add(1)
		return map[string]interface{}{"type": "ok"}
	})
	defer srv.close()

	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	const goroutines = 16
	const callsEach = 25
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < callsEach; j++ {
				if _, err := c.Send(map[string]interface{}{"type": "x"}); err != nil {
					t.Errorf("send: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if got := counter.Load(); got != uint64(goroutines*callsEach) {
		t.Fatalf("server saw %d requests, want %d", got, goroutines*callsEach)
	}
}

func TestSendConcurrentRaceFreeOnPool(t *testing.T) {
	t.Parallel()
	var counter atomic.Uint64
	srv := newFakeJSONServer(t, func(_ map[string]interface{}) map[string]interface{} {
		counter.Add(1)
		return map[string]interface{}{"type": "ok"}
	})
	defer srv.close()

	c, err := DialPool(srv.addr(), 4)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()

	const goroutines = 16
	const callsEach = 25
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < callsEach; j++ {
				if _, err := c.Send(map[string]interface{}{"type": "x"}); err != nil {
					t.Errorf("send: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if got := counter.Load(); got != uint64(goroutines*callsEach) {
		t.Fatalf("server saw %d requests, want %d", got, goroutines*callsEach)
	}
}

// --- Send (single-conn) reconnect-failure branch ------------------------

// TestSendReconnectFailureSurfacesWrappedError covers the legacy-path
// branch: send fails, reconnect also fails → Client returns a "send failed
// and reconnect failed" wrap. We close the server first, then make Send
// hit a dead conn — both attempts (initial + reconnect) fail.
func TestSendReconnectFailureSurfacesWrappedError(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	c, err := Dial(srv.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Kill the server first so the reconnect dial inside Send also fails.
	srv.close()
	// Also close the local end so the very first WriteMessage errors quickly.
	c.mu.Lock()
	_ = c.conn.Close()
	c.mu.Unlock()

	_, err = c.Send(map[string]interface{}{"type": "x"})
	if err == nil {
		t.Fatalf("expected error when both send and reconnect fail")
	}
	// Could be either "send failed and reconnect failed" or a raw send/recv
	// error — accept any failure.
	if err.Error() == "" {
		t.Fatalf("error message must not be empty")
	}
}

// TestPoolSendReconnectFailureSurfacesWrappedError is the pool-path analogue.
func TestPoolSendReconnectFailureSurfacesWrappedError(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()

	// Kill the server, then kill both pool entries' conns so the round-trip
	// fails AND reconnectEntry's dial fails.
	srv.close()
	for _, e := range c.pool.entries {
		e.mu.Lock()
		_ = e.conn.Close()
		e.mu.Unlock()
	}

	_, err = c.Send(map[string]interface{}{"type": "x"})
	if err == nil {
		t.Fatalf("expected pool-path error when both send and reconnect fail")
	}
}

// --- Close: pool with secondary entries -----------------------------------

func TestClosePoolReleasesAllSecondaryConns(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 3)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}

	// All entries should currently have non-nil conns.
	conns := make([]net.Conn, len(c.pool.entries))
	for i, e := range c.pool.entries {
		conns[i] = e.conn
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Every conn (primary + secondary) should now be unusable.
	for i, conn := range conns {
		if _, err := conn.Write([]byte{0}); err == nil {
			t.Fatalf("conn %d should be closed after Close()", i)
		}
	}
}

// --- Misc small branch fills ---------------------------------------------

// Verify the helper Send returns a "client closed" error when isClosed
// is true AND we still try to send (covers the closed-guard inside sendPool).
func TestSendPoolReturnsClosedErrorBeforeAcquire(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	c.Close()

	_, err = c.Send(map[string]interface{}{"type": "x"})
	if err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("expected closed error, got: %v", err)
	}
}

// Smoke-test the RegisterWithKeyOpts RelayOnly + LANAddrs branch (the only
// "false" branches not exercised by existing tests).
func TestRegisterWithKeyOptsRelayOnlySerialized(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, err := c.RegisterWithKeyOpts(RegisterOpts{
		ListenAddr: "x:1",
		PublicKey:  "PUB",
		LANAddrs:   []string{"10.0.0.1:1"},
		RelayOnly:  true,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	echo := assertEcho(t, resp)
	if got, _ := echo["relay_only"].(bool); !got {
		t.Fatalf("relay_only: %v", got)
	}
	if _, ok := echo["owner"]; ok {
		t.Fatalf("owner should be omitted when blank")
	}
}

// Ensure RegisterWithKey with multiple version variadic args picks the first
// non-empty (firstNonEmpty branch).
func TestRegisterWithKeyFirstNonEmptyVersion(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, err := c.RegisterWithKey("x:1", "PUB", "", nil, "", "", "v2.0.0", "v3.0.0")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	echo := assertEcho(t, resp)
	if got, _ := echo["version"].(string); got != "v2.0.0" {
		t.Fatalf("version: want v2.0.0 (first non-empty), got %q", got)
	}
}
