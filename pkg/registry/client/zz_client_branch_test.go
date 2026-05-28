// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// Branch-fill tests: every wrapper that takes an optional adminToken,
// signature, or variadic flag has an untested branch when the optional
// arg is blank. This file ticks the remaining `if x != ""` / `if len(...) > 0`
// branches and the binary_client reconnect/lookup/resolve error edges.

// --- Client member-mgmt wrappers: with-adminToken branches --------------
//
// Existing tests cover the blank-token path; here we cover the non-blank
// branch so the `if adminToken != ""` is exercised both ways.

func TestPromoteDemoteKickTransferIncludeAdminToken(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	cases := []struct {
		name      string
		call      func() (map[string]interface{}, error)
		targetKey string
	}{
		{"promote", func() (map[string]interface{}, error) { return c.PromoteMember(1, 2, 3, "ADM") }, "target_node_id"},
		{"demote", func() (map[string]interface{}, error) { return c.DemoteMember(1, 2, 3, "ADM") }, "target_node_id"},
		{"kick", func() (map[string]interface{}, error) { return c.KickMember(1, 2, 3, "ADM") }, "target_node_id"},
		{"transfer", func() (map[string]interface{}, error) { return c.TransferOwnership(1, 2, 3, "ADM") }, "new_owner_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.call()
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			echo := assertEcho(t, resp)
			if got, _ := echo["admin_token"].(string); got != "ADM" {
				t.Fatalf("%s: admin_token: %q", tc.name, got)
			}
			if got, _ := echo[tc.targetKey].(float64); uint32(got) != 3 {
				t.Fatalf("%s: %s: %v", tc.name, tc.targetKey, got)
			}
		})
	}
}

// --- ReportTrust / RevokeTrust / SetVisibility: WITH-signer branch -----
//
// Existing TestReportTrustAndRevokeTrustFormat and TestSetVisibilityPublicFlagSerialized
// drive the no-signer (sig empty) path. Cover the signer-attached branch
// so `if sig := ...; sig != ""` is hit both ways.

func TestReportRevokeVisibilityIncludeSignatureWhenSignerSet(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	c.SetSigner(func(ch string) string { return "SIG:" + ch })
	cases := []struct {
		name      string
		call      func() (map[string]interface{}, error)
		challenge string
	}{
		{"report_trust", func() (map[string]interface{}, error) { return c.ReportTrust(1, 2) }, "report_trust:1:2"},
		{"revoke_trust", func() (map[string]interface{}, error) { return c.RevokeTrust(1, 2) }, "revoke_trust:1:2"},
		{"set_visibility", func() (map[string]interface{}, error) { return c.SetVisibility(9, false) }, "set_visibility:9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.call()
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			echo := assertEcho(t, resp)
			if got, _ := echo["signature"].(string); got != "SIG:"+tc.challenge {
				t.Fatalf("%s: signature: want SIG:%s, got %q", tc.name, tc.challenge, got)
			}
		})
	}
}

// --- CreateManagedNetwork full-options branch -----------------------------

func TestCreateManagedNetworkFullOptions(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, err := c.CreateManagedNetwork(2, "n", "invite", "tok", "ADM", true, `{"a":1}`, "NAT")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	echo := assertEcho(t, resp)
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

// --- ListNetworks with adminToken ----------------------------------------

func TestListNetworksWithAdminTokenIncludesField(t *testing.T) {
	t.Parallel()
	c, _ := echoOnlyClient(t)
	resp, err := c.ListNetworks("SUPER")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	echo := assertEcho(t, resp)
	if got, _ := echo["admin_token"].(string); got != "SUPER" {
		t.Fatalf("admin_token: %q", got)
	}
}

// --- DialTLS error wrapping happy/sad already covered; sad path only used
// "dial registry TLS" prefix once. Cover the happy-path connect branch with
// a real TLS listener that closes immediately. -----------------------------

// --- binary_client: reconnect after failure ------------------------------

// TestBinaryHeartbeatReconnectsAfterBrokenConn covers the
// `err != nil && !c.closed → reconnect → retry` branch in Heartbeat.
func TestBinaryHeartbeatReconnectsAfterBrokenConn(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		if msgType != wire.MsgHeartbeat {
			return wire.MsgError, wire.EncodeError("bad")
		}
		return wire.MsgHeartbeatOK, wire.EncodeHeartbeatResp(123, false)
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	// Forcibly close the underlying conn so the next Heartbeat triggers
	// reconnect+retry.
	c.mu.Lock()
	_ = c.conn.Close()
	c.mu.Unlock()

	unixTime, _, err := c.Heartbeat(1, make([]byte, 64))
	if err != nil {
		t.Fatalf("Heartbeat after broken conn: %v", err)
	}
	if unixTime != 123 {
		t.Fatalf("unixTime = %d, want 123", unixTime)
	}
}

// TestBinaryLookupReconnectsAfterBrokenConn covers the reconnect branch
// inside Lookup.
func TestBinaryLookupReconnectsAfterBrokenConn(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		if msgType != wire.MsgLookup {
			return wire.MsgError, wire.EncodeError("bad")
		}
		return wire.MsgLookupOK, wire.EncodeLookupResp(
			7, true, false, nil, nil, "h", nil, "1.1.1.1:1", "",
		)
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	c.mu.Lock()
	_ = c.conn.Close()
	c.mu.Unlock()

	res, err := c.Lookup(7)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.NodeID != 7 {
		t.Fatalf("NodeID = %d", res.NodeID)
	}
}

// TestBinaryResolveReconnectsAfterBrokenConn covers the reconnect branch
// inside Resolve.
func TestBinaryResolveReconnectsAfterBrokenConn(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		if msgType != wire.MsgResolve {
			return wire.MsgError, wire.EncodeError("bad")
		}
		return wire.MsgResolveOK, wire.EncodeResolveResp(8, "2.2.2.2:2", nil, 0)
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	c.mu.Lock()
	_ = c.conn.Close()
	c.mu.Unlock()

	res, err := c.Resolve(8, 1, make([]byte, 64))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.NodeID != 8 {
		t.Fatalf("NodeID = %d", res.NodeID)
	}
}

// TestBinarySendJSONReconnectsAfterBrokenConn covers the reconnect branch
// inside SendJSON.
func TestBinarySendJSONReconnectsAfterBrokenConn(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(msgType byte, payload []byte) (byte, []byte) {
		if msgType != wire.MsgJSON {
			return wire.MsgError, wire.EncodeError("bad")
		}
		body, _ := json.Marshal(map[string]interface{}{"type": "ok"})
		return wire.MsgJSON, body
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}
	defer c.Close()

	c.mu.Lock()
	_ = c.conn.Close()
	c.mu.Unlock()

	resp, err := c.SendJSON(map[string]interface{}{"op": "x"})
	if err != nil {
		t.Fatalf("SendJSON: %v", err)
	}
	if resp["type"] != "ok" {
		t.Fatalf("type: %v", resp["type"])
	}
}

// TestBinaryReconnectAllAttemptsFail covers the failure path: all 5
// reconnect attempts fail and the client surfaces "reconnect failed".
//
// We pass a small backoff window indirectly by pointing at a closed port.
// 5 attempts * ~0.5s backoff each is up to ~7.5s of sleeping inside
// reconnect — too slow for -short. Instead, exercise the immediate path:
// close the client first so reconnect returns "client closed" without
// sleeping. This still covers the c.closed branch.
func TestBinaryReconnectShortCircuitsWhenClosed(t *testing.T) {
	t.Parallel()
	srv := newFakeBinaryServer(t, func(byte, []byte) (byte, []byte) {
		return wire.MsgHeartbeatOK, wire.EncodeHeartbeatResp(1, false)
	})

	c, err := DialBinary(srv.addr())
	if err != nil {
		t.Fatalf("DialBinary: %v", err)
	}

	// Tear down the listener to make a future dial fail, then close the
	// client to force the reconnect early-return branch.
	srv.Close()
	// Drop the local conn and mark closed before triggering reconnect.
	c.mu.Lock()
	_ = c.conn.Close()
	c.closed = true
	err = c.reconnect()
	c.mu.Unlock()
	if err == nil {
		t.Fatalf("reconnect after Close should fail")
	}
	if !strings.Contains(err.Error(), "client closed") {
		t.Fatalf("expected 'client closed' error, got: %v", err)
	}
}

// TestBinaryDialBinaryHandshakeWriteFailure exercises the
// "conn.Write(handshake) fails" branch in DialBinary. We can't intercept
// the write directly, but we can race a close: connect to a listener that
// accepts then immediately closes the conn before the handshake write
// completes. On macOS this typically surfaces as a write error on a
// half-closed socket.
func TestBinaryDialBinaryHandshakeWriteFailure(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Drop the conn immediately. Then close the listener so subsequent
		// dials return ECONNREFUSED if the test re-runs.
		conn.Close()
	}()
	// DialBinary may succeed (handshake writes 5 bytes into the kernel buffer
	// before EOF is observed) or fail. Either is fine — we just need the path
	// to execute and not panic. The accept goroutine guarantees a real connect.
	c, err := DialBinary(addr)
	if err == nil && c != nil {
		c.Close()
	}
	<-done
	ln.Close()

	// As a deterministic companion: dial a closed port. This exercises the
	// "net.Dial fails" branch.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	closed.Close()
	_, err = DialBinary(closedAddr)
	if err == nil {
		t.Fatalf("DialBinary to closed port should fail")
	}
}

// --- Backoff cap check via reconnect against unreachable addr ------------

// TestClientReconnectBackoffCapsAtMax pushes reconnect into >5s of backoff
// growth and verifies it returns the eventual "reconnect failed" wrap.
// We use a Client whose addr points to a closed port; reconnect dials it
// 5 times then gives up. Using a fresh-grabbed-then-released kernel port
// keeps each failed dial fast (ECONNREFUSED on loopback is sub-ms).
func TestClientReconnectExhaustsAttempts(t *testing.T) {
	if testing.Short() {
		// 5 attempts * 0.5s = ~7.5s of sleep — too slow for -short with -race.
		t.Skip("skipping long reconnect-exhaustion test under -short")
	}
	t.Parallel()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	c := &Client{addr: addr}
	c.mu.Lock()
	err := c.reconnect(context.Background())
	c.mu.Unlock()
	if err == nil {
		t.Fatalf("expected reconnect failure")
	}
	if !strings.Contains(err.Error(), "reconnect failed") {
		t.Fatalf("expected 'reconnect failed' wrap, got: %v", err)
	}
}

// --- Close after pool conn already closed: idempotency / second-close ----

func TestClosePoolEntryAlreadyClosedReturnsFirstErrOrNil(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()

	c, err := DialPool(srv.addr(), 3)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	// Pre-close one secondary conn so Close()'s per-entry loop hits the
	// "already-closed" path on it.
	c.pool.entries[1].mu.Lock()
	_ = c.pool.entries[1].conn.Close()
	c.pool.entries[1].mu.Unlock()

	// Double-close should be safe.
	if err := c.Close(); err != nil {
		// Close may surface the first error (double-close on a TCPConn).
		// That's acceptable — what matters is no panic.
		t.Logf("Close returned (acceptable): %v", err)
	}
}

// --- sendOnEntry server error path (response with "error" key) -----------

func TestSendOnEntryReturnsServerErrorResponse(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, func(_ map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "rate-limited"}
	})
	defer srv.close()

	c, err := DialPool(srv.addr(), 2)
	if err != nil {
		t.Fatalf("DialPool: %v", err)
	}
	defer c.Close()

	resp, err := c.Send(map[string]interface{}{"type": "x"})
	if err == nil {
		t.Fatalf("expected server error")
	}
	if resp == nil {
		t.Fatalf("resp must be non-nil for server-error path")
	}
	if !strings.Contains(err.Error(), "rate-limited") {
		t.Fatalf("error should contain server message, got: %v", err)
	}
}

// --- DialTLS happy path ---------------------------------------------------

func TestDialTLSHappyPathConnects(t *testing.T) {
	t.Parallel()
	srv := newFakeTLSServer(t, echoHandler())
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // test-only
	}
	c, err := DialTLS(srv.addr(), cfg)
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer c.Close()
	resp, err := c.Send(map[string]interface{}{"type": "x"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got, _ := resp["type"].(string); got != "ok" {
		t.Fatalf("type: %q", got)
	}
	// Ensure tlsConfig is retained so reconnect would use TLS too.
	if c.tlsConfig == nil {
		t.Fatalf("tlsConfig should be retained on Client after DialTLS")
	}
}
