// SPDX-License-Identifier: AGPL-3.0-or-later

package wss_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/transport"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/transport/wss"
)

// fakeBeacon is an httptest.NewTLSServer that speaks the beacon WSS
// protocol: it accepts the WS upgrade, sends an auth challenge,
// verifies the daemon's Ed25519 signature, and then echoes binary
// frames back. Used to drive end-to-end Dial → Send → Recv tests
// without spinning up the real beacon.
type fakeBeacon struct {
	srv        *httptest.Server
	expectedID uint32
	t          *testing.T

	// verifyResult overrides the signature verification outcome.
	// nil = accept (default); non-nil = reject with that error
	// surfaced as "auth_fail" in the close reason.
	verifyOverride error

	// recordedFrames captures binary frames received from the daemon
	// for assertion. Append-only; guarded by srv close.
	recordedFrames [][]byte

	// killAfterFrame, when >0, makes the echo loop close the
	// active WS conn AFTER receiving (and not echoing) that frame.
	// Used by TestReconnect_AfterServerCloseRestoresSendAndRecv to
	// simulate a transient connection break. The next dial that
	// arrives at the same fakeBeacon httptest server will get a
	// fresh handle() — including a fresh auth handshake — so the
	// supervisor's redial path is exercised end-to-end.
	killAfterFrame int

	// failNextDials, when >0, makes handle() refuse upgrades for that
	// many subsequent connection attempts (counter decrements each
	// time). Used to simulate transient beacon-side outages so the
	// supervisor must keep retrying with backoff. The handler closes
	// the underlying TCP without completing the WS upgrade — same
	// shape as nginx returning 502 while the beacon process restarts.
	failNextDials int
}

func newFakeBeacon(t *testing.T, expectedNodeID uint32) *fakeBeacon {
	t.Helper()
	fb := &fakeBeacon{expectedID: expectedNodeID, t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/", fb.handle)
	fb.srv = httptest.NewTLSServer(mux)
	t.Cleanup(fb.srv.Close)
	return fb
}

func (fb *fakeBeacon) url() string {
	return strings.Replace(fb.srv.URL, "https://", "wss://", 1)
}

// tlsConfig returns a *tls.Config that trusts the httptest server's
// self-signed cert. Used by tests to dial without certificate
// verification errors.
func (fb *fakeBeacon) tlsConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(fb.srv.Certificate())
	return &tls.Config{RootCAs: pool}
}

func (fb *fakeBeacon) handle(w http.ResponseWriter, r *http.Request) {
	// Outage simulation: refuse the upgrade entirely. The httptest
	// server returns 503; the daemon's websocket.Dial fails with a
	// "did not return status 101" error which the supervisor treats
	// as a transient dial failure and retries with backoff.
	if fb.failNextDials > 0 {
		fb.failNextDials--
		http.Error(w, "beacon outage (test)", http.StatusServiceUnavailable)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"pilot.v1"},
	})
	if err != nil {
		fb.t.Logf("fake beacon: accept: %v", err)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "fake beacon defer")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Send auth challenge with a fixed nonce + timestamp so we can assert
	// on the signed payload (beacon >= v0.2.6 binds ts into the signature).
	nonce := "deadbeef12345678deadbeef12345678"
	const ts int64 = 1700000000
	ch := map[string]interface{}{"type": "auth_challenge", "nonce": nonce, "ts": ts}
	chBytes, _ := json.Marshal(ch)
	if err := conn.Write(ctx, websocket.MessageText, chBytes); err != nil {
		fb.t.Logf("fake beacon: write challenge: %v", err)
		return
	}

	// Read auth_reply.
	msgType, body, err := conn.Read(ctx)
	if err != nil {
		fb.t.Logf("fake beacon: read auth_reply: %v", err)
		return
	}
	if msgType != websocket.MessageText {
		fb.t.Logf("fake beacon: expected text auth_reply, got %v", msgType)
		conn.Close(websocket.StatusPolicyViolation, "bad reply frame")
		return
	}
	var reply struct {
		Type      string `json:"type"`
		NodeID    uint32 `json:"node_id"`
		PublicKey string `json:"public_key"`
		Sig       string `json:"sig"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		conn.Close(websocket.StatusPolicyViolation, "malformed reply")
		return
	}
	if fb.verifyOverride != nil {
		conn.Close(websocket.StatusPolicyViolation, "auth_fail (test override)")
		return
	}
	if reply.NodeID != fb.expectedID {
		conn.Close(websocket.StatusPolicyViolation, "node_id mismatch")
		return
	}
	pubBytes, err := base64.StdEncoding.DecodeString(reply.PublicKey)
	if err != nil {
		conn.Close(websocket.StatusPolicyViolation, "bad pubkey b64")
		return
	}
	sigBytes, err := base64.StdEncoding.DecodeString(reply.Sig)
	if err != nil {
		conn.Close(websocket.StatusPolicyViolation, "bad sig b64")
		return
	}
	signed := fmt.Sprintf("compat_auth:%d:%d:%s", reply.NodeID, ts, nonce)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(signed), sigBytes) {
		conn.Close(websocket.StatusPolicyViolation, "sig verify failed")
		return
	}

	// Send auth_ok.
	okBytes, _ := json.Marshal(map[string]string{"type": "auth_ok"})
	if err := conn.Write(ctx, websocket.MessageText, okBytes); err != nil {
		return
	}

	// Echo loop: binary frames in → binary frames out (prefix "echo:")
	frameCount := 0
	for {
		_, body, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		frameCount++
		fb.recordedFrames = append(fb.recordedFrames, append([]byte(nil), body...))
		// Reconnect simulation: at killAfterFrame, eat the frame and
		// drop the underlying TCP immediately so the daemon's
		// supervisor has to redial. CloseNow skips the graceful WS
		// close handshake — that's exactly what an nginx restart or
		// a TCP RST looks like from the client side, and it makes
		// the client's pending conn.Read unblock right away.
		if fb.killAfterFrame > 0 && frameCount == fb.killAfterFrame {
			_ = conn.CloseNow()
			return
		}
		out := append([]byte("echo:"), body...)
		if err := conn.Write(r.Context(), websocket.MessageBinary, out); err != nil {
			return
		}
	}
}

// TestDial_AuthSuccess pins the happy path: a legit Ed25519 identity
// completes the auth challenge and Dial returns a usable Transport.
func TestDial_AuthSuccess(t *testing.T) {
	t.Parallel()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	fb := newFakeBeacon(t, 42)

	tr, err := wss.Dial(context.Background(), wss.Config{
		URL:       fb.url(),
		TLSConfig: fb.tlsConfig(),
		Identity:  id,
		NodeID:    42,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	if tr.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}
}

// TestSendRecv_RoundTrip drives a binary frame through the WSS pipe
// and confirms the echoed response comes back. End-to-end check of
// the binary-frame mapping.
func TestSendRecv_RoundTrip(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	fb := newFakeBeacon(t, 1)

	tr, err := wss.Dial(context.Background(), wss.Config{
		URL:       fb.url(),
		TLSConfig: fb.tlsConfig(),
		Identity:  id,
		NodeID:    1,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	payload := []byte("hello pilot")
	n, err := tr.Send(payload, nil)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Send returned %d bytes; want %d", n, len(payload))
	}

	// Recv should give us the echoed frame.
	frame, src, err := tr.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	want := append([]byte("echo:"), payload...)
	if string(frame) != string(want) {
		t.Errorf("Recv frame = %q; want %q", frame, want)
	}
	// src should be the synthetic beacon addr, not nil.
	if src == nil {
		t.Error("Recv src is nil; want synthetic beacon addr")
	}
}

// TestDial_RejectedAuthFails pins that a beacon-side rejection
// closes the WS and surfaces an error from Dial. Critical: if Dial
// succeeded silently against an unauthenticated connection, the
// daemon would think compat mode is working when it isn't.
func TestDial_RejectedAuthFails(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	fb := newFakeBeacon(t, 1)
	fb.verifyOverride = errors.New("synthetic rejection")

	_, err := wss.Dial(context.Background(), wss.Config{
		URL:         fb.url(),
		TLSConfig:   fb.tlsConfig(),
		Identity:    id,
		NodeID:      1,
		DialTimeout: 3 * time.Second,
	})
	if err == nil {
		t.Fatal("Dial succeeded against rejecting beacon; expected error")
	}
}

// TestDial_RequiresConfig pins the Dial-time validation. Missing URL,
// TLSConfig, or Identity should fail loudly rather than dialing with
// dangerous defaults.
func TestDial_RequiresConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  wss.Config
		want string
	}{
		{"missing URL", wss.Config{TLSConfig: &tls.Config{}, Identity: mustID(t), NodeID: 1}, "URL is required"},
		{"missing TLSConfig", wss.Config{URL: "wss://x", Identity: mustID(t), NodeID: 1}, "TLSConfig is required"},
		{"missing Identity", wss.Config{URL: "wss://x", TLSConfig: &tls.Config{}, NodeID: 1}, "Identity is required"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := wss.Dial(context.Background(), tc.cfg)
			if err == nil {
				t.Fatalf("Dial accepted bad config; expected %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q; want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestClose_Idempotent pins that Close can be called multiple times
// without panic or double-close errors. Required because pkg/daemon
// closes the transport on shutdown AND on read-loop teardown if a
// connection error fires first.
func TestClose_Idempotent(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	fb := newFakeBeacon(t, 1)

	tr, err := wss.Dial(context.Background(), wss.Config{
		URL:       fb.url(),
		TLSConfig: fb.tlsConfig(),
		Identity:  id,
		NodeID:    1,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("second Close: %v (must be nil — idempotent)", err)
	}
}

// TestRecv_AfterClose returns ErrClosed. The daemon's readLoop checks
// errors.Is(err, transport.ErrClosed) to distinguish "drop frame" from
// "transport gone, exit loop." If Recv ever returns a different error
// after Close, that distinction breaks.
func TestRecv_AfterClose(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	fb := newFakeBeacon(t, 1)

	tr, _ := wss.Dial(context.Background(), wss.Config{
		URL:       fb.url(),
		TLSConfig: fb.tlsConfig(),
		Identity:  id,
		NodeID:    1,
	})
	_ = tr.Close()
	_, _, err := tr.Recv()
	if !errors.Is(err, transport.ErrClosed) {
		t.Errorf("Recv after Close = %v; want transport.ErrClosed", err)
	}
}

// TestTransportSatisfiesInterface is a compile-time assertion: a
// *wss.Transport must implement transport.Transport. If anyone
// changes a method signature, the build fails here.
func TestTransportSatisfiesInterface(t *testing.T) {
	t.Parallel()
	var _ transport.Transport = (*wss.Transport)(nil)
}

// TestReconnect_AfterServerCloseRestoresSendAndRecv pins the bug we
// observed in v1.10.2/1.10.3 production: when the WSS connection
// dies (network blip, beacon nginx restart, GFW spoofed RST), the
// daemon's transport must redial+reauth and resume traffic. Before
// the supervisor goroutine landed, the conn stayed broken until the
// caller manually restarted pilot-daemon — every Send/Recv between
// the break and the restart was lost.
//
// Scheme:
//
//  1. spin up a fakeBeacon with a configurable "kill the active conn
//     after N echoes" behavior
//  2. dial a transport, send+recv one frame (confirms baseline works)
//  3. send a second frame — fakeBeacon eats it and forcibly closes
//     the WS conn (simulates the break)
//  4. send a third frame — must succeed after the supervisor's
//     reconnect+reauth, and the echo must come back via Recv
func TestReconnect_AfterServerCloseRestoresSendAndRecv(t *testing.T) {
	t.Parallel()
	id := mustID(t)
	const nodeID uint32 = 909
	fb := newFakeBeacon(t, nodeID)
	// After the second binary frame, close the active conn so the
	// daemon has to reconnect.
	fb.killAfterFrame = 2

	tr, err := wss.Dial(context.Background(), wss.Config{
		URL:         fb.url(),
		TLSConfig:   fb.tlsConfig(),
		Identity:    id,
		NodeID:      nodeID,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	// 1. Baseline round-trip works.
	if _, err := tr.Send([]byte("first"), nil); err != nil {
		t.Fatalf("Send #1: %v", err)
	}
	frame, _, err := tr.Recv()
	if err != nil {
		t.Fatalf("Recv #1: %v", err)
	}
	if string(frame) != "echo:first" {
		t.Fatalf("Recv #1 = %q, want %q", frame, "echo:first")
	}

	// 2. Send the "kill" frame — the fakeBeacon's killAfterFrame=2
	// will eat this frame and CloseNow() the conn. This Send may
	// return success even though the bytes get lost on the dying
	// conn (TCP-write succeeded into the local buffer; the peer
	// closes before the bytes are read). This models production
	// where the WSS transport cannot detect a send was lost — the
	// CALLER'S retransmit layer (key-exchange retx, dial-retry) is
	// what re-sends the data after a response timeout.
	if _, err := tr.Send([]byte("kill"), nil); err != nil {
		t.Fatalf("Send #2 (kill): %v", err)
	}

	// 3. Wait for the supervisor to actually observe the break AND
	// reconnect. We detect this by polling Send — once it returns
	// ErrReconnecting, the supervisor has torn down the old conn.
	// Then we keep retrying until Send succeeds (new conn installed).
	// Generous deadline: covers 250ms backoff + dial + auth.
	deadline := time.Now().Add(10 * time.Second)
	sawReconnecting := false
	for time.Now().Before(deadline) {
		_, sendErr := tr.Send([]byte("probe"), nil)
		if errors.Is(sendErr, wss.ErrReconnecting) {
			sawReconnecting = true
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if sendErr != nil {
			// "wss send: failed to write msg" against the dying conn
			// is expected during the brief window before the
			// supervisor flips conn to nil.
			if strings.Contains(sendErr.Error(), "wss send:") {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			t.Fatalf("Send probe unexpected error: %v", sendErr)
		}
		// sendErr == nil: only trust this if we ALSO observed
		// ErrReconnecting at some point — otherwise we may have
		// caught a Send that wrote into the dying-conn buffer
		// (returns nil but the bytes are lost). Once we've seen
		// ErrReconnecting AND then a nil error, the supervisor has
		// reinstalled a healthy conn.
		if sawReconnecting {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sawReconnecting {
		t.Fatalf("supervisor never marked the conn as reconnecting")
	}

	// 4. Echo for "probe" should arrive on the new conn. (wss.Transport
	// doesn't expose SetReadDeadline, so put the Recv in a goroutine
	// with a separate timeout — same as the daemon's real consumers.)
	recvDone := make(chan struct {
		body []byte
		err  error
	}, 1)
	go func() {
		body, _, err := tr.Recv()
		recvDone <- struct {
			body []byte
			err  error
		}{body, err}
	}()
	select {
	case r := <-recvDone:
		if r.err != nil {
			t.Fatalf("Recv after reconnect: %v", r.err)
		}
		if string(r.body) != "echo:probe" {
			t.Fatalf("Recv after reconnect = %q, want %q", r.body, "echo:probe")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Recv after reconnect timed out (no echo for 'probe')")
	}
}

// TestReconnect_SurvivesFailedRedialAttempts is the regression test
// for the supervisor early-exit bug. The supervisor must keep retrying
// with backoff even when the FIRST redial attempt fails — production
// daemons used to wedge here, sitting with t.conn=nil forever.
//
// Sequence: dial → server kills conn → server refuses 3 redial
// attempts → server recovers → daemon must reconnect and ferry a new
// frame round trip.
func TestReconnect_SurvivesFailedRedialAttempts(t *testing.T) {
	t.Parallel()
	id := mustID(t)
	const nodeID uint32 = 4242
	fb := newFakeBeacon(t, nodeID)
	fb.killAfterFrame = 2

	tr, err := wss.Dial(context.Background(), wss.Config{
		URL:         fb.url(),
		TLSConfig:   fb.tlsConfig(),
		Identity:    id,
		NodeID:      nodeID,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	// Baseline round-trip.
	if _, err := tr.Send([]byte("first"), nil); err != nil {
		t.Fatalf("Send #1: %v", err)
	}
	if _, _, err := tr.Recv(); err != nil {
		t.Fatalf("Recv #1: %v", err)
	}

	// Arm the outage NOW that the initial dial is established. The
	// kill on frame #2 (below) will sever the conn; the next 3
	// redial attempts then hit the 503 path. With backoff
	// 250ms → 500ms → 1s, the supervisor spends ~1.75s in the
	// "failed reconnect" loop before the fourth attempt succeeds.
	fb.failNextDials = 3

	// Trigger the kill. The second frame is eaten by fakeBeacon
	// (killAfterFrame=2).
	if _, err := tr.Send([]byte("kill"), nil); err != nil {
		t.Fatalf("Send kill: %v", err)
	}

	// Poll Send until the supervisor reconnects to the now-recovered
	// server. Generous deadline: cumulative backoff with one cap step
	// is ~4s, plus the dial+auth cost.
	deadline := time.Now().Add(15 * time.Second)
	sawReconnecting := false
	for time.Now().Before(deadline) {
		_, sendErr := tr.Send([]byte("probe"), nil)
		if errors.Is(sendErr, wss.ErrReconnecting) {
			sawReconnecting = true
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if sendErr != nil {
			if strings.Contains(sendErr.Error(), "wss send:") {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			t.Fatalf("Send probe unexpected error: %v", sendErr)
		}
		if sawReconnecting {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sawReconnecting {
		t.Fatalf("supervisor never marked the conn as reconnecting — did the kill not land?")
	}
	if fb.failNextDials != 0 {
		t.Fatalf("expected supervisor to exhaust failNextDials, %d remaining", fb.failNextDials)
	}

	// New conn is alive — Recv the echo for "probe".
	recvDone := make(chan struct {
		body []byte
		err  error
	}, 1)
	go func() {
		body, _, err := tr.Recv()
		recvDone <- struct {
			body []byte
			err  error
		}{body, err}
	}()
	select {
	case r := <-recvDone:
		if r.err != nil {
			t.Fatalf("Recv after recovery: %v", r.err)
		}
		if string(r.body) != "echo:probe" {
			t.Fatalf("Recv after recovery = %q, want %q", r.body, "echo:probe")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Recv after recovery timed out — supervisor wedged")
	}
}

// TestIdlePing_KeepsConnectionAlive verifies that the idle-ping
// goroutine runs without interfering with Send/Recv. The bug was that
// IdlePingInterval was stored but no goroutine ever sent websocket
// Ping frames — corporate proxies would idle-timeout the WS connection
// and the daemon would wedge on Recv forever.
func TestIdlePing_KeepsConnectionAlive(t *testing.T) {
	t.Parallel()
	id := mustID(t)
	fb := newFakeBeacon(t, 1)

	tr, err := wss.Dial(context.Background(), wss.Config{
		URL:              fb.url(),
		TLSConfig:        fb.tlsConfig(),
		Identity:         id,
		NodeID:           1,
		IdlePingInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	// Wait long enough for several ping cycles to fire. If the ping
	// goroutine panics or deadlocks (e.g., holds writeMu while the
	// transport is closed), the Send/Recv round-trip below will hang.
	time.Sleep(200 * time.Millisecond)

	// Send/Recv must still work after idle pings have fired.
	payload := []byte("after-pings")
	if _, err := tr.Send(payload, nil); err != nil {
		t.Fatalf("Send after idle pings: %v", err)
	}
	frame, _, err := tr.Recv()
	if err != nil {
		t.Fatalf("Recv after idle pings: %v", err)
	}
	want := append([]byte("echo:"), payload...)
	if string(frame) != string(want) {
		t.Errorf("Recv = %q; want %q", frame, want)
	}
}

func mustID(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}
