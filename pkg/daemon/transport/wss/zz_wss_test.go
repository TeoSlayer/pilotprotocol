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

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport/wss"
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

	// Send auth challenge with a fixed nonce so we can assert on it.
	nonce := "deadbeef12345678deadbeef12345678"
	ch := map[string]string{"type": "auth_challenge", "nonce": nonce}
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
	signed := fmt.Sprintf("compat_auth:%d:%s", reply.NodeID, nonce)
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
	for {
		_, body, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		fb.recordedFrames = append(fb.recordedFrames, append([]byte(nil), body...))
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

func mustID(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}
