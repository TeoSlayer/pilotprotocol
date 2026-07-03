// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/reqsig"
)

// --- test helpers ------------------------------------------------------------

// runSignEnvelope marshals payload, dispatches handleSignEnvelope, and returns
// the raw [cmd][body...] reply.
func runSignEnvelope(t *testing.T, s *IPCServer, payload map[string]interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	ic, client := newIPCTestConn(t)
	return runHandler(t, client, func() { s.handleSignEnvelope(ic, 0, raw) })
}

// runVerifyEnvelope dispatches handleVerifyEnvelope and decodes the expected
// CmdVerifyEnvelopeOK JSON verdict.
func runVerifyEnvelope(t *testing.T, s *IPCServer, payload map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleVerifyEnvelope(ic, 0, raw) })
	if reply[0] != CmdVerifyEnvelopeOK {
		t.Fatalf("opcode = 0x%02X, want CmdVerifyEnvelopeOK (0x%02X); body=%q", reply[0], CmdVerifyEnvelopeOK, reply[1:])
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(reply[1:], &resp); err != nil {
		t.Fatalf("verdict json: %v (payload=%q)", err, reply[1:])
	}
	return resp
}

// signedTestEnvelope signs an envelope with the given key outside the daemon
// (as a remote peer would) so verify-side failure modes can be exercised with
// arbitrary node/timestamp values.
func signedTestEnvelope(t *testing.T, priv ed25519.PrivateKey, network uint16, node uint32, ts int64) (canonical, sigB64 string) {
	t.Helper()
	nonce, err := reqsig.NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	canonical, sigB64, err = reqsig.Sign(priv, reqsig.Envelope{
		Network:   network,
		Node:      node,
		Timestamp: ts,
		Nonce:     nonce,
		BodyHash:  reqsig.HashBody([]byte("body")),
		Audience:  "svc.example.io",
	})
	if err != nil {
		t.Fatalf("reqsig.Sign: %v", err)
	}
	return canonical, sigB64
}

// --- handleSignEnvelope ------------------------------------------------------

// TestHandleSignAndVerifyEnvelopeRoundTrip proves the full loop: the daemon
// signs an envelope naming its OWN address, and the verify handler accepts it
// back (cache key-resolution path), reporting node/address/via/trusted.
func TestHandleSignAndVerifyEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()
	d, s := newSimpleHandlerDaemon(t, nil)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	d.identity = id

	bodyHash := reqsig.HashBody([]byte(`{"q":"x"}`))
	reply := runSignEnvelope(t, s, map[string]interface{}{
		"audience":  "svc.example.io",
		"body_hash": bodyHash,
	})
	if reply[0] != CmdSignEnvelopeOK {
		t.Fatalf("opcode = 0x%02X, want CmdSignEnvelopeOK (0x%02X); body=%q", reply[0], CmdSignEnvelopeOK, reply[1:])
	}
	var signed map[string]interface{}
	if err := json.Unmarshal(reply[1:], &signed); err != nil {
		t.Fatalf("sign reply json: %v", err)
	}
	canonical, _ := signed["envelope"].(string)
	sigB64, _ := signed["signature"].(string)
	if addr, _ := signed["address"].(string); addr != "0:0000.0000.0007" {
		t.Errorf("address = %q, want 0:0000.0000.0007", addr)
	}

	// The envelope must name the daemon's own address and echo the body hash.
	e, err := reqsig.Parse(canonical)
	if err != nil {
		t.Fatalf("Parse(%q): %v", canonical, err)
	}
	if e.Network != 0 || e.Node != 7 {
		t.Errorf("envelope address = %d/%d, want 0/7", e.Network, e.Node)
	}
	if e.BodyHash != bodyHash || e.Audience != "svc.example.io" {
		t.Errorf("envelope fields = %+v", e)
	}
	// Signature verifies directly against the daemon key.
	if _, err := reqsig.Verify(id.PublicKey, canonical, sigB64); err != nil {
		t.Fatalf("reqsig.Verify: %v", err)
	}

	// Round trip through the verify handler: seed the keyexchange cache so
	// the key resolves locally (verified_via=cache), no registry needed.
	d.tunnels.kx.SetPeerPubKey(7, id.PublicKey)
	verdict := runVerifyEnvelope(t, s, map[string]interface{}{
		"envelope":  canonical,
		"signature": sigB64,
	})
	if valid, _ := verdict["valid"].(bool); !valid {
		t.Fatalf("verdict = %+v, want valid=true", verdict)
	}
	if nid, _ := verdict["node_id"].(float64); uint32(nid) != 7 {
		t.Errorf("node_id = %v, want 7", verdict["node_id"])
	}
	if addr, _ := verdict["address"].(string); addr != "0:0000.0000.0007" {
		t.Errorf("address = %q", addr)
	}
	if via, _ := verdict["verified_via"].(string); via != "cache" {
		t.Errorf("verified_via = %q, want cache", via)
	}
	if trusted, ok := verdict["trusted"].(bool); !ok || trusted {
		t.Errorf("trusted = %v, want false (no handshake service)", verdict["trusted"])
	}
}

// TestHandleSignEnvelopeHashesBodyB64 proves the daemon hashes a b64 body
// itself and honors a caller-supplied nonce.
func TestHandleSignEnvelopeHashesBodyB64(t *testing.T) {
	t.Parallel()
	d, s := newSimpleHandlerDaemon(t, nil)
	id, _ := crypto.GenerateIdentity()
	d.identity = id

	const nonce = "00112233aabbccdd"
	body := []byte("hello envelope")
	reply := runSignEnvelope(t, s, map[string]interface{}{
		"audience": "svc.example.io",
		"body_b64": base64.StdEncoding.EncodeToString(body),
		"nonce":    nonce,
	})
	if reply[0] != CmdSignEnvelopeOK {
		t.Fatalf("opcode = 0x%02X, want CmdSignEnvelopeOK; body=%q", reply[0], reply[1:])
	}
	var signed map[string]interface{}
	if err := json.Unmarshal(reply[1:], &signed); err != nil {
		t.Fatalf("json: %v", err)
	}
	e, err := reqsig.Parse(signed["envelope"].(string))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if e.BodyHash != reqsig.HashBody(body) {
		t.Errorf("body hash = %q, want daemon-computed sha256", e.BodyHash)
	}
	if e.Nonce != nonce {
		t.Errorf("nonce = %q, want caller-supplied %q", e.Nonce, nonce)
	}
}

// TestHandleSignEnvelopeRejectsBadInput pins the refusal paths — the daemon
// must never emit a signature for malformed envelope inputs (the IPC socket
// is same-UID-open, so these checks are the signing-oracle boundary).
func TestHandleSignEnvelopeRejectsBadInput(t *testing.T) {
	t.Parallel()
	d, s := newSimpleHandlerDaemon(t, nil)
	id, _ := crypto.GenerateIdentity()
	d.identity = id

	goodHash := reqsig.HashBody([]byte("x"))
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantMsg string
	}{
		{"missing audience", map[string]interface{}{"body_hash": goodHash}, "audience required"},
		{"bad audience charset", map[string]interface{}{"audience": "UPPER", "body_hash": goodHash}, "audience"},
		{"no body source", map[string]interface{}{"audience": "svc.example.io"}, "body_hash or body_b64"},
		{"both body sources", map[string]interface{}{"audience": "svc.example.io", "body_hash": goodHash, "body_b64": "aGk="}, "mutually exclusive"},
		{"short body hash", map[string]interface{}{"audience": "svc.example.io", "body_hash": "abcd"}, "body hash"},
		{"bad body_b64", map[string]interface{}{"audience": "svc.example.io", "body_b64": "!!!"}, "not base64"},
		{"bad nonce", map[string]interface{}{"audience": "svc.example.io", "body_hash": goodHash, "nonce": "zz"}, "nonce"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply := runSignEnvelope(t, s, tc.payload)
			assertErrorReply(t, reply, tc.wantMsg)
		})
	}
}

func TestHandleSignEnvelopeNoIdentityReturnsError(t *testing.T) {
	t.Parallel()
	d, s := newSimpleHandlerDaemon(t, nil)
	d.identity = nil
	reply := runSignEnvelope(t, s, map[string]interface{}{
		"audience":  "svc.example.io",
		"body_hash": reqsig.HashBody([]byte("x")),
	})
	assertErrorReply(t, reply, "no identity")
}

// --- handleVerifyEnvelope ----------------------------------------------------

func TestHandleVerifyEnvelopeRejectsTamperedEnvelope(t *testing.T) {
	t.Parallel()
	d, s := newSimpleHandlerDaemon(t, nil)
	peer, _ := crypto.GenerateIdentity()
	d.tunnels.kx.SetPeerPubKey(42, peer.PublicKey)

	canonical, sigB64 := signedTestEnvelope(t, peer.PrivateKey, 0, 42, time.Now().Unix())
	// Flip the audience TLD — still a well-formed envelope, wrong signature.
	tampered := strings.TrimSuffix(canonical, "svc.example.io") + "svc.example.iq"
	verdict := runVerifyEnvelope(t, s, map[string]interface{}{
		"envelope":  tampered,
		"signature": sigB64,
	})
	if valid, _ := verdict["valid"].(bool); valid {
		t.Fatalf("tampered envelope verified: %+v", verdict)
	}
	if reason, _ := verdict["reason"].(string); !strings.Contains(reason, "signature verification failed") {
		t.Errorf("reason = %q, want signature failure", verdict["reason"])
	}
}

func TestHandleVerifyEnvelopeRejectsStaleTimestamp(t *testing.T) {
	t.Parallel()
	d, s := newSimpleHandlerDaemon(t, nil)
	peer, _ := crypto.GenerateIdentity()
	d.tunnels.kx.SetPeerPubKey(42, peer.PublicKey)

	canonical, sigB64 := signedTestEnvelope(t, peer.PrivateKey, 0, 42, time.Now().Add(-time.Hour).Unix())
	verdict := runVerifyEnvelope(t, s, map[string]interface{}{
		"envelope":  canonical,
		"signature": sigB64,
	})
	if valid, _ := verdict["valid"].(bool); valid {
		t.Fatalf("stale envelope verified: %+v", verdict)
	}
	if reason, _ := verdict["reason"].(string); !strings.Contains(reason, "window") {
		t.Errorf("reason = %q, want freshness-window failure", verdict["reason"])
	}

	// A caller-widened skew window admits the same envelope.
	verdict = runVerifyEnvelope(t, s, map[string]interface{}{
		"envelope":      canonical,
		"signature":     sigB64,
		"max_skew_secs": 7200,
	})
	if valid, _ := verdict["valid"].(bool); !valid {
		t.Fatalf("wide-skew verify failed: %+v", verdict)
	}
}

// TestHandleVerifyEnvelopeUnknownPeerNoRegistry: no cached key and no
// registry fallback — the verdict is a detailed valid:false, not CmdError.
func TestHandleVerifyEnvelopeUnknownPeerNoRegistry(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)
	peer, _ := crypto.GenerateIdentity()
	canonical, sigB64 := signedTestEnvelope(t, peer.PrivateKey, 0, 4242, time.Now().Unix())
	verdict := runVerifyEnvelope(t, s, map[string]interface{}{
		"envelope":  canonical,
		"signature": sigB64,
	})
	if valid, _ := verdict["valid"].(bool); valid {
		t.Fatalf("verified without any key source: %+v", verdict)
	}
	if reason, _ := verdict["reason"].(string); !strings.Contains(reason, "4242") {
		t.Errorf("reason = %q, want mention of node 4242", verdict["reason"])
	}
}

// TestHandleVerifyEnvelopeRegistryPathAndTrusted covers the cache-miss key
// resolution path (verified_via=registry, then memoized to cache) plus the
// handshake-trust flag.
func TestHandleVerifyEnvelopeRegistryPathAndTrusted(t *testing.T) {
	t.Parallel()
	d, s := newSimpleHandlerDaemon(t, nil)
	peer, _ := crypto.GenerateIdentity()
	// Stand in for the registry fetch (keyexchange verifyFunc).
	d.tunnels.SetPeerVerifyFunc(func(nodeID uint32) (ed25519.PublicKey, error) {
		return peer.PublicKey, nil
	})
	fs := installFakeHandshake(d)
	fs.trustedRecs = []HandshakeTrustRecord{{NodeID: 42}}

	canonical, sigB64 := signedTestEnvelope(t, peer.PrivateKey, 0, 42, time.Now().Unix())
	verdict := runVerifyEnvelope(t, s, map[string]interface{}{
		"envelope":  canonical,
		"signature": sigB64,
	})
	if valid, _ := verdict["valid"].(bool); !valid {
		t.Fatalf("verdict = %+v, want valid=true", verdict)
	}
	if via, _ := verdict["verified_via"].(string); via != "registry" {
		t.Errorf("verified_via = %q, want registry on first resolve", via)
	}
	if trusted, _ := verdict["trusted"].(bool); !trusted {
		t.Errorf("trusted = %v, want true", verdict["trusted"])
	}

	// Second verify hits the memoized key.
	verdict = runVerifyEnvelope(t, s, map[string]interface{}{
		"envelope":  canonical,
		"signature": sigB64,
	})
	if via, _ := verdict["verified_via"].(string); via != "cache" {
		t.Errorf("verified_via = %q, want cache on second resolve", via)
	}
}

// TestHandleVerifyEnvelopeCheckStanding covers the optional registry-standing
// decoration — fields appear only when the registry returns them, so the
// handler tolerates older registries (and the parallel work stream adding
// last_seen_unix/key_generation).
func TestHandleVerifyEnvelopeCheckStanding(t *testing.T) {
	t.Parallel()
	peer, _ := crypto.GenerateIdentity()
	now := time.Now().Unix()

	t.Run("full standing fields", func(t *testing.T) {
		t.Parallel()
		client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
			if req["type"] == "lookup" {
				return map[string]interface{}{
					"last_seen_unix": now - 30,
					"key_generation": 3,
					"networks":       []interface{}{float64(0), float64(5)},
				}
			}
			return map[string]interface{}{}
		})
		defer cleanup()
		d, s := newSimpleHandlerDaemon(t, client)
		d.tunnels.kx.SetPeerPubKey(42, peer.PublicKey)

		canonical, sigB64 := signedTestEnvelope(t, peer.PrivateKey, 0, 42, now)
		verdict := runVerifyEnvelope(t, s, map[string]interface{}{
			"envelope":       canonical,
			"signature":      sigB64,
			"check_standing": true,
		})
		if valid, _ := verdict["valid"].(bool); !valid {
			t.Fatalf("verdict = %+v, want valid=true", verdict)
		}
		if online, _ := verdict["online"].(bool); !online {
			t.Errorf("online = %v, want true (last_seen 30s ago)", verdict["online"])
		}
		if ls, _ := verdict["last_seen_unix"].(float64); int64(ls) != now-30 {
			t.Errorf("last_seen_unix = %v, want %d", verdict["last_seen_unix"], now-30)
		}
		if kg, _ := verdict["key_generation"].(float64); uint32(kg) != 3 {
			t.Errorf("key_generation = %v, want 3", verdict["key_generation"])
		}
		if member, _ := verdict["network_member"].(bool); !member {
			t.Errorf("network_member = %v, want true (network 0 in [0 5])", verdict["network_member"])
		}
	})

	t.Run("registry without standing fields", func(t *testing.T) {
		t.Parallel()
		client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
			return map[string]interface{}{} // lookup succeeds, no standing data
		})
		defer cleanup()
		d, s := newSimpleHandlerDaemon(t, client)
		d.tunnels.kx.SetPeerPubKey(42, peer.PublicKey)

		canonical, sigB64 := signedTestEnvelope(t, peer.PrivateKey, 0, 42, now)
		verdict := runVerifyEnvelope(t, s, map[string]interface{}{
			"envelope":       canonical,
			"signature":      sigB64,
			"check_standing": true,
		})
		if valid, _ := verdict["valid"].(bool); !valid {
			t.Fatalf("verdict = %+v, want valid=true", verdict)
		}
		for _, key := range []string{"online", "last_seen_unix", "key_generation", "network_member"} {
			if _, present := verdict[key]; present {
				t.Errorf("%s should be omitted when the registry doesn't report it", key)
			}
		}
	})

	t.Run("no registry at all", func(t *testing.T) {
		t.Parallel()
		d, s := newSimpleHandlerDaemon(t, nil)
		d.tunnels.kx.SetPeerPubKey(42, peer.PublicKey)

		canonical, sigB64 := signedTestEnvelope(t, peer.PrivateKey, 0, 42, now)
		verdict := runVerifyEnvelope(t, s, map[string]interface{}{
			"envelope":       canonical,
			"signature":      sigB64,
			"check_standing": true,
		})
		if valid, _ := verdict["valid"].(bool); !valid {
			t.Fatalf("verdict = %+v, want valid=true (cache verify works offline)", verdict)
		}
		for _, key := range []string{"online", "last_seen_unix", "key_generation", "network_member"} {
			if _, present := verdict[key]; present {
				t.Errorf("%s should be omitted with no registry", key)
			}
		}
	})
}

// TestHandleVerifyEnvelopeMalformedPayloads pins the CmdError (vs valid:false)
// boundary: transport-level garbage is an error, envelope-level problems are
// verdicts.
func TestHandleVerifyEnvelopeMalformedPayloads(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)

	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleVerifyEnvelope(ic, 0, []byte("not json")) })
	assertErrorReply(t, reply, "bad payload")

	raw, _ := json.Marshal(map[string]interface{}{"envelope": "x"}) // missing signature
	ic2, client2 := newIPCTestConn(t)
	reply = runHandler(t, client2, func() { s.handleVerifyEnvelope(ic2, 0, raw) })
	assertErrorReply(t, reply, "envelope and signature required")

	// A syntactically bad envelope is a verdict, not an error.
	verdict := runVerifyEnvelope(t, s, map[string]interface{}{
		"envelope":  "garbage",
		"signature": "c2ln",
	})
	if valid, _ := verdict["valid"].(bool); valid {
		t.Fatal("garbage envelope verified")
	}
}
