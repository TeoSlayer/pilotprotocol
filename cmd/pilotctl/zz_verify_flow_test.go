// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// TestVerifierFrameRoundtrip pins the length-prefixed JSON framing against
// itself.
func TestVerifierFrameRoundtrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	want := verifierRequest{Op: "begin", Provider: "github", NodeID: 109517}
	go func() { _ = writeVerifierFrame(c1, want) }()

	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	var got verifierRequest
	if err := readVerifierFrame(c2, &got); err != nil {
		t.Fatalf("readVerifierFrame: %v", err)
	}
	if got != want {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", got, want)
	}
}

// TestVerifierWireKeys pins the JSON wire keys so they stay compatible with
// pilot-verify's protocol.go (op/provider/node_id/flow_id).
func TestVerifierWireKeys(t *testing.T) {
	b, _ := json.Marshal(verifierRequest{Op: "poll", FlowID: "abc"})
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if m["op"] != "poll" || m["flow_id"] != "abc" {
		t.Fatalf("unexpected request wire shape: %s", b)
	}
	// provider/node_id must be omitted when empty (poll carries only flow_id).
	if _, ok := m["provider"]; ok {
		t.Errorf("poll request should omit provider: %s", b)
	}
}

// TestVerifierExchangeBeginPoll drives the real begin→poll→ready protocol
// against a simulated verifier that mirrors pilot-verify's behavior (one
// request/response per connection).
func TestVerifierExchangeBeginPoll(t *testing.T) {
	// --- begin ---
	srv, cli := net.Pipe()
	defer cli.Close()
	go func() {
		defer srv.Close()
		var req verifierRequest
		if err := readVerifierFrame(srv, &req); err != nil {
			return
		}
		if req.Op != "begin" || req.Provider != "github" || req.NodeID != 42 {
			_ = writeVerifierFrame(srv, verifierResponse{OK: false, Error: "bad begin"})
			return
		}
		_ = writeVerifierFrame(srv, verifierResponse{
			OK: true, FlowID: "flow-1", UserCode: "WXYZ-1234",
			VerificationURI: "https://github.com/login/device",
		})
	}()
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	begin, err := verifierExchange(cli, verifierRequest{Op: "begin", Provider: "github", NodeID: 42})
	if err != nil {
		t.Fatalf("begin exchange: %v", err)
	}
	if begin.FlowID != "flow-1" || begin.UserCode != "WXYZ-1234" || begin.VerificationURI == "" {
		t.Fatalf("begin response wrong: %+v", begin)
	}

	// --- poll -> ready (new connection, as the verifier serves one op/conn) ---
	srv2, cli2 := net.Pipe()
	defer cli2.Close()
	go func() {
		defer srv2.Close()
		var req verifierRequest
		if err := readVerifierFrame(srv2, &req); err != nil {
			return
		}
		if req.Op != "poll" || req.FlowID != "flow-1" {
			_ = writeVerifierFrame(srv2, verifierResponse{OK: false, Error: "bad poll"})
			return
		}
		_ = writeVerifierFrame(srv2, verifierResponse{
			OK: true, Status: "ready",
			Badge:    "pilotbadge:v1:42:github:1781827200:0:bdg-v1:",
			BadgeSig: "c2ln",
		})
	}()
	_ = cli2.SetReadDeadline(time.Now().Add(2 * time.Second))
	poll, err := verifierExchange(cli2, verifierRequest{Op: "poll", FlowID: begin.FlowID})
	if err != nil {
		t.Fatalf("poll exchange: %v", err)
	}
	if poll.Status != "ready" || poll.Badge == "" || poll.BadgeSig != "c2ln" {
		t.Fatalf("poll response wrong: %+v", poll)
	}
}

// TestVerifierExchangeError surfaces a verifier error frame as a Go error.
func TestVerifierExchangeError(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()
	go func() {
		defer srv.Close()
		var req verifierRequest
		_ = readVerifierFrame(srv, &req)
		_ = writeVerifierFrame(srv, verifierResponse{OK: false, Error: "provider not configured"})
	}()
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := verifierExchange(cli, verifierRequest{Op: "begin", Provider: "google"}); err == nil {
		t.Fatal("expected error from !ok verifier response")
	}
}
