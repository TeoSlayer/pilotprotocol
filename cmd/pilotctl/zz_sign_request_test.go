// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilot-protocol/common/reqsig"
)

// IPC cmd codes for the request-signature envelope commands — must match
// daemon CmdSignEnvelope/CmdVerifyEnvelope and driver cmdSignEnvelope/
// cmdVerifyEnvelope. Kept here (not zz_fake_daemon_test.go) alongside the
// only tests that use them.
const (
	tdCmdSignEnvelope     byte = 0x33
	tdCmdSignEnvelopeOK   byte = 0x34
	tdCmdVerifyEnvelope   byte = 0x35
	tdCmdVerifyEnvelopeOK byte = 0x36
)

// receivedPayload scans the fake daemon's received frames for cmd and
// returns the decoded JSON payload of the first match.
func receivedPayload(t *testing.T, d *fakeDaemon, cmd byte) map[string]interface{} {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, frame := range d.received {
		if len(frame) > 1 && frame[0] == cmd {
			var got map[string]interface{}
			if err := json.Unmarshal(frame[1:], &got); err != nil {
				t.Fatalf("frame 0x%02X payload not JSON: %v", cmd, err)
			}
			return got
		}
	}
	t.Fatalf("no frame with cmd 0x%02X received", cmd)
	return nil
}

// TestCLISignRequestEnvelope covers the happy path: the CLI hashes --body
// locally, sends {audience, body_hash} to the daemon, and prints
// {envelope, signature, address}.
func TestCLISignRequestEnvelope(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	d.onJSON(tdCmdSignEnvelope, tdCmdSignEnvelopeOK,
		`{"type":"sign_envelope_ok","envelope":"pilot-req-v1|env","signature":"c2ln","address":"0:0000.0000.0007"}`)

	stdout, stderr, code := runCLI(t, []string{
		"--json", "sign-request",
		"--audience", "svc.example.io",
		"--body", "hello envelope",
	}, map[string]string{"PILOT_SOCKET": d.path})
	if code != 0 {
		t.Fatalf("exit=%d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}

	var env map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("json: %v (stdout=%q)", err, stdout)
	}
	data, _ := env["data"].(map[string]interface{})
	if data["envelope"] != "pilot-req-v1|env" || data["signature"] != "c2ln" || data["address"] != "0:0000.0000.0007" {
		t.Errorf("data = %+v", data)
	}

	// The daemon must have been asked for the locally computed sha256, never
	// the raw body.
	got := receivedPayload(t, d, tdCmdSignEnvelope)
	if got["audience"] != "svc.example.io" {
		t.Errorf("audience = %v", got["audience"])
	}
	if got["body_hash"] != reqsig.HashBody([]byte("hello envelope")) {
		t.Errorf("body_hash = %v, want sha256 of --body", got["body_hash"])
	}
}

func TestCLISignRequestEnvelopeRequiresAudience(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"sign-request", "--body", "x"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit without --audience")
	}
	if !strings.Contains(stderr, "audience") {
		t.Errorf("expected usage mention of --audience, got: %s", stderr)
	}
}

func TestCLISignRequestEnvelopeRequiresOneBodySource(t *testing.T) {
	t.Parallel()
	// None given.
	_, stderr, code := runCLI(t, []string{"sign-request", "--audience", "svc.example.io"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit without a body source")
	}
	if !strings.Contains(stderr, "exactly one") {
		t.Errorf("expected 'exactly one' error, got: %s", stderr)
	}
	// Two given.
	_, stderr, code = runCLI(t, []string{
		"sign-request", "--audience", "svc.example.io",
		"--body", "x", "--body-hash", strings.Repeat("a", 64),
	}, nil)
	if code == 0 {
		t.Error("expected non-zero exit with two body sources")
	}
	if !strings.Contains(stderr, "exactly one") {
		t.Errorf("expected 'exactly one' error, got: %s", stderr)
	}
}

// TestCLIVerifyRequestEnvelopeValid: a valid verdict prints the daemon reply
// and exits 0; flags round-trip onto the wire.
func TestCLIVerifyRequestEnvelopeValid(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	d.onJSON(tdCmdVerifyEnvelope, tdCmdVerifyEnvelopeOK,
		`{"type":"verify_envelope_ok","valid":true,"node_id":7,"address":"0:0000.0000.0007","verified_via":"cache","trusted":true}`)

	stdout, stderr, code := runCLI(t, []string{
		"--json", "verify-request",
		"--envelope", "pilot-req-v1|env",
		"--signature", "c2ln",
		"--standing",
		"--max-skew", "600",
	}, map[string]string{"PILOT_SOCKET": d.path})
	if code != 0 {
		t.Fatalf("exit=%d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("json: %v (stdout=%q)", err, stdout)
	}
	data, _ := env["data"].(map[string]interface{})
	if valid, _ := data["valid"].(bool); !valid {
		t.Errorf("data = %+v, want valid=true", data)
	}

	got := receivedPayload(t, d, tdCmdVerifyEnvelope)
	if got["envelope"] != "pilot-req-v1|env" || got["signature"] != "c2ln" {
		t.Errorf("payload = %+v", got)
	}
	if cs, _ := got["check_standing"].(bool); !cs {
		t.Errorf("check_standing = %v, want true (--standing)", got["check_standing"])
	}
	if skew, _ := got["max_skew_secs"].(float64); skew != 600 {
		t.Errorf("max_skew_secs = %v, want 600 (--max-skew)", got["max_skew_secs"])
	}
}

// TestCLIVerifyRequestEnvelopeInvalidExitsOne: valid:false still prints the
// verdict but the process exits 1 (scriptable gate).
func TestCLIVerifyRequestEnvelopeInvalidExitsOne(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	d.onJSON(tdCmdVerifyEnvelope, tdCmdVerifyEnvelopeOK,
		`{"type":"verify_envelope_ok","valid":false,"reason":"reqsig: signature verification failed"}`)

	stdout, _, code := runCLI(t, []string{
		"--json", "verify-request",
		"--envelope", "pilot-req-v1|env",
		"--signature", "c2ln",
	}, map[string]string{"PILOT_SOCKET": d.path})
	if code != 1 {
		t.Fatalf("exit=%d, want 1 on valid:false", code)
	}
	if !strings.Contains(stdout, "signature verification failed") {
		t.Errorf("verdict reason missing from output: %s", stdout)
	}
}

func TestCLIVerifyRequestEnvelopeRequiresArgs(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"verify-request", "--envelope", "e"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit without --signature")
	}
	if !strings.Contains(stderr, "--signature") && !strings.Contains(stderr, "signature") {
		t.Errorf("expected usage mention of --signature, got: %s", stderr)
	}
}
