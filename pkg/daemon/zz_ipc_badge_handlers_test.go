// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/pilot-protocol/common/badgeverify"
	"github.com/pilot-protocol/common/crypto"
)

// --- handleSubmitBadge -----------------------------------------------------

// TestHandleSubmitBadgeSignsAndForwards proves the happy path: the handler
// signs "submit_badge:<node_id>:<badge>" with the CURRENT key, forwards the
// badge + badge_sig + node signature to the registry, and the signature
// actually verifies against the node's public key (so a registry can trust
// the address owns this badge).
func TestHandleSubmitBadgeSignsAndForwards(t *testing.T) {
	t.Parallel()

	const badge = "pilotbadge:v1:7:github:1781827200:0:bdg-v1:"
	const badgeSig = "aXNzdWVyLXNpZw=="

	var gotBadge, gotBadgeSig, gotSig string
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "submit_badge" {
			gotBadge, _ = req["badge"].(string)
			gotBadgeSig, _ = req["badge_sig"].(string)
			gotSig, _ = req["signature"].(string)
			return map[string]interface{}{"ok": true}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	d, s := newSimpleHandlerDaemon(t, client)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	d.identity = id

	payload, _ := json.Marshal(map[string]string{"badge": badge, "badge_sig": badgeSig})
	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleSubmitBadge(ic, 0, payload) })

	if reply[0] != CmdSubmitBadgeOK {
		t.Fatalf("opcode = 0x%02X, want CmdSubmitBadgeOK (0x%02X); body=%q", reply[0], CmdSubmitBadgeOK, reply[3:])
	}
	if gotBadge != badge || gotBadgeSig != badgeSig {
		t.Errorf("registry got badge=%q sig=%q, want %q / %q", gotBadge, gotBadgeSig, badge, badgeSig)
	}
	// The node-ownership signature must verify over the canonical challenge.
	rawSig, err := base64.StdEncoding.DecodeString(gotSig)
	if err != nil {
		t.Fatalf("node signature not base64: %v", err)
	}
	challenge := fmt.Sprintf("submit_badge:%d:%s", d.NodeID(), badge)
	if !ed25519.Verify(id.PublicKey, []byte(challenge), rawSig) {
		t.Errorf("node-ownership signature does not verify over %q", challenge)
	}
}

func TestHandleSubmitBadgeBadPayloadReturnsError(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleSubmitBadge(ic, 0, []byte("not json")) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError", reply[0])
	}
}

func TestHandleSubmitBadgeMissingFieldsReturnsError(t *testing.T) {
	t.Parallel()
	_, s := newSimpleHandlerDaemon(t, nil)
	ic, client := newIPCTestConn(t)
	payload, _ := json.Marshal(map[string]string{"badge": "x"}) // no badge_sig
	reply := runHandler(t, client, func() { s.handleSubmitBadge(ic, 0, payload) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError on missing badge_sig", reply[0])
	}
}

func TestHandleSubmitBadgeNoIdentityReturnsError(t *testing.T) {
	t.Parallel()
	// regConn present but identity nil → cannot prove ownership.
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"ok": true}
	})
	defer cleanup()
	d, s := newSimpleHandlerDaemon(t, client)
	d.identity = nil

	payload, _ := json.Marshal(map[string]string{"badge": "b", "badge_sig": "s"})
	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleSubmitBadge(ic, 0, payload) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError when daemon has no identity", reply[0])
	}
}

// --- handleEnrollRecovery --------------------------------------------------

// TestHandleEnrollRecoverySignsCommitment proves the handler parses the
// verifier-produced enrollment, signs the COMMITMENT (not the whole string)
// with the current key, and forwards everything to the registry.
func TestHandleEnrollRecoverySignsCommitment(t *testing.T) {
	t.Parallel()

	const commitment = "Y29tbWl0bWVudC1obWFj"
	enrollment, err := badgeverify.CanonicalEnrollment(badgeverify.Enrollment{
		NodeID:     7,
		Provider:   "github",
		Commitment: commitment,
		IssuedAt:   1781827200,
		Kid:        "bdg-v1",
	})
	if err != nil {
		t.Fatalf("CanonicalEnrollment: %v", err)
	}
	const enrollSig = "ZW5yb2xsLXNpZw=="

	var gotEnrollment, gotSig string
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "enroll_recovery" {
			gotEnrollment, _ = req["enrollment"].(string)
			gotSig, _ = req["signature"].(string)
			return map[string]interface{}{"ok": true}
		}
		return map[string]interface{}{}
	})
	defer cleanup()

	d, s := newSimpleHandlerDaemon(t, client)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	d.identity = id

	payload, _ := json.Marshal(map[string]string{"enrollment": enrollment, "enrollment_sig": enrollSig})
	ic, client2 := newIPCTestConn(t)
	reply := runHandler(t, client2, func() { s.handleEnrollRecovery(ic, 0, payload) })

	if reply[0] != CmdEnrollRecoveryOK {
		t.Fatalf("opcode = 0x%02X, want CmdEnrollRecoveryOK (0x%02X); body=%q", reply[0], CmdEnrollRecoveryOK, reply[3:])
	}
	if gotEnrollment != enrollment {
		t.Errorf("registry got enrollment=%q, want %q", gotEnrollment, enrollment)
	}
	// Signature must be over the COMMITMENT, proving the daemon parsed it.
	rawSig, err := base64.StdEncoding.DecodeString(gotSig)
	if err != nil {
		t.Fatalf("node signature not base64: %v", err)
	}
	challenge := fmt.Sprintf("enroll_recovery:%d:%s", d.NodeID(), commitment)
	if !ed25519.Verify(id.PublicKey, []byte(challenge), rawSig) {
		t.Errorf("recovery-enrollment signature does not verify over %q", challenge)
	}
}

func TestHandleEnrollRecoveryBadEnrollmentReturnsError(t *testing.T) {
	t.Parallel()
	d, s := newSimpleHandlerDaemon(t, nil)
	id, _ := crypto.GenerateIdentity()
	d.identity = id
	payload, _ := json.Marshal(map[string]string{"enrollment": "garbage", "enrollment_sig": "s"})
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleEnrollRecovery(ic, 0, payload) })
	if reply[0] != CmdError {
		t.Fatalf("opcode 0x%02X, want CmdError on unparseable enrollment", reply[0])
	}
}
